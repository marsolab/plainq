package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"
)

func (c *Collector) coordinatorWorker(ctx context.Context) {
	for {
		now := c.now().UTC()

		err := c.runCoordinatorPass(ctx, now)
		if err != nil {
			c.logger.Error("Telemetry coordinator failed", slog.String("error", err.Error()))
		}

		delay := c.nextCoordinatorDelay(now, err)
		timer := time.NewTimer(delay)

		select {
		case <-ctx.Done():
			stopTimer(timer)

			return
		case <-c.stop:
			stopTimer(timer)

			return
		case <-timer.C:
		}
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (c *Collector) runCoordinatorPass(ctx context.Context, now time.Time) error {
	c.coordinatorMu.Lock()
	defer c.coordinatorMu.Unlock()

	now = now.UTC()
	if !c.coordinatorInitialized {
		if err := c.initializeCoordinatorLocked(ctx, now); err != nil {
			return err
		}
	} else if err := c.promotePreDurableTerminals(ctx); err != nil {
		return err
	}

	return c.runInitializedCoordinatorLocked(ctx, now)
}

//nolint:cyclop // Startup intentionally enforces each dependent persistence stage in strict order.
func (c *Collector) initializeCoordinatorLocked(ctx context.Context, startupNow time.Time) error {
	intervalMS := c.collectionInterval.Milliseconds()
	if intervalMS <= 0 {
		return errors.New("initialize telemetry coordinator: positive millisecond collection interval is required")
	}

	if err := c.promotePreDurableTerminals(ctx); err != nil {
		return fmt.Errorf("initialize telemetry coordinator: %w", err)
	}

	if err := c.loadDurableTerminalReservations(ctx); err != nil {
		return fmt.Errorf("initialize telemetry coordinator: %w", err)
	}

	if err := c.flushAssignedTerminalStates(ctx); err != nil {
		return fmt.Errorf("initialize telemetry coordinator: %w", err)
	}

	minuteBound := startupNow.Truncate(aggregationInterval1m).UnixMilli()
	hourBound := startupNow.Truncate(aggregationInterval1h).UnixMilli()
	dayBound := startupNow.Truncate(aggregationInterval1d).UnixMilli()

	if err := c.runRollup(ctx, Resolution1m, minuteBound); err != nil {
		return err
	}

	if err := c.runRollup(ctx, Resolution1h, hourBound); err != nil {
		return err
	}

	if err := c.runRollup(ctx, Resolution1d, dayBound); err != nil {
		return err
	}

	if c.store != nil {
		reset, err := c.store.ResetRawInterval(ctx, intervalMS)
		if err != nil {
			return fmt.Errorf("reset raw collection interval: %w", err)
		}

		if reset {
			c.logger.Info("Telemetry raw collection interval reset",
				slog.Int64("sample_interval_ms", intervalMS))
		}
	}

	c.lastRollup1m = minuteBound
	c.lastRollup1h = hourBound
	c.lastRollup1d = dayBound

	if c.cleanupInterval > 0 {
		c.nextCleanup = startupNow.Add(c.cleanupInterval)
	}

	c.coordinatorInitialized = true

	return nil
}

//nolint:cyclop,gocyclo // The coordinator is an explicit ordered gate across raw, terminal, rollup, and cleanup stages.
func (c *Collector) runInitializedCoordinatorLocked(ctx context.Context, now time.Time) error {
	intervalMS := c.collectionInterval.Milliseconds()

	boundary := floorUnixMillis(now.UnixMilli(), intervalMS)
	if boundary > c.lastTopicBoundary {
		if err := c.calculateRatesAt(ctx, time.UnixMilli(boundary)); err != nil {
			return err
		}

		if c.lastTopicBoundary < boundary {
			// A frozen older boundary committed first. Leave terminal, rollup,
			// and cleanup work gated until a following pass closes the latest
			// raw bucket.
			return nil
		}
	}

	if boundary > 0 {
		if err := c.assignTerminalStates(ctx, boundary); err != nil {
			return err
		}

		for _, state := range c.terminalStatesDue(boundary) {
			if !isAssignedTerminalState(state) {
				continue
			}

			if err := c.completeTerminalState(ctx, state); err != nil {
				return err
			}
		}
	}

	minuteBound := now.Truncate(aggregationInterval1m).UnixMilli()
	if minuteBound > c.lastRollup1m {
		if err := c.runRollup(ctx, Resolution1m, minuteBound); err != nil {
			return err
		}

		c.lastRollup1m = minuteBound
	}

	hourBound := now.Truncate(aggregationInterval1h).UnixMilli()
	if hourBound > c.lastRollup1h {
		if err := c.runRollup(ctx, Resolution1h, hourBound); err != nil {
			return err
		}

		c.lastRollup1h = hourBound
	}

	dayBound := now.Truncate(aggregationInterval1d).UnixMilli()
	if dayBound > c.lastRollup1d {
		if err := c.runRollup(ctx, Resolution1d, dayBound); err != nil {
			return err
		}

		c.lastRollup1d = dayBound
	}

	if !c.nextCleanup.IsZero() && !now.Before(c.nextCleanup) {
		if err := c.runCleanup(ctx, now); err != nil {
			return err
		}

		c.nextCleanup = advanceDeadline(c.nextCleanup, c.cleanupInterval, now)
	}

	return nil
}

func (c *Collector) runRollup(ctx context.Context, resolution Resolution, closedThrough int64) error {
	if c.store == nil {
		return nil
	}

	start := time.Now()
	err := c.store.Rollup(ctx, resolution, closedThrough)
	c.observeAggregation(string(resolution), start, err)

	if err != nil {
		return fmt.Errorf("roll up %s through %d: %w", resolution, closedThrough, err)
	}

	return nil
}

func (c *Collector) runCleanup(ctx context.Context, now time.Time) error {
	if c.store == nil {
		return nil
	}

	retention := c.retentionPeriod
	if retention <= 0 {
		return errors.New("clean up telemetry history: positive retention is required")
	}

	rawKeep := minDuration(retentionRaw, retention)
	minuteKeep := minDuration(retention1m, retention)
	legacy5mKeep := minDuration(retention5m, retention)
	hourKeep := minDuration(retention1h, retention)
	nowMS := now.UnixMilli()

	err := c.store.CleanupOldMetrics(ctx,
		retentionCutoff(nowMS, rawKeep, c.collectionInterval),
		retentionCutoff(nowMS, minuteKeep, aggregationInterval1m),
		retentionCutoff(nowMS, legacy5mKeep, 5*aggregationInterval1m),
		retentionCutoff(nowMS, hourKeep, aggregationInterval1h),
		retentionCutoff(nowMS, retention, aggregationInterval1d),
	)
	c.observeCleanup(err)

	if err != nil {
		return fmt.Errorf("clean up telemetry history: %w", err)
	}

	return nil
}

func retentionCutoff(nowMS int64, keep, sourceBucket time.Duration) int64 {
	keepMS := keep.Milliseconds()
	sourceMS := sourceBucket.Milliseconds()

	if keepMS < 0 || sourceMS < 0 || keepMS > math.MaxInt64-sourceMS {
		return math.MinInt64
	}

	total := keepMS + sourceMS
	if nowMS < math.MinInt64+total {
		return math.MinInt64
	}

	return nowMS - total
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}

	return right
}

func advanceDeadline(deadline time.Time, interval time.Duration, now time.Time) time.Time {
	if interval <= 0 || deadline.After(now) {
		return deadline
	}

	steps := int64(now.Sub(deadline)/interval) + 1
	intervalNS := int64(interval)

	if steps > math.MaxInt64/intervalNS {
		return now.Add(interval)
	}

	return deadline.Add(time.Duration(steps * intervalNS))
}

func floorUnixMillis(timestamp, intervalMS int64) int64 {
	if intervalMS <= 0 {
		return 0
	}

	quotient := timestamp / intervalMS
	if timestamp < 0 && timestamp%intervalMS != 0 {
		quotient--
	}

	return quotient * intervalMS
}

func coordinatorRetryDelay(collectionInterval time.Duration) time.Duration {
	delay := max(time.Second, collectionInterval)

	return min(30*time.Second, delay)
}

func (c *Collector) nextCoordinatorDelay(now time.Time, passErr error) time.Duration {
	if passErr != nil {
		return coordinatorRetryDelay(c.collectionInterval)
	}

	c.coordinatorMu.Lock()
	defer c.coordinatorMu.Unlock()

	intervalMS := c.collectionInterval.Milliseconds()
	latestBoundary := floorUnixMillis(now.UnixMilli(), intervalMS)
	nextCollection := time.UnixMilli(latestBoundary + intervalMS)

	if c.lastTopicBoundary < latestBoundary {
		nextCollection = now.Add(time.Millisecond)
	}

	deadlines := []time.Time{
		nextCollection,
		time.UnixMilli(c.lastRollup1m + aggregationInterval1m.Milliseconds()),
		time.UnixMilli(c.lastRollup1h + aggregationInterval1h.Milliseconds()),
		time.UnixMilli(c.lastRollup1d + aggregationInterval1d.Milliseconds()),
	}
	if !c.nextCleanup.IsZero() {
		deadlines = append(deadlines, c.nextCleanup)
	}

	next := deadlines[0]
	for _, deadline := range deadlines[1:] {
		if deadline.Before(next) {
			next = deadline
		}
	}

	delay := next.Sub(now)
	if delay <= 0 {
		return time.Millisecond
	}

	return delay
}

func (c *Collector) promotePreDurableTerminals(ctx context.Context) error {
	return c.promoteTerminalStates(ctx)
}

func (c *Collector) flushAssignedTerminalStates(ctx context.Context) error {
	for _, state := range c.assignedTerminalStates() {
		if err := c.completeTerminalState(ctx, state); err != nil {
			return err
		}
	}

	return nil
}

func (c *Collector) assignedTerminalStates() []TerminalState {
	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	states := make([]TerminalState, 0, len(c.terminalReservations))
	c.terminalOrder.Ascend(func(reservation *terminalReservation) bool {
		if reservation.durable && !reservation.canceled && isAssignedTerminalState(reservation.state) {
			states = append(states, reservation.state)
		}

		return true
	})

	return states
}
