// Package quota provides durable fixed-window admission and shared
// transaction helpers for resource usage ledgers.
package quota

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
)

// ErrExhausted identifies rate or capacity exhaustion.
var ErrExhausted = errors.New("quota exhausted")

// ErrIdempotencyConflict reports reuse of a key for a different reservation.
var ErrIdempotencyConflict = errors.New("quota idempotency conflict")

const maximumRetryDelay = time.Second

type exhaustionRetryError struct {
	cause error
	delay time.Duration
}

func (e *exhaustionRetryError) Error() string {
	return e.cause.Error()
}

func (e *exhaustionRetryError) Unwrap() error {
	return e.cause
}

// RetryDelay returns a positive, bounded delay for quota exhaustion. Capacity
// failures that have no fixed-window boundary use the conservative maximum.
func RetryDelay(err error) (time.Duration, bool) {
	if !errors.Is(err, ErrExhausted) {
		return 0, false
	}

	var retryErr *exhaustionRetryError
	if errors.As(err, &retryErr) {
		return boundedRetryDelay(retryErr.delay), true
	}

	return maximumRetryDelay, true
}

// ReservationResult describes one persistent fixed-window reservation.
type ReservationResult struct {
	AlreadyConsumed bool   `json:"already_consumed"`
	Used            uint64 `json:"used"`
}

// UsageDelta carries exact row-derived additions and removals. Each field is
// non-negative; direction is explicit so signed underflow cannot be hidden by
// a caller-provided integer.
type UsageDelta struct {
	TenantID string
	AgentID  string

	AgentCountAdded           uint64
	AgentCountRemoved         uint64
	QueueCountAdded           uint64
	QueueCountRemoved         uint64
	TopicCountAdded           uint64
	TopicCountRemoved         uint64
	SubscriptionCountAdded    uint64
	SubscriptionCountRemoved  uint64
	StoredBytesAdded          uint64
	StoredBytesRemoved        uint64
	PendingDirectAdded        uint64
	PendingDirectRemoved      uint64
	PendingBytesAdded         uint64
	PendingBytesRemoved       uint64
	AgentSubscriptionsAdded   uint64
	AgentSubscriptionsRemoved uint64
	ActiveCredentialsAdded    uint64
	ActiveCredentialsRemoved  uint64
}

// RateTransaction reserves rate units through an already-open operation
// transaction.
type RateTransaction interface {
	ReserveRate(
		ctx context.Context,
		tenantID string,
		action authz.Action,
		units uint64,
		now time.Time,
	) (time.Time, error)
}

// UsageTransaction applies exact row-derived ledger deltas through an
// already-open operation transaction.
type UsageTransaction interface {
	ApplyActualUsage(ctx context.Context, delta UsageDelta) error
}

// ReserveRateTx delegates to an existing operation transaction and returns
// the bounded retry time on exhaustion.
func ReserveRateTx(
	ctx context.Context,
	tx RateTransaction,
	tenantID string,
	action authz.Action,
	units uint64,
	now time.Time,
) (time.Time, error) {
	if tx == nil || tenantID == "" || units == 0 || !authz.ValidAction(action) {
		return time.Time{}, errors.New("valid quota rate transaction input is required")
	}

	retryAt, err := tx.ReserveRate(ctx, tenantID, action, units, now.UTC())
	if err != nil {
		err = withRetryAt(err, now, retryAt)

		return retryAt, fmt.Errorf("reserve rate in transaction: %w", err)
	}

	return retryAt, nil
}

// ApplyActualUsageTx delegates exact additions/removals to an existing
// operation transaction.
func ApplyActualUsageTx(ctx context.Context, tx UsageTransaction, delta UsageDelta) error {
	if tx == nil || delta.TenantID == "" {
		return errors.New("valid quota usage transaction input is required")
	}

	if err := tx.ApplyActualUsage(ctx, delta); err != nil {
		return fmt.Errorf("apply actual usage in transaction: %w", err)
	}

	return nil
}

// WindowStore atomically resolves idempotency and reserves one rate window.
type WindowStore interface {
	Reserve(
		ctx context.Context,
		tenantID string,
		action authz.Action,
		limit uint64,
		units uint64,
		idempotencyKey string,
		window time.Time,
	) (ReservationResult, error)
}

// StaticLimits supplies fixed per-action admission ceilings.
type StaticLimits map[authz.Action]uint64

// Limiter consumes persistent fixed-window rate units.
type Limiter interface {
	Consume(
		ctx context.Context,
		tenantID string,
		action authz.Action,
		units uint64,
		idempotencyKey string,
		now time.Time,
	) error
}

type limiter struct {
	store  WindowStore
	limits StaticLimits
}

// NewLimiter constructs a persistent fixed-window limiter.
func NewLimiter(store WindowStore, limits StaticLimits) (Limiter, error) {
	if store == nil {
		return nil, errors.New("quota window store is required")
	}

	if len(limits) == 0 {
		return nil, errors.New("quota limits are required")
	}

	copyLimits := make(StaticLimits, len(limits))
	for action, limit := range limits {
		if !authz.ValidAction(action) || limit == 0 {
			return nil, fmt.Errorf("invalid quota limit for action %q", action)
		}

		copyLimits[action] = limit
	}

	return &limiter{store: store, limits: copyLimits}, nil
}

func (l *limiter) Consume(
	ctx context.Context,
	tenantID string,
	action authz.Action,
	units uint64,
	idempotencyKey string,
	now time.Time,
) error {
	if tenantID == "" || idempotencyKey == "" || units == 0 {
		return errors.New("tenant, idempotency key, and positive units are required")
	}

	limit, ok := l.limits[action]
	if !ok {
		return fmt.Errorf("quota action %q has no limit", action)
	}

	_, err := l.store.Reserve(ctx, tenantID, action, limit, units, idempotencyKey, windowTime(now))
	if err != nil {
		err = withRetryAt(err, now, windowTime(now).Add(time.Second))

		return fmt.Errorf("reserve quota window: %w", err)
	}

	return nil
}

func windowTime(now time.Time) time.Time {
	return now.UTC().Truncate(time.Second)
}

func withRetryAt(err error, now, retryAt time.Time) error {
	if !errors.Is(err, ErrExhausted) {
		return err
	}

	return &exhaustionRetryError{cause: err, delay: boundedRetryDelay(retryAt.Sub(now.UTC()))}
}

func boundedRetryDelay(delay time.Duration) time.Duration {
	if delay <= 0 || delay > maximumRetryDelay {
		return maximumRetryDelay
	}

	return delay
}
