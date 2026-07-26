package collector

import (
	"context"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
)

// RegisterMetrics exposes the collector's own health on the Prometheus
// endpoint.
//
// The queue numbers themselves are already exported from the storage layer,
// so nothing here duplicates them. What is exported is whether this
// subsystem is working — because the failure mode of a metrics pipeline is
// silence, and a telemetry store that has been rejecting every write for a
// week looks exactly like a quiet server on a dashboard.
func (c *Collector) RegisterMetrics() {
	//nolint:nonamedreturns // two bare ints in a row need naming to be readable.
	metrics.RegisterTelemetryCollector(func() (queues, topics int) {
		c.queueMu.RLock()
		queues = len(c.queueMetrics)
		c.queueMu.RUnlock()

		c.topicMu.RLock()
		topics = len(c.topicMetrics)
		c.topicMu.RUnlock()

		return queues, topics
	})
}

// persist records the outcome of one write to the telemetry store.
//
// These writes were best-effort and silent: every call site discarded the
// error with a `_ =`, so a store that had stopped accepting writes produced
// no log line, no metric, and a dashboard that simply stopped moving. The
// write stays best-effort — telemetry must never fail a queue operation —
// but it is no longer invisible.
func (c *Collector) persist(operation string, err error) {
	metrics.RecordTelemetryWrite(operation, err)

	if err != nil {
		c.logger.Debug("Telemetry store write failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
	}
}

// saveRaw records one raw metric datapoint. It is a no-op when telemetry has
// no store, which is what "telemetry disabled" looks like from in here.
func (c *Collector) saveRaw(ctx context.Context, now int64, id, metric string, value float64) {
	if c.store == nil {
		return
	}

	c.persist(metrics.TelemetryOpSaveRaw, c.store.SaveRawMetric(ctx, now, id, metric, value, ""))
}

// saveRate records one rate snapshot over the collection window.
func (c *Collector) saveRate(ctx context.Context, now int64, id, metric string, rate float64) {
	if c.store == nil {
		return
	}

	c.persist(metrics.TelemetryOpSaveRate, c.store.SaveRateSnapshot(ctx, now, id, metric, rate, rateWindowSeconds))
}

// observeCollection records one rate-calculation pass.
func (c *Collector) observeCollection(start time.Time) {
	metrics.RecordTelemetryCollection(start, nil)
}

// observeAggregation records one roll-up over a window.
func (c *Collector) observeAggregation(interval string, start time.Time, err error) {
	metrics.RecordTelemetryAggregation(interval, start, err)
}

// observeCleanup records one retention sweep of the telemetry store.
func (c *Collector) observeCleanup(err error) { metrics.RecordTelemetryCleanup(err) }
