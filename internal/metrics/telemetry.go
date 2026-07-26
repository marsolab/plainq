package metrics

import "time"

// labelInterval names the aggregation window a telemetry roll-up covers.
const labelInterval = "interval"

// Telemetry-subsystem metrics.
//
// These measure the collector that powers Houston's dashboards, not the queue
// itself. They exist because the failure mode of a metrics pipeline is
// silence: without them, a telemetry store that has been rejecting every
// write for a week looks exactly like a quiet server.
var (
	telemetryCollections = NewCounterVec(Definition{
		Name:   Namespace + "_telemetry_collections_total",
		Help:   "Rate-calculation passes the telemetry collector ran, by outcome.",
		Labels: []string{labelResult},
	})

	telemetryCollectionDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_telemetry_collection_duration_seconds",
		Help:   "How long one telemetry collection pass took. Approaching the collection interval means it is falling behind.",
		Labels: []string{},
	}, LatencyBuckets)

	telemetryStoreWrites = NewCounterVec(Definition{
		Name:   Namespace + "_telemetry_store_writes_total",
		Help:   "Writes to the telemetry store, by operation and outcome. A climbing error count means the dashboards are going stale.",
		Labels: []string{labelOperation, labelResult},
	})

	telemetryAggregations = NewCounterVec(Definition{
		Name:   Namespace + "_telemetry_aggregations_total",
		Help:   "Telemetry roll-ups, by window and outcome.",
		Labels: []string{labelInterval, labelResult},
	})

	telemetryAggregationDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_telemetry_aggregation_duration_seconds",
		Help:   "How long a telemetry roll-up took.",
		Labels: []string{labelInterval},
	}, SlowBuckets)

	telemetryCleanups = NewCounterVec(Definition{
		Name:   Namespace + "_telemetry_cleanups_total",
		Help:   "Retention sweeps over the telemetry store, by outcome.",
		Labels: []string{labelResult},
	})

	telemetryTrackedDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_telemetry_tracked",
		Help:   "Distinct queues and topics the collector is holding metrics for.",
		Labels: []string{labelKind},
	})
)

// Telemetry store operations.
const (
	TelemetryOpSaveRaw      = "save_raw"
	TelemetryOpSaveRate     = "save_rate"
	TelemetryOpSaveStats    = "save_stats"
	TelemetryOpUpdateInFlgt = "update_in_flight"
)

// RecordTelemetryCollection records one collection pass.
func RecordTelemetryCollection(start time.Time, err error) {
	telemetryCollections.With(resultOf(err)).Inc()
	telemetryCollectionDuration.ObserveSince(start)
}

// RecordTelemetryWrite records one write to the telemetry store.
func RecordTelemetryWrite(operation string, err error) {
	telemetryStoreWrites.With(operation, resultOf(err)).Inc()
}

// RecordTelemetryAggregation records one roll-up over a window.
func RecordTelemetryAggregation(interval string, start time.Time, err error) {
	telemetryAggregations.With(interval, resultOf(err)).Inc()
	telemetryAggregationDuration.ObserveSince(start, interval)
}

// RecordTelemetryCleanup records one retention sweep of the telemetry store.
func RecordTelemetryCleanup(err error) { telemetryCleanups.With(resultOf(err)).Inc() }

// RegisterTelemetryCollector publishes how many queues and topics the
// collector is holding metrics for, read at scrape time.
func RegisterTelemetryCollector(tracked func() (queues, topics int)) {
	GaugeFunc(telemetryTrackedDef, func() float64 {
		queues, _ := tracked()

		return float64(queues)
	}, RecordQueue)

	GaugeFunc(telemetryTrackedDef, func() float64 {
		_, topics := tracked()

		return float64(topics)
	}, RecordTopic)
}
