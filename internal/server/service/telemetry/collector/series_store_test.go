package collector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestSaveAndQueryTypedRawSeriesUsesHalfOpenRange(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	for _, timestamp := range []int64{999, 1000, 1999, 2000} {
		sample := testSample(timestamp, "queue-1", "depth", MetricKindGauge, float64(timestamp), 0)
		coverage := testCoverage(ResolutionRaw, timestamp, sample, 1)
		if err := store.SaveMetricAndCoverage(ctx, sample, coverage); err != nil {
			t.Fatalf("save typed point at %d: %v", timestamp, err)
		}
	}

	result, err := store.QuerySeries(ctx, SeriesQuery{
		MetricName: "depth", SubjectID: "queue-1", Kind: MetricKindGauge,
		Resolution: ResolutionRaw, From: 1000, To: 2000,
	})
	if err != nil {
		t.Fatalf("query typed series: %v", err)
	}
	if result.DataPoints == nil || result.Coverage == nil || result.PriorCoverage == nil {
		t.Fatalf("result slices must be non-nil: %#v", result)
	}
	if len(result.DataPoints) != 2 || result.DataPoints[0].Timestamp != 1000 || result.DataPoints[1].Timestamp != 1999 {
		t.Fatalf("half-open points = %#v, want timestamps 1000 and 1999", result.DataPoints)
	}
	for _, point := range result.DataPoints {
		if point.Source != "observed" || point.Count != 1 {
			t.Fatalf("raw point = %#v, want source observed and count 1", point)
		}
	}
	if len(result.Coverage) != 2 || result.Coverage[0].BucketStart != 1000 || result.Coverage[1].BucketStart != 1999 {
		t.Fatalf("half-open coverage = %#v, want buckets 1000 and 1999", result.Coverage)
	}
}

func TestQuerySeriesSQLiteFixtureSeparatesDiagnosticRowsFromExactCoverage(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO metrics_raw (timestamp, queue_id, metric_name, metric_value, labels)
VALUES (999, 'topic-1', 'plainq_topic_subscriptions_active', 9, ''),
       (1000, 'topic-1', 'plainq_topic_subscriptions_active', 10, ''),
       (2000, 'topic-1', 'plainq_topic_subscriptions_active', 20, ''),
       (3000, 'topic-1', 'plainq_topic_subscriptions_active', 30, '');
INSERT INTO telemetry_coverage
    (resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms)
VALUES ('raw', 999, 'topic-1', 'plainq_topic_subscriptions_active', '', 'gauge', 1000),
       ('raw', 1000, 'topic-1', '', '', '', 1000),
       ('raw', 1000, 'topic-1', 'plainq_topic_subscriptions_active', 'other', 'gauge', 1000),
       ('raw', 1000, 'topic-1', 'plainq_topic_subscriptions_active', '', 'counter', 1000),
       ('raw', 2000, 'topic-1', 'plainq_topic_subscriptions_active', '', 'gauge', 1000),
       ('raw', 3000, 'topic-1', 'plainq_topic_subscriptions_active', '', 'gauge', 1000);`); err != nil {
		t.Fatalf("seed migrated raw fixture: %v", err)
	}

	result := mustQuerySeries(t, store, SeriesQuery{
		MetricName: "plainq_topic_subscriptions_active", SubjectID: "topic-1", Kind: MetricKindGauge,
		Resolution: ResolutionRaw, From: 1000, To: 3000,
	})

	assertDataPointTimestamps(t, result.DataPoints, []int64{1000, 2000})
	assertCoverageBucketStarts(t, result.Coverage, []int64{2000})
	if result.DataPoints[0].Value != 10 {
		t.Fatalf("diagnostic pre-migration point value = %v, want 10", result.DataPoints[0].Value)
	}
}

func TestQuerySeriesSQLiteFixtureRequiresExactCoveredRawPrior(t *testing.T) {
	tests := map[string]struct {
		kind MetricKind
	}{
		"counter": {kind: MetricKindCounter},
		"gauge":   {kind: MetricKindGauge},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, conn := newTelemetryTestStoreWithConn(t)
			if _, err := conn.Exec(`
INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (1000, 'topic-1', 'carry_metric', 10, '', ?, 0),
       (2500, 'topic-1', 'carry_metric', 25, '', ?, 0);
INSERT INTO telemetry_coverage
    (resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms)
VALUES ('raw', 1000, 'topic-1', 'carry_metric', '', ?, 1000),
       ('raw', 2000, 'topic-1', 'carry_metric', '', ?, 1000),
       ('raw', 2500, 'topic-1', '', '', '', 1000);`, string(tc.kind), string(tc.kind), string(tc.kind), string(tc.kind)); err != nil {
				t.Fatalf("seed %s carry fixture: %v", tc.kind, err)
			}

			result := mustQuerySeries(t, store, SeriesQuery{
				MetricName: "carry_metric", SubjectID: "topic-1", Kind: tc.kind,
				Resolution: ResolutionRaw, From: 3000, To: 4000, CarryForward: true,
			})
			if result.Prior == nil {
				t.Fatal("covered prior = nil, want exact-covered point")
			}
			if result.Prior.Timestamp != 1000 || result.Prior.Value != 10 {
				t.Fatalf("covered prior = %#v, want timestamp 1000/value 10", result.Prior)
			}
			assertCoverageBucketStarts(t, result.PriorCoverage, []int64{1000, 2000})
		})
	}
}

func TestQuerySeriesSQLiteFixtureExposesPriorCoverageGap(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (1000, 'topic-1', 'plainq_topic_subscriptions_active', 10, '', 'gauge', 0),
       (2000, 'topic-1', 'plainq_topic_subscriptions_active', 20, '', 'gauge', 0);
INSERT INTO telemetry_coverage
    (resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms)
VALUES ('raw', 1000, 'topic-1', 'plainq_topic_subscriptions_active', '', 'gauge', 1000),
       ('raw', 2000, 'topic-1', '', '', '', 1000);`); err != nil {
		t.Fatalf("seed gapped carry fixture: %v", err)
	}

	result := mustQuerySeries(t, store, SeriesQuery{
		MetricName: "plainq_topic_subscriptions_active", SubjectID: "topic-1", Kind: MetricKindGauge,
		Resolution: ResolutionRaw, From: 3000, To: 4000, CarryForward: true,
	})
	if result.Prior == nil || result.Prior.Timestamp != 1000 {
		t.Fatalf("covered prior = %#v, want the older exact-covered point at 1000", result.Prior)
	}
	assertCoverageBucketStarts(t, result.PriorCoverage, []int64{1000})
}

func TestQuerySeriesSQLiteFixtureKeepsPhysicalSupportBucketVisible(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	for _, timestamp := range []int64{-1000, 0, 1000, 2000} {
		sample := testSample(
			timestamp, "topic-1", "plainq_topic_messages_published_total", MetricKindCounter, float64(timestamp+2000), 0,
		)
		if err := store.SaveMetricAndCoverage(ctx, sample, testCoverage(ResolutionRaw, timestamp, sample, 1000)); err != nil {
			t.Fatalf("seed physical retention bucket %d: %v", timestamp, err)
		}
	}

	// The worker retains one extra source bucket at the cleanup cutoff. Public
	// handlers use their later RetentionFrom bound to classify/filter bucket 0.
	if err := store.CleanupOldMetrics(ctx, 0, 0, 0, 0, 0); err != nil {
		t.Fatalf("clean before physical retention cutoff: %v", err)
	}

	physical := mustQuerySeries(t, store, SeriesQuery{
		MetricName: "plainq_topic_messages_published_total", SubjectID: "topic-1", Kind: MetricKindCounter,
		Resolution: ResolutionRaw, From: -1000, To: 2000,
	})
	assertDataPointTimestamps(t, physical.DataPoints, []int64{0, 1000})
	assertCoverageBucketStarts(t, physical.Coverage, []int64{0, 1000})

	public := mustQuerySeries(t, store, SeriesQuery{
		MetricName: "plainq_topic_messages_published_total", SubjectID: "topic-1", Kind: MetricKindCounter,
		Resolution: ResolutionRaw, From: 1000, To: 2000,
	})
	assertDataPointTimestamps(t, public.DataPoints, []int64{1000})
	assertCoverageBucketStarts(t, public.Coverage, []int64{1000})
}

func TestCoverageIsPerResolutionSubjectAndSeries(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	a := testSample(1000, "queue-1", "a", MetricKindGauge, 1, 0)
	b := testSample(1000, "queue-1", "b", MetricKindCounter, 2, 0)
	for _, coverage := range []CoverageBucket{
		testCoverage(ResolutionRaw, 1000, a, 1000),
		testCoverage(ResolutionRaw, 1000, b, 1000),
		{Resolution: ResolutionRaw, BucketStart: 1000, SubjectID: "queue-1", SampleIntervalMS: 1000},
		{Resolution: Resolution1m, BucketStart: 0, SubjectID: "queue-1", MetricName: "a", Kind: MetricKindGauge, SampleIntervalMS: 60000},
	} {
		if err := store.SaveCoverage(ctx, coverage); err != nil {
			t.Fatalf("save coverage %#v: %v", coverage, err)
		}
	}

	result, err := store.QuerySeries(ctx, SeriesQuery{
		MetricName: "a", SubjectID: "queue-1", Kind: MetricKindGauge,
		Resolution: ResolutionRaw, From: 0, To: 2000,
	})
	if err != nil {
		t.Fatalf("query series coverage: %v", err)
	}
	if len(result.Coverage) != 1 || result.Coverage[0].MetricName != "a" || result.Coverage[0].Kind != MetricKindGauge {
		t.Fatalf("exact coverage = %#v, want only raw a/gauge", result.Coverage)
	}

	subject, err := store.QuerySubjectCoverage(ctx, SubjectCoverageQuery{
		SubjectID: "queue-1", Resolution: ResolutionRaw, From: 0, To: 2000,
	})
	if err != nil {
		t.Fatalf("query subject coverage: %v", err)
	}
	if len(subject) != 1 || subject[0].MetricName != "" || subject[0].Labels != "" || subject[0].Kind != "" {
		t.Fatalf("subject coverage = %#v, want only empty identity", subject)
	}
}

func TestQuerySubjectCoverageNeverReturnsSeriesCoverage(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	if err := store.SaveCoverage(ctx, CoverageBucket{
		Resolution: ResolutionRaw, BucketStart: 1000, SubjectID: "queue-1",
		MetricName: "depth", Kind: MetricKindGauge, SampleIntervalMS: 1000,
	}); err != nil {
		t.Fatalf("save series coverage: %v", err)
	}
	got, err := store.QuerySubjectCoverage(ctx, SubjectCoverageQuery{
		SubjectID: "queue-1", Resolution: ResolutionRaw, From: 0, To: 2000,
	})
	if err != nil {
		t.Fatalf("query subject coverage: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("subject coverage = %#v, want non-nil empty slice", got)
	}
}

func TestQuerySeriesReadsPointsCoverageAndPriorFromOneSnapshot(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	for _, timestamp := range []int64{0, 1000, 2000} {
		sample := testSample(timestamp, "queue-1", "depth", MetricKindGauge, float64(timestamp/1000), 0)
		if err := store.SaveMetricAndCoverage(ctx, sample, testCoverage(ResolutionRaw, timestamp, sample, 1000)); err != nil {
			t.Fatalf("seed sample %d: %v", timestamp, err)
		}
	}

	result, err := store.QuerySeries(ctx, SeriesQuery{
		MetricName: "depth", SubjectID: "queue-1", Kind: MetricKindGauge,
		Resolution: ResolutionRaw, From: 2000, To: 3000, CarryForward: true,
	})
	if err != nil {
		t.Fatalf("query series snapshot: %v", err)
	}
	if len(result.DataPoints) != 1 || len(result.Coverage) != 1 {
		t.Fatalf("in-range result = %#v, want one point and coverage", result)
	}
	if result.Prior == nil || result.Prior.Timestamp != 1000 || result.Prior.Value != 1 {
		t.Fatalf("prior = %#v, want covered point at 1000", result.Prior)
	}
	if len(result.PriorCoverage) != 1 || result.PriorCoverage[0].BucketStart != 1000 {
		t.Fatalf("prior coverage = %#v, want bucket 1000", result.PriorCoverage)
	}
}

func TestLegacyFiveMinuteTableRemainsReadableButNeverSelected(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO metrics_5m
    (timestamp, queue_id, metric_name, metric_value_min, metric_value_max, metric_value_avg, labels)
VALUES (0, 'queue-1', 'depth', 1, 5, 3, '')`); err != nil {
		t.Fatalf("seed legacy five minute row: %v", err)
	}
	legacy, err := store.GetMetrics(context.Background(), "depth", "queue-1", 0, 300000, "5m")
	if err != nil || len(legacy) != 1 {
		t.Fatalf("legacy five minute read = %#v, %v; want one row", legacy, err)
	}
	if _, err := store.QuerySeries(context.Background(), SeriesQuery{
		MetricName: "depth", SubjectID: "queue-1", Kind: MetricKindGauge,
		Resolution: Resolution("5m"), From: 0, To: 300000,
	}); err == nil {
		t.Fatal("typed QuerySeries accepted legacy 5m resolution")
	}
}

func TestSeededVersion3NullableRollupIsNotCoalescedToZero(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO metrics_1m
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels, metric_kind)
VALUES (0, 'queue-1', 'depth', 0, 0, 0, 0, 1, '', 'gauge')`); err != nil {
		t.Fatalf("seed nullable legacy aggregate: %v", err)
	}
	result, err := store.QuerySeries(context.Background(), SeriesQuery{
		MetricName: "depth", SubjectID: "queue-1", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	if err != nil {
		t.Fatalf("query nullable aggregate: %v", err)
	}
	if len(result.DataPoints) != 0 {
		t.Fatalf("nullable legacy aggregate became point %#v, want skipped", result.DataPoints)
	}
}

func TestQuerySeriesCarryForwardSkipsNullableLegacyAggregate(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO metrics_1m
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count,
     labels, metric_kind, first_value, last_value, increase_value, window_ms)
VALUES (-120000, 'queue-1', 'depth', 4, 4, 4, 4, 1, '', 'gauge', 4, 4, NULL, 0);
INSERT INTO metrics_1m
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count,
     labels, metric_kind, first_value, last_value, increase_value, window_ms)
VALUES (-60000, 'queue-1', 'depth', 0, 0, 0, 0, 1, '', 'gauge', NULL, NULL, NULL, 0);
INSERT INTO telemetry_coverage
    (resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms)
VALUES ('1m', -120000, 'queue-1', 'depth', '', 'gauge', 60000),
       ('1m', -60000, 'queue-1', 'depth', '', 'gauge', 60000);`); err != nil {
		t.Fatalf("seed covered aggregate history: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "depth", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 60000, CarryForward: true,
	})
	if result.Prior == nil || result.Prior.Timestamp != -120000 || result.Prior.Value != 4 {
		t.Fatalf("prior = %#v, want older kind-valid aggregate", result.Prior)
	}
}

func TestSaveRateSnapshotPersistsExactAndCompatibilityWindows(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	ctx := context.Background()
	if err := store.SaveRateSnapshot(ctx, 1000, "queue-1", "send_rate", 2, 1000); err != nil {
		t.Fatalf("save 1000ms rate snapshot: %v", err)
	}
	if err := store.SaveRateSnapshot(ctx, 2000, "queue-1", "send_rate", 3, 1500); err != nil {
		t.Fatalf("save 1500ms rate snapshot: %v", err)
	}
	rows, err := conn.Query(`SELECT window_seconds, window_ms FROM rate_snapshots ORDER BY timestamp`)
	if err != nil {
		t.Fatalf("query rate windows: %v", err)
	}
	defer rows.Close()
	want := [][2]int64{{1, 1000}, {2, 1500}}
	index := 0
	for rows.Next() {
		var seconds, milliseconds int64
		if err := rows.Scan(&seconds, &milliseconds); err != nil {
			t.Fatalf("scan rate windows: %v", err)
		}
		if index >= len(want) || [2]int64{seconds, milliseconds} != want[index] {
			t.Fatalf("rate window %d = %ds/%dms, want %v", index, seconds, milliseconds, want[index])
		}
		index++
	}
	if index != len(want) {
		t.Fatalf("rate window rows = %d, want %d", index, len(want))
	}
	if err := store.SaveRateSnapshot(ctx, 3000, "queue-1", "send_rate", 4, 0); err == nil {
		t.Fatal("SaveRateSnapshot accepted non-positive exact window")
	}
}

func TestSaveRateSnapshotAndMetricIsAtomicAndExact(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	ctx := context.Background()
	sample := testSample(1000, "queue-1", "send_rate", MetricKindRate, 4, 1500)
	if err := store.SaveRateSnapshotAndMetric(ctx, 1000, "queue-1", "send_rate", 5, 1500, sample); err == nil {
		t.Fatal("SaveRateSnapshotAndMetric accepted mismatched rate")
	}
	if _, err := conn.Exec(`CREATE TRIGGER fail_typed_rate BEFORE INSERT ON metrics_raw
BEGIN SELECT RAISE(ABORT, 'typed rate failure'); END;`); err != nil {
		t.Fatalf("install typed rate failure trigger: %v", err)
	}
	if err := store.SaveRateSnapshotAndMetric(ctx, 1000, "queue-1", "send_rate", 4, 1500, sample); err == nil {
		t.Fatal("SaveRateSnapshotAndMetric returned nil, want typed insert failure")
	}
	assertTableCount(t, conn, "rate_snapshots", 0)
	assertTableCount(t, conn, "metrics_raw", 0)
}

func TestSaveMetricAndCoverageRollsBackTogether(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
CREATE TRIGGER fail_coverage BEFORE INSERT ON telemetry_coverage
BEGIN SELECT RAISE(ABORT, 'coverage failure'); END;`); err != nil {
		t.Fatalf("install coverage failure trigger: %v", err)
	}
	sample := testSample(1000, "queue-1", "depth", MetricKindGauge, 2, 0)
	if err := store.SaveMetricAndCoverage(context.Background(), sample, testCoverage(ResolutionRaw, 1000, sample, 1000)); err == nil {
		t.Fatal("SaveMetricAndCoverage returned nil, want coverage failure")
	}
	assertTableCount(t, conn, "metrics_raw", 0)
	assertTableCount(t, conn, "telemetry_coverage", 0)
}

func TestResetRawIntervalPurgesRowsAndCoverageAtomically(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	ctx := context.Background()
	reset, err := store.ResetRawInterval(ctx, 1000)
	if err != nil || !reset {
		t.Fatalf("initial ResetRawInterval = %v, %v; want true", reset, err)
	}
	sample := testSample(1000, "queue-1", "depth", MetricKindGauge, 2, 0)
	if err := store.SaveMetricAndCoverage(ctx, sample, testCoverage(ResolutionRaw, 1000, sample, 1000)); err != nil {
		t.Fatalf("seed raw grid: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO telemetry_collection_commits (boundary, sample_interval_ms) VALUES (2000, 1000)`); err != nil {
		t.Fatalf("seed collection ledger: %v", err)
	}
	if _, err := conn.Exec(`CREATE TRIGGER fail_raw_coverage_delete BEFORE DELETE ON telemetry_coverage
WHEN OLD.resolution = 'raw'
BEGIN SELECT RAISE(ABORT, 'raw coverage delete failure'); END;`); err != nil {
		t.Fatalf("install raw reset failure trigger: %v", err)
	}
	if reset, err = store.ResetRawInterval(ctx, 1500); err == nil || reset {
		t.Fatalf("failed ResetRawInterval = %v, %v; want false,error", reset, err)
	}
	assertTableCount(t, conn, "metrics_raw", 1)
	assertRawCoverageCount(t, conn, 1)
	assertTableCount(t, conn, "telemetry_collection_commits", 1)
	var interval int64
	if err := conn.QueryRow(`SELECT raw_sample_interval_ms FROM telemetry_collection_state WHERE singleton = 1`).Scan(&interval); err != nil {
		t.Fatalf("query rolled-back interval: %v", err)
	}
	if interval != 1000 {
		t.Fatalf("rolled-back interval = %d, want 1000", interval)
	}
	if _, err := conn.Exec(`DROP TRIGGER fail_raw_coverage_delete`); err != nil {
		t.Fatalf("drop raw reset failure trigger: %v", err)
	}
	reset, err = store.ResetRawInterval(ctx, 1500)
	if err != nil || !reset {
		t.Fatalf("changed ResetRawInterval = %v, %v; want true", reset, err)
	}
	assertTableCount(t, conn, "metrics_raw", 0)
	assertRawCoverageCount(t, conn, 0)
	assertTableCount(t, conn, "telemetry_collection_commits", 0)
	reset, err = store.ResetRawInterval(ctx, 1500)
	if err != nil || reset {
		t.Fatalf("stable ResetRawInterval = %v, %v; want false", reset, err)
	}
}

func TestResetRawIntervalPurgesUncoveredLegacyRowsOnMetadataUpgrade(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (123, 'queue-1', 'depth', 1, '', 'gauge', 0)`); err != nil {
		t.Fatalf("seed uncovered raw row: %v", err)
	}
	reset, err := store.ResetRawInterval(context.Background(), 1000)
	if err != nil || !reset {
		t.Fatalf("ResetRawInterval = %v, %v; want true", reset, err)
	}
	assertTableCount(t, conn, "metrics_raw", 0)
}

func TestResetRawIntervalPurgesUncoveredRowsWhenGridChanges(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	ctx := context.Background()
	if reset, err := store.ResetRawInterval(ctx, 1000); err != nil || !reset {
		t.Fatalf("initialize raw interval: %v, %v", reset, err)
	}
	if _, err := conn.Exec(`INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (123, 'queue-1', 'depth', 1, '', 'gauge', 0)`); err != nil {
		t.Fatalf("seed uncovered raw row: %v", err)
	}
	if reset, err := store.ResetRawInterval(ctx, 2000); err != nil || !reset {
		t.Fatalf("change raw interval: %v, %v", reset, err)
	}
	assertTableCount(t, conn, "metrics_raw", 0)
}

func TestTerminalStateEnqueueIsDurableAndBounded(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	first := TerminalState{SubjectID: "queue-1", Generation: 1, ObservedAt: 100}
	accepted, err := store.EnqueueTerminalState(ctx, first, 1)
	if err != nil || !accepted {
		t.Fatalf("first enqueue = %v, %v; want accepted", accepted, err)
	}
	accepted, err = store.EnqueueTerminalState(ctx, first, 1)
	if err != nil || !accepted {
		t.Fatalf("deduplicated enqueue = %v, %v; want accepted", accepted, err)
	}
	accepted, err = store.EnqueueTerminalState(ctx, TerminalState{
		SubjectID: "queue-2", Generation: 2, ObservedAt: 200,
	}, 1)
	if err != nil || accepted {
		t.Fatalf("over-cap enqueue = %v, %v; want false,nil", accepted, err)
	}
	states, err := store.ListTerminalStates(ctx)
	if err != nil {
		t.Fatalf("list terminal states: %v", err)
	}
	if len(states) != 1 || states[0].SubjectID != "queue-1" || states[0].ObservedAt != 100 {
		t.Fatalf("terminal states = %#v, want durable first observation", states)
	}
}

func TestTerminalStateEnqueueHonorsCapConcurrently(t *testing.T) {
	store := newTelemetryTestStore(t)
	ctx := context.Background()
	start := make(chan struct{})
	results := make(chan bool, 2)
	errors := make(chan error, 2)
	var wg sync.WaitGroup
	for _, subject := range []string{"queue-a", "queue-b"} {
		wg.Add(1)
		go func(subject string) {
			defer wg.Done()
			<-start
			accepted, err := store.EnqueueTerminalState(ctx, TerminalState{
				SubjectID: subject, Generation: 1, ObservedAt: 100,
			}, 1)
			results <- accepted
			errors <- err
		}(subject)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent enqueue: %v", err)
		}
	}
	acceptedCount := 0
	for accepted := range results {
		if accepted {
			acceptedCount++
		}
	}
	if acceptedCount != 1 {
		t.Fatalf("concurrent accepted count = %d, want 1", acceptedCount)
	}
}

func TestTerminalStateCancellationIsGenerationExact(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	first := TerminalState{SubjectID: "queue-1", Generation: 1, ObservedAt: 100}
	second := TerminalState{SubjectID: "queue-1", Generation: 2, ObservedAt: 200}
	for _, state := range []TerminalState{first, second} {
		accepted, err := store.EnqueueTerminalState(ctx, state, 2)
		if err != nil || !accepted {
			t.Fatalf("enqueue generation %d = %t, %v; want accepted", state.Generation, accepted, err)
		}
	}
	if err := store.CancelTerminalState(ctx, first.SubjectID, first.Generation); err != nil {
		t.Fatalf("cancel first generation: %v", err)
	}
	if err := store.CancelTerminalState(ctx, first.SubjectID, first.Generation); err != nil {
		t.Fatalf("repeat first-generation cancellation: %v", err)
	}
	states, err := store.ListTerminalStates(ctx)
	if err != nil || len(states) != 1 || states[0].Generation != second.Generation {
		t.Fatalf("states after exact cancellation = %#v, %v; want only generation 2", states, err)
	}
}

func TestTerminalTopicAtomicRetryDoesNotDuplicateZero(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	ctx := context.Background()
	state := TerminalState{SubjectID: "queue-1", Generation: 1, ObservedAt: 100}
	accepted, err := store.EnqueueTerminalState(ctx, state, 10)
	if err != nil || !accepted {
		t.Fatalf("enqueue terminal state: %v, %v", accepted, err)
	}
	if err := store.AssignTerminalBucket(ctx, "queue-1", state.Generation, 1000, 1000); err != nil {
		t.Fatalf("assign terminal bucket: %v", err)
	}
	if err := store.AssignTerminalBucket(ctx, "queue-1", state.Generation, 2000, 1000); err == nil {
		t.Fatal("conflicting terminal assignment accepted")
	}
	sample := testSample(1000, "queue-1", "depth", MetricKindGauge, 0, 0)
	coverage := testCoverage(ResolutionRaw, 1000, sample, 1000)
	if _, err := conn.Exec(`CREATE TRIGGER fail_terminal_coverage BEFORE INSERT ON telemetry_coverage
BEGIN SELECT RAISE(ABORT, 'terminal coverage failure'); END;`); err != nil {
		t.Fatalf("install terminal coverage trigger: %v", err)
	}
	if err := store.CompleteTerminalState(ctx, "queue-1", state.Generation, sample, coverage); err == nil {
		t.Fatal("terminal completion returned nil, want trigger failure")
	}
	assertTableCount(t, conn, "metrics_raw", 0)
	assertTableCount(t, conn, "telemetry_terminal_state", 1)
	if _, err := conn.Exec(`DROP TRIGGER fail_terminal_coverage`); err != nil {
		t.Fatalf("drop terminal failure trigger: %v", err)
	}
	if err := store.CompleteTerminalState(ctx, "queue-1", state.Generation, sample, coverage); err != nil {
		t.Fatalf("complete terminal state: %v", err)
	}
	if err := store.CompleteTerminalState(ctx, "queue-1", state.Generation, sample, coverage); err != nil {
		t.Fatalf("repeat terminal completion: %v", err)
	}
	assertTableCount(t, conn, "metrics_raw", 1)
	assertTableCount(t, conn, "telemetry_coverage", 1)
	assertTableCount(t, conn, "telemetry_terminal_state", 0)
}

func TestCoverageWritesOnlyAfterSuccessfulCollection(t *testing.T) {
	tests := []struct {
		name    string
		trigger string
	}{
		{
			name: "after rows",
			trigger: `CREATE TRIGGER fail_collection_rate BEFORE INSERT ON rate_snapshots
BEGIN SELECT RAISE(ABORT, 'rate failure'); END;`,
		},
		{
			name: "after coverage",
			trigger: `CREATE TRIGGER fail_collection_coverage BEFORE INSERT ON telemetry_coverage
WHEN NEW.metric_name = ''
BEGIN SELECT RAISE(ABORT, 'coverage failure'); END;`,
		},
		{
			name: "final ledger",
			trigger: `CREATE TRIGGER fail_collection_ledger BEFORE INSERT ON telemetry_collection_commits
BEGIN SELECT RAISE(ABORT, 'ledger failure'); END;`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store, conn := newTelemetryTestStoreWithConn(t)
			if _, err := conn.Exec(tt.trigger); err != nil {
				t.Fatalf("install failure trigger: %v", err)
			}
			if err := store.SaveCollectionBoundary(context.Background(), testCollectionBatch()); err == nil {
				t.Fatal("SaveCollectionBoundary returned nil, want statement failure")
			}
			for _, table := range []string{"metrics_raw", "rate_snapshots", "telemetry_coverage", "telemetry_collection_commits"} {
				assertTableCount(t, conn, table, 0)
			}
		})
	}

	t.Run("commit failure", func(t *testing.T) {
		t.Parallel()
		store, conn := newTelemetryTestStoreWithConn(t)
		store.commit = func(transaction) error { return errors.New("commit failure") }
		if err := store.SaveCollectionBoundary(context.Background(), testCollectionBatch()); err == nil {
			t.Fatal("SaveCollectionBoundary returned nil, want commit failure")
		}
		for _, table := range []string{"metrics_raw", "rate_snapshots", "telemetry_coverage", "telemetry_collection_commits"} {
			assertTableCount(t, conn, table, 0)
		}
	})
}

func TestSaveCollectionBoundaryRetryIsIdempotent(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	batch := testCollectionBatch()
	for range 2 {
		if err := store.SaveCollectionBoundary(context.Background(), batch); err != nil {
			t.Fatalf("save/retry collection boundary: %v", err)
		}
	}
	assertTableCount(t, conn, "metrics_raw", len(batch.Samples))
	assertTableCount(t, conn, "rate_snapshots", len(batch.RateSnapshots))
	assertTableCount(t, conn, "telemetry_coverage", len(batch.Coverage))
	assertTableCount(t, conn, "telemetry_collection_commits", 1)
}

func TestLostBoundaryCommitAcknowledgementUsesCompletionLedger(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	sentinel := errors.New("lost commit acknowledgement")
	store.commit = func(tx transaction) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return sentinel
	}
	batch := testCollectionBatch()
	if err := store.SaveCollectionBoundary(context.Background(), batch); !errors.Is(err, sentinel) {
		t.Fatalf("first boundary error = %v, want sentinel", err)
	}
	store.commit = defaultCommit
	if err := store.SaveCollectionBoundary(context.Background(), batch); err != nil {
		t.Fatalf("retry after lost acknowledgement: %v", err)
	}
	assertTableCount(t, conn, "metrics_raw", len(batch.Samples))
	assertTableCount(t, conn, "rate_snapshots", len(batch.RateSnapshots))
	assertTableCount(t, conn, "telemetry_coverage", len(batch.Coverage))
	assertTableCount(t, conn, "telemetry_collection_commits", 1)
}

func TestCleanupOldMetricsPrunesCompletionLedgerAndAllowsRecollection(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	ctx := context.Background()
	oldBatch := shiftedCollectionBatch(-1000)
	retainedBoundaryBatch := testCollectionBatch()
	for _, batch := range []CollectionBatch{oldBatch, retainedBoundaryBatch} {
		if err := store.SaveCollectionBoundary(ctx, batch); err != nil {
			t.Fatalf("seed collection boundary %d: %v", batch.Boundary, err)
		}
	}

	if err := store.CleanupOldMetrics(ctx, 2000, 0, 0, 0, 0); err != nil {
		t.Fatalf("clean old metrics: %v", err)
	}

	rows, err := conn.Query(`SELECT boundary FROM telemetry_collection_commits ORDER BY boundary`)
	if err != nil {
		t.Fatalf("query retained completion ledger: %v", err)
	}
	defer rows.Close()
	var boundaries []int64
	for rows.Next() {
		var boundary int64
		if err := rows.Scan(&boundary); err != nil {
			t.Fatalf("scan retained completion boundary: %v", err)
		}
		boundaries = append(boundaries, boundary)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate retained completion boundaries: %v", err)
	}
	if len(boundaries) != 1 || boundaries[0] != 2000 {
		t.Fatalf("retained completion boundaries = %v, want [2000]", boundaries)
	}

	if err := store.SaveCollectionBoundary(ctx, oldBatch); err != nil {
		t.Fatalf("recollect cleaned boundary: %v", err)
	}
	var recollectedRows int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM metrics_raw WHERE timestamp < 1000`).Scan(&recollectedRows); err != nil {
		t.Fatalf("count recollected raw rows: %v", err)
	}
	if recollectedRows != len(oldBatch.Samples) {
		t.Fatalf("recollected raw rows = %d, want %d", recollectedRows, len(oldBatch.Samples))
	}
	assertTableCount(t, conn, "telemetry_collection_commits", 2)
}

func TestCleanupOldMetricsDeletesEachTierCoverageLedgerAndQueueStats(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (999, 'queue-1', 'depth', 1, '', 'gauge', 0),
       (1000, 'queue-1', 'depth', 2, '', 'gauge', 0);
INSERT INTO metrics_1m
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
VALUES (1999, 'queue-1', 'depth', 1, 1, 1, 1, 1, ''),
       (2000, 'queue-1', 'depth', 2, 2, 2, 2, 1, '');
INSERT INTO metrics_5m
    (timestamp, queue_id, metric_name, metric_value_min, metric_value_max, metric_value_avg, labels)
VALUES (2999, 'queue-1', 'depth', 1, 1, 1, ''),
       (3000, 'queue-1', 'depth', 2, 2, 2, '');
INSERT INTO metrics_1h
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
VALUES (3999, 'queue-1', 'depth', 1, 1, 1, 1, 1, ''),
       (4000, 'queue-1', 'depth', 2, 2, 2, 2, 1, '');
INSERT INTO metrics_1d
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
VALUES (4999, 'queue-1', 'depth', 1, 1, 1, 1, 1, ''),
       (5000, 'queue-1', 'depth', 2, 2, 2, 2, 1, '');
INSERT INTO telemetry_coverage
    (resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms)
VALUES ('raw', 999, 'queue-1', 'depth', '', 'gauge', 1000),
       ('raw', 1000, 'queue-1', 'depth', '', 'gauge', 1000),
       ('1m', 1999, 'queue-1', 'depth', '', 'gauge', 60000),
       ('1m', 2000, 'queue-1', 'depth', '', 'gauge', 60000),
       ('1h', 3999, 'queue-1', 'depth', '', 'gauge', 3600000),
       ('1h', 4000, 'queue-1', 'depth', '', 'gauge', 3600000),
       ('1d', 4999, 'queue-1', 'depth', '', 'gauge', 86400000),
       ('1d', 5000, 'queue-1', 'depth', '', 'gauge', 86400000);
INSERT INTO telemetry_collection_commits (boundary, sample_interval_ms)
VALUES (999, 1000), (1000, 1000);
INSERT INTO queue_stats_snapshot (timestamp, queue_id)
VALUES (999, 'queue-1'), (1000, 'queue-1');`); err != nil {
		t.Fatalf("seed cleanup tiers: %v", err)
	}

	if err := store.CleanupOldMetrics(context.Background(), 1000, 2000, 3000, 4000, 5000); err != nil {
		t.Fatalf("cleanup old metrics: %v", err)
	}

	for _, table := range []string{
		"metrics_raw", "metrics_1m", "metrics_5m", "metrics_1h", "metrics_1d",
		"telemetry_collection_commits", "queue_stats_snapshot",
	} {
		assertTableCount(t, conn, table, 1)
	}
	assertTableCount(t, conn, "telemetry_coverage", 4)

	var oldCoverage int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM telemetry_coverage
WHERE (resolution = 'raw' AND bucket_start < 1000)
   OR (resolution = '1m' AND bucket_start < 2000)
   OR (resolution = '1h' AND bucket_start < 4000)
   OR (resolution = '1d' AND bucket_start < 5000)`).Scan(&oldCoverage); err != nil {
		t.Fatalf("count old produced-tier coverage: %v", err)
	}
	if oldCoverage != 0 {
		t.Fatalf("old produced-tier coverage rows = %d, want 0", oldCoverage)
	}
}

func TestCleanupPreservesLatestRateSnapshotPerSeries(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO rate_snapshots (timestamp, queue_id, metric_name, rate_per_second, window_seconds, window_ms)
VALUES (100, 'active', 'send_rate', 1, 1, 1000),
       (1000, 'active', 'send_rate', 2, 1, 1000),
       (100, 'idle', 'send_rate', 3, 1, 1000),
       (200, 'idle', 'send_rate', 4, 1, 1000),
       (200, 'idle', 'send_rate', 5, 1, 1000),
       (300, 'idle', 'receive_rate', 6, 1, 1000);`); err != nil {
		t.Fatalf("seed rate snapshots: %v", err)
	}

	var newestIdleSendID int64
	if err := conn.QueryRow(`SELECT id FROM rate_snapshots
WHERE queue_id = 'idle' AND metric_name = 'send_rate'
ORDER BY timestamp DESC, id DESC LIMIT 1`).Scan(&newestIdleSendID); err != nil {
		t.Fatalf("read newest idle send snapshot: %v", err)
	}

	if err := store.CleanupOldMetrics(context.Background(), 1000, 0, 0, 0, 0); err != nil {
		t.Fatalf("cleanup rate snapshots: %v", err)
	}

	assertTableCount(t, conn, "rate_snapshots", 3)

	var retainedIdleSendID int64
	if err := conn.QueryRow(`SELECT id FROM rate_snapshots
WHERE queue_id = 'idle' AND metric_name = 'send_rate'`).Scan(&retainedIdleSendID); err != nil {
		t.Fatalf("read retained idle send snapshot: %v", err)
	}
	if retainedIdleSendID != newestIdleSendID {
		t.Fatalf("retained idle send snapshot id = %d, want newest tied id %d", retainedIdleSendID, newestIdleSendID)
	}

	for name, query := range map[string]string{
		"active recent snapshot": `SELECT COUNT(*) FROM rate_snapshots
WHERE queue_id = 'active' AND metric_name = 'send_rate' AND timestamp = 1000`,
		"idle receive snapshot": `SELECT COUNT(*) FROM rate_snapshots
WHERE queue_id = 'idle' AND metric_name = 'receive_rate' AND timestamp = 300`,
	} {
		var got int
		if err := conn.QueryRow(query).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		if got != 1 {
			t.Fatalf("%s count = %d, want 1", name, got)
		}
	}
}

func TestCleanupAndCoverageDeleteAtomically(t *testing.T) {
	t.Parallel()

	{
		store, _ := newTelemetryTestStoreWithConn(t)
		sample := testSample(100, "queue-1", "depth", MetricKindGauge, 1, 0)
		coverage := testCoverage(ResolutionRaw, 100, sample, 1000)
		if err := store.SaveMetricAndCoverage(context.Background(), sample, coverage); err != nil {
			t.Fatalf("seed cleanup snapshot: %v", err)
		}

		commitReady := make(chan struct{})
		releaseCommit := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseCommit) }) }
		defer release()

		store.commit = func(tx transaction) error {
			close(commitReady)
			<-releaseCommit

			return tx.Commit()
		}

		cleanupDone := make(chan error, 1)
		go func() {
			cleanupDone <- store.CleanupOldMetrics(context.Background(), 1000, 1000, 1000, 1000, 1000)
		}()

		select {
		case <-commitReady:
		case <-time.After(time.Second):
			t.Fatal("cleanup did not reach its transaction boundary")
		}

		before := mustQuerySeries(t, store, SeriesQuery{
			MetricName: "depth", SubjectID: "queue-1", Kind: MetricKindGauge,
			Resolution: ResolutionRaw, From: 0, To: 1000,
		})
		if len(before.DataPoints) != 1 || len(before.Coverage) != 1 {
			t.Fatalf("reader during cleanup = %d points/%d coverage, want coherent pre-cleanup 1/1",
				len(before.DataPoints), len(before.Coverage))
		}

		release()

		select {
		case err := <-cleanupDone:
			if err != nil {
				t.Fatalf("commit cleanup: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cleanup did not finish after commit release")
		}

		after := mustQuerySeries(t, store, SeriesQuery{
			MetricName: "depth", SubjectID: "queue-1", Kind: MetricKindGauge,
			Resolution: ResolutionRaw, From: 0, To: 1000,
		})
		if len(after.DataPoints) != 0 || len(after.Coverage) != 0 {
			t.Fatalf("reader after cleanup = %d points/%d coverage, want coherent post-cleanup 0/0",
				len(after.DataPoints), len(after.Coverage))
		}
	}

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`
INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (100, 'queue-1', 'depth', 1, '', 'gauge', 0);
INSERT INTO metrics_1m
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
VALUES (100, 'queue-1', 'depth', 1, 1, 1, 1, 1, '');
INSERT INTO metrics_5m
    (timestamp, queue_id, metric_name, metric_value_min, metric_value_max, metric_value_avg, labels)
VALUES (100, 'queue-1', 'depth', 1, 1, 1, '');
INSERT INTO metrics_1h
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
VALUES (100, 'queue-1', 'depth', 1, 1, 1, 1, 1, '');
INSERT INTO metrics_1d
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
VALUES (100, 'queue-1', 'depth', 1, 1, 1, 1, 1, '');
INSERT INTO telemetry_coverage
    (resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms)
VALUES ('raw', 100, 'queue-1', 'depth', '', 'gauge', 1000),
       ('1m', 100, 'queue-1', 'depth', '', 'gauge', 60000),
       ('1h', 100, 'queue-1', 'depth', '', 'gauge', 3600000),
       ('1d', 100, 'queue-1', 'depth', '', 'gauge', 86400000);
INSERT INTO telemetry_collection_commits (boundary, sample_interval_ms) VALUES (100, 1000);
INSERT INTO queue_stats_snapshot (timestamp, queue_id) VALUES (100, 'queue-1');
INSERT INTO rate_snapshots (timestamp, queue_id, metric_name, rate_per_second, window_seconds, window_ms)
VALUES (100, 'queue-1', 'send_rate', 1, 1, 1000),
       (200, 'queue-1', 'send_rate', 2, 1, 1000);
CREATE TRIGGER fail_late_cleanup BEFORE DELETE ON rate_snapshots
WHEN OLD.timestamp = 100
BEGIN SELECT RAISE(ABORT, 'late cleanup failure'); END;`); err != nil {
		t.Fatalf("seed atomic cleanup failure: %v", err)
	}

	if err := store.CleanupOldMetrics(context.Background(), 1000, 1000, 1000, 1000, 1000); err == nil {
		t.Fatal("CleanupOldMetrics returned nil, want late delete failure")
	}

	for table, want := range map[string]int{
		"metrics_raw":                  1,
		"metrics_1m":                   1,
		"metrics_5m":                   1,
		"metrics_1h":                   1,
		"metrics_1d":                   1,
		"telemetry_coverage":           4,
		"telemetry_collection_commits": 1,
		"queue_stats_snapshot":         1,
		"rate_snapshots":               2,
	} {
		assertTableCount(t, conn, table, want)
	}
}

func TestCollectorStoreInterfaceCompilesDuringTypedMigration(t *testing.T) {
	t.Parallel()

	var _ Store = (*SQLiteStore)(nil)
}

func testSample(timestamp int64, subject, metric string, kind MetricKind, value float64, windowMS int64) MetricSample {
	return MetricSample{
		Timestamp: timestamp, SubjectID: subject, MetricName: metric,
		Kind: kind, Value: value, Labels: "", WindowMS: windowMS,
	}
}

func testCoverage(resolution Resolution, bucket int64, sample MetricSample, interval int64) CoverageBucket {
	return CoverageBucket{
		Resolution: resolution, BucketStart: bucket, SubjectID: sample.SubjectID,
		MetricName: sample.MetricName, Labels: sample.Labels, Kind: sample.Kind,
		SampleIntervalMS: interval,
	}
}

func testCollectionBatch() CollectionBatch {
	gauge := testSample(1000, "queue-1", "depth", MetricKindGauge, 2, 0)
	event := testSample(1250, "queue-1", "publish_fanout", MetricKindEvent, 3, 0)
	rate := testSample(1000, "queue-1", "send_rate", MetricKindRate, 4, 1500)
	return CollectionBatch{
		Boundary: 2000, SampleIntervalMS: 1000,
		Samples: []MetricSample{gauge, event, rate},
		RateSnapshots: []RateSnapshot{{
			Timestamp: rate.Timestamp, SubjectID: rate.SubjectID, MetricName: rate.MetricName,
			Rate: rate.Value, WindowMS: rate.WindowMS,
		}},
		Coverage: []CoverageBucket{
			testCoverage(ResolutionRaw, 1000, gauge, 1000),
			testCoverage(ResolutionRaw, 1000, rate, 1000),
			{Resolution: ResolutionRaw, BucketStart: 1000, SubjectID: "queue-1", SampleIntervalMS: 1000},
		},
	}
}

func shiftedCollectionBatch(delta int64) CollectionBatch {
	batch := testCollectionBatch()
	batch.Boundary += delta
	for index := range batch.Samples {
		batch.Samples[index].Timestamp += delta
	}
	for index := range batch.RateSnapshots {
		batch.RateSnapshots[index].Timestamp += delta
	}
	for index := range batch.Coverage {
		batch.Coverage[index].BucketStart += delta
	}

	return batch
}

func assertTableCount(t *testing.T, conn *litekit.Conn, table string, want int) {
	t.Helper()
	var got int
	if err := conn.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil { //nolint:gosec // table is a test constant.
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}

func assertRawCoverageCount(t *testing.T, conn *litekit.Conn, want int) {
	t.Helper()
	var got int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM telemetry_coverage WHERE resolution = 'raw'`).Scan(&got); err != nil {
		t.Fatalf("count raw coverage: %v", err)
	}
	if got != want {
		t.Fatalf("raw coverage count = %d, want %d", got, want)
	}
}

func assertDataPointTimestamps(t *testing.T, points []DataPoint, want []int64) {
	t.Helper()
	if len(points) != len(want) {
		t.Fatalf("data point count = %d, want %d: %#v", len(points), len(want), points)
	}
	for index, timestamp := range want {
		if points[index].Timestamp != timestamp {
			t.Fatalf("data point %d timestamp = %d, want %d: %#v", index, points[index].Timestamp, timestamp, points)
		}
	}
}

func assertCoverageBucketStarts(t *testing.T, coverage []CoverageBucket, want []int64) {
	t.Helper()
	if len(coverage) != len(want) {
		t.Fatalf("coverage count = %d, want %d: %#v", len(coverage), len(want), coverage)
	}
	for index, bucketStart := range want {
		if coverage[index].BucketStart != bucketStart {
			t.Fatalf(
				"coverage %d bucket start = %d, want %d: %#v",
				index, coverage[index].BucketStart, bucketStart, coverage,
			)
		}
	}
}
