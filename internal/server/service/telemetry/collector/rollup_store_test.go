package collector

import (
	"context"
	"math"
	"slices"
	"testing"

	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestGaugeRollupValueIsLast(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	seedRawGrid(t, store, "queue-1", "depth", MetricKindGauge, 0, 60000, 1000, func(index int64) (float64, int64) {
		return float64(index), 0
	})
	if err := store.Rollup(context.Background(), Resolution1m, 60000); err != nil {
		t.Fatalf("roll up gauge: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "depth", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	if len(result.DataPoints) != 1 {
		t.Fatalf("gauge points = %#v, want one", result.DataPoints)
	}
	point := result.DataPoints[0]
	if point.Avg == point.Last || point.Value != point.Last || point.Value != 59 {
		t.Fatalf("gauge point = %#v, want value=last=59 and avg different", point)
	}
}

func TestCounterRollupUsesResetAwareIncrease(t *testing.T) {
	t.Parallel()

	t.Run("covered adjacent prior", func(t *testing.T) {
		store := newTelemetryTestStore(t)
		ctx := context.Background()
		prior := testSample(-1000, "queue-1", "published", MetricKindCounter, 90, 0)
		if err := store.SaveMetricAndCoverage(ctx, prior, testCoverage(ResolutionRaw, -1000, prior, 1000)); err != nil {
			t.Fatalf("seed prior: %v", err)
		}
		seedRawGrid(t, store, "queue-1", "published", MetricKindCounter, 0, 60000, 1000, func(index int64) (float64, int64) {
			switch index {
			case 0:
				return 100, 0
			case 1:
				return 3, 0
			default:
				return 8, 0
			}
		})
		if err := store.Rollup(ctx, Resolution1m, 60000); err != nil {
			t.Fatalf("roll up counter: %v", err)
		}
		result := mustQuerySeries(t, store, SeriesQuery{
			SubjectID: "queue-1", MetricName: "published", Kind: MetricKindCounter,
			Resolution: Resolution1m, From: 0, To: 60000,
		})
		if len(result.DataPoints) != 1 || result.DataPoints[0].Increase != 18 || result.DataPoints[0].Value != 18 {
			t.Fatalf("counter point = %#v, want reset-aware increase 18", result.DataPoints)
		}
		if len(result.Coverage) != 1 {
			t.Fatalf("counter coverage = %#v, want complete", result.Coverage)
		}
	})

	t.Run("missing prior retains visible increase without coverage", func(t *testing.T) {
		store := newTelemetryTestStore(t)
		seedRawGrid(t, store, "queue-1", "published", MetricKindCounter, 0, 60000, 1000, func(index int64) (float64, int64) {
			switch index {
			case 0:
				return 90, 0
			case 1:
				return 100, 0
			case 2:
				return 3, 0
			default:
				return 8, 0
			}
		})
		if err := store.Rollup(context.Background(), Resolution1m, 60000); err != nil {
			t.Fatalf("roll up counter: %v", err)
		}
		result := mustQuerySeries(t, store, SeriesQuery{
			SubjectID: "queue-1", MetricName: "published", Kind: MetricKindCounter,
			Resolution: Resolution1m, From: 0, To: 60000,
		})
		if len(result.DataPoints) != 1 || result.DataPoints[0].Increase != 18 {
			t.Fatalf("visible counter point = %#v, want 18", result.DataPoints)
		}
		if len(result.Coverage) != 0 {
			t.Fatalf("counter coverage = %#v, want incomplete without baseline", result.Coverage)
		}
	})
}

func TestCounterRollupDoesNotBridgeInterveningCoverageGap(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	older := testSample(-2000, "queue-1", "published", MetricKindCounter, 90, 0)
	if err := store.SaveMetricAndCoverage(ctx, older, testCoverage(ResolutionRaw, -2000, older, 1000)); err != nil {
		t.Fatalf("seed older counter: %v", err)
	}
	seedRawGrid(t, store, "queue-1", "published", MetricKindCounter, 0, 60000, 1000, func(index int64) (float64, int64) {
		switch index {
		case 0:
			return 100, 0
		case 1:
			return 3, 0
		default:
			return 8, 0
		}
	})
	if err := store.Rollup(ctx, Resolution1m, 60000); err != nil {
		t.Fatalf("roll up counter gap: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "published", Kind: MetricKindCounter,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	if len(result.DataPoints) != 1 || result.DataPoints[0].Increase != 8 {
		t.Fatalf("gap counter point = %#v, want only visible in-bucket increase 8", result.DataPoints)
	}
	if len(result.Coverage) != 0 {
		t.Fatalf("gap counter coverage = %#v, want incomplete", result.Coverage)
	}
}

func TestRateRollupUsesWeightedAverage(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	seedRawGrid(t, store, "queue-1", "send_rate", MetricKindRate, 0, 60000, 1000, func(index int64) (float64, int64) {
		if index < 30 {
			return 2, 1000
		}
		return 10, 2000
	})
	if err := store.Rollup(context.Background(), Resolution1m, 60000); err != nil {
		t.Fatalf("roll up rate: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "send_rate", Kind: MetricKindRate,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	if len(result.DataPoints) != 1 {
		t.Fatalf("rate points = %#v, want one", result.DataPoints)
	}
	want := (2*30000.0 + 10*60000.0) / 90000.0
	if math.Abs(result.DataPoints[0].Avg-want) > 1e-9 || result.DataPoints[0].WindowMS != 90000 {
		t.Fatalf("rate point = %#v, want weighted avg %v/window 90000", result.DataPoints[0], want)
	}
}

func TestRateRollupRejectsNonPositiveRawWindowMS(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	if _, err := conn.Exec(`INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (0, 'queue-1', 'send_rate', 2, '', 'rate', 0)`); err != nil {
		t.Fatalf("seed invalid raw rate: %v", err)
	}
	seedCoverageRow(t, store, ResolutionRaw, 0, "queue-1", "send_rate", MetricKindRate, 1000)
	if err := store.Rollup(context.Background(), Resolution1m, 60000); err == nil {
		t.Fatal("Rollup accepted a raw rate with non-positive window_ms")
	}
	assertTableCount(t, conn, "metrics_1m", 0)
}

func TestEventRollupPreservesWeightedFanout(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	for timestamp := int64(0); timestamp < 60000; timestamp += 1000 {
		if err := store.SaveCoverage(ctx, CoverageBucket{
			Resolution: ResolutionRaw, BucketStart: timestamp, SubjectID: "topic-1",
			MetricName: "publish_fanout", Kind: MetricKindEvent, SampleIntervalMS: 1000,
		}); err != nil {
			t.Fatalf("seed event coverage: %v", err)
		}
	}
	for _, sample := range []MetricSample{
		testSample(100, "topic-1", "publish_fanout", MetricKindEvent, 3, 0),
		testSample(200, "topic-1", "publish_fanout", MetricKindEvent, 9, 0),
	} {
		if err := store.SaveMetric(ctx, sample); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	if err := store.Rollup(ctx, Resolution1m, 60000); err != nil {
		t.Fatalf("roll up event: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "topic-1", MetricName: "publish_fanout", Kind: MetricKindEvent,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	if len(result.DataPoints) != 1 {
		t.Fatalf("event points = %#v, want one", result.DataPoints)
	}
	point := result.DataPoints[0]
	if point.Sum != 12 || point.Count != 2 || point.Avg != 6 || point.Value != 6 {
		t.Fatalf("event aggregate = %#v, want sum=12 count=2 avg=value=6", point)
	}
}

func TestRollupPropagatesCoveredZeroEventWithoutFabricatingPoint(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	for timestamp := int64(0); timestamp < 60000; timestamp += 1000 {
		seedCoverageRow(t, store, ResolutionRaw, timestamp, "topic-1", "publish_fanout", MetricKindEvent, 1000)
	}
	if err := store.Rollup(context.Background(), Resolution1m, 60000); err != nil {
		t.Fatalf("roll up zero-event coverage: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "topic-1", MetricName: "publish_fanout", Kind: MetricKindEvent,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	if len(result.DataPoints) != 0 || len(result.Coverage) != 1 {
		t.Fatalf("zero-event result = %#v, want no point and complete coverage", result)
	}
}

func TestRollupSubjectCoverageRequiresEveryExpectedSeries(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	ctx := context.Background()
	missing := testSample(-1000, "queue-1", "missing_now", MetricKindGauge, 1, 0)
	if err := store.SaveMetricAndCoverage(ctx, missing, testCoverage(ResolutionRaw, -1000, missing, 1000)); err != nil {
		t.Fatalf("seed prior expected series: %v", err)
	}
	seedRawGrid(t, store, "queue-1", "depth", MetricKindGauge, 0, 60000, 1000, func(index int64) (float64, int64) {
		return float64(index), 0
	})
	for timestamp := int64(0); timestamp < 60000; timestamp += 1000 {
		if err := store.SaveCoverage(ctx, CoverageBucket{
			Resolution: ResolutionRaw, BucketStart: timestamp,
			SubjectID: "queue-1", SampleIntervalMS: 1000,
		}); err != nil {
			t.Fatalf("seed subject coverage: %v", err)
		}
	}
	if err := store.Rollup(ctx, Resolution1m, 60000); err != nil {
		t.Fatalf("roll up subject coverage: %v", err)
	}
	coverage, err := store.QuerySubjectCoverage(ctx, SubjectCoverageQuery{
		SubjectID: "queue-1", Resolution: Resolution1m, From: 0, To: 60000,
	})
	if err != nil {
		t.Fatalf("query rolled subject coverage: %v", err)
	}
	if len(coverage) != 0 {
		t.Fatalf("subject coverage = %#v, want withheld for missing expected series", coverage)
	}
}

func TestRollupProcessesClosedBucketsOnly(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	seedRawGrid(t, store, "queue-1", "depth", MetricKindGauge, 0, 120000, 1000, func(index int64) (float64, int64) {
		return float64(index), 0
	})
	ctx := context.Background()
	if err := store.Rollup(ctx, Resolution1m, 59999); err != nil {
		t.Fatalf("roll up open bucket: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "depth", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 120000,
	})
	if len(result.DataPoints) != 0 {
		t.Fatalf("open-bucket rollup wrote %#v", result.DataPoints)
	}
	if err := store.Rollup(ctx, Resolution1m, 60000); err != nil {
		t.Fatalf("roll up first closed bucket: %v", err)
	}
	result = mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "depth", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 120000,
	})
	if len(result.DataPoints) != 1 || result.DataPoints[0].Timestamp != 0 {
		t.Fatalf("closed-bucket points = %#v, want only bucket zero", result.DataPoints)
	}
}

func TestRollupIsIdempotentAndDoesNotReplaceCompleteBucketWithTail(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	seedRawGrid(t, store, "queue-1", "depth", MetricKindGauge, 0, 60000, 1000, func(index int64) (float64, int64) {
		return float64(index), 0
	})
	ctx := context.Background()
	if err := store.Rollup(ctx, Resolution1m, 60000); err != nil {
		t.Fatalf("initial rollup: %v", err)
	}
	before := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "depth", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	late := testSample(59000, "queue-1", "depth", MetricKindGauge, 999, 0)
	if err := store.SaveMetric(context.Background(), late); err != nil {
		t.Fatalf("seed late tail: %v", err)
	}
	for range 2 {
		if err := store.Rollup(ctx, Resolution1m, 61000); err != nil {
			t.Fatalf("repeat rollup: %v", err)
		}
	}
	after := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "depth", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 60000,
	})
	if len(before.DataPoints) != 1 || len(after.DataPoints) != 1 || after.DataPoints[0] != before.DataPoints[0] {
		t.Fatalf("idempotent rollup changed %#v to %#v", before.DataPoints, after.DataPoints)
	}
}

func TestRollupCatchesUpRetainedBucketsFromCheckpoint(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	seedRawGrid(t, store, "queue-1", "depth", MetricKindGauge, 0, 180000, 1000, func(index int64) (float64, int64) {
		return float64(index), 0
	})
	ctx := context.Background()
	if err := store.Rollup(ctx, Resolution1m, 120000); err != nil {
		t.Fatalf("catch up first two buckets: %v", err)
	}
	if err := store.Rollup(ctx, Resolution1m, 180000); err != nil {
		t.Fatalf("continue checkpoint: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "depth", Kind: MetricKindGauge,
		Resolution: Resolution1m, From: 0, To: 180000,
	})
	if len(result.DataPoints) != 3 {
		t.Fatalf("catch-up points = %#v, want three", result.DataPoints)
	}
}

func TestRollupIdentityIncludesMetricKindAfterUpgrade(t *testing.T) {
	t.Parallel()

	store := newTelemetryTestStore(t)
	seedRawGrid(t, store, "queue-1", "same", MetricKindGauge, 0, 60000, 1000, func(index int64) (float64, int64) {
		return float64(index), 0
	})
	prior := testSample(-1000, "queue-1", "same", MetricKindCounter, 0, 0)
	if err := store.SaveMetricAndCoverage(context.Background(), prior, testCoverage(ResolutionRaw, -1000, prior, 1000)); err != nil {
		t.Fatalf("seed counter baseline: %v", err)
	}
	seedRawGrid(t, store, "queue-1", "same", MetricKindCounter, 0, 60000, 1000, func(index int64) (float64, int64) {
		return float64(index + 1), 0
	})
	if err := store.Rollup(context.Background(), Resolution1m, 60000); err != nil {
		t.Fatalf("roll up kind identities: %v", err)
	}
	for _, kind := range []MetricKind{MetricKindGauge, MetricKindCounter} {
		result := mustQuerySeries(t, store, SeriesQuery{
			SubjectID: "queue-1", MetricName: "same", Kind: kind,
			Resolution: Resolution1m, From: 0, To: 60000,
		})
		if len(result.DataPoints) != 1 {
			t.Fatalf("%s points = %#v, want one", kind, result.DataPoints)
		}
	}
}

func TestRollupIdentityAllowsLegacyGaugeBesideNewTypedRow(t *testing.T) {
	t.Parallel()

	_, conn := newTelemetryTestStoreWithConn(t)
	for _, kind := range []MetricKind{MetricKindGauge, MetricKindCounter} {
		if _, err := conn.Exec(`INSERT INTO metrics_1m
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count,
     labels, metric_kind, first_value, last_value, increase_value, window_ms)
VALUES (0, 'queue-1', 'same', 1, 1, 1, 1, 1, '', ?, 1, 1, 1, 0)`, string(kind)); err != nil {
			t.Fatalf("insert %s identity: %v", kind, err)
		}
	}
	assertTableCount(t, conn, "metrics_1m", 2)
}

func TestTypedRollupIndexesIncludeMetricKind(t *testing.T) {
	t.Parallel()

	_, conn := newTelemetryTestStoreWithConn(t)
	for _, index := range []string{
		"idx_metrics_raw_composite", "idx_metrics_1m_unique", "idx_metrics_1m_composite",
		"idx_metrics_1h_unique", "idx_metrics_1h_composite", "idx_metrics_1d_unique", "idx_metrics_1d_composite",
	} {
		rows, err := conn.Query(`PRAGMA index_info('` + index + `')`) //nolint:gosec // index is a test constant.
		if err != nil {
			t.Fatalf("inspect index %s: %v", index, err)
		}
		columns := make([]string, 0)
		for rows.Next() {
			var sequence, columnID int
			var name string
			if err := rows.Scan(&sequence, &columnID, &name); err != nil {
				rows.Close()
				t.Fatalf("scan index %s: %v", index, err)
			}
			columns = append(columns, name)
		}
		if err := rows.Close(); err != nil {
			t.Fatalf("close index rows %s: %v", index, err)
		}
		if !slices.Contains(columns, "metric_kind") {
			t.Fatalf("index %s columns = %v, want metric_kind", index, columns)
		}
	}
}

func TestCounterRollupCountsCrossChildIncreaseAndResetExactlyOnce(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	seedAggregateRow(t, conn, Resolution1m, -60000, "queue-1", "published", MetricKindCounter, 90, 90, 0, 1, 0)
	seedCoverageRow(t, store, Resolution1m, -60000, "queue-1", "published", MetricKindCounter, 60000)
	for child := int64(0); child < 60; child++ {
		first, last, increase := 8.0, 8.0, 0.0
		if child == 0 {
			first, last, increase = 100, 110, 20
		} else if child == 1 {
			first, last, increase = 3, 8, 8
		}
		seedAggregateRow(t, conn, Resolution1m, child*60000, "queue-1", "published", MetricKindCounter,
			first, last, increase, 1, 0)
		seedCoverageRow(t, store, Resolution1m, child*60000, "queue-1", "published", MetricKindCounter, 60000)
	}
	if err := store.Rollup(context.Background(), Resolution1h, 3600000); err != nil {
		t.Fatalf("roll up child counters: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "published", Kind: MetricKindCounter,
		Resolution: Resolution1h, From: 0, To: 3600000,
	})
	if len(result.DataPoints) != 1 || result.DataPoints[0].Increase != 28 || result.DataPoints[0].Value != 28 {
		t.Fatalf("parent counter = %#v, want increase 28", result.DataPoints)
	}
}

func TestRateRollupWeightsDifferentWindowMS(t *testing.T) {
	t.Parallel()

	store, conn := newTelemetryTestStoreWithConn(t)
	for child := int64(0); child < 60; child++ {
		value, window := 2.0, int64(1000)
		if child >= 30 {
			value, window = 10, 2000
		}
		seedAggregateRow(t, conn, Resolution1m, child*60000, "queue-1", "send_rate", MetricKindRate,
			value, value, 0, 1, window)
		seedCoverageRow(t, store, Resolution1m, child*60000, "queue-1", "send_rate", MetricKindRate, 60000)
	}
	if err := store.Rollup(context.Background(), Resolution1h, 3600000); err != nil {
		t.Fatalf("roll up child rates: %v", err)
	}
	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: "send_rate", Kind: MetricKindRate,
		Resolution: Resolution1h, From: 0, To: 3600000,
	})
	want := (2*30000.0 + 10*60000.0) / 90000.0
	if len(result.DataPoints) != 1 || math.Abs(result.DataPoints[0].Avg-want) > 1e-9 || result.DataPoints[0].WindowMS != 90000 {
		t.Fatalf("parent rate = %#v, want weighted avg %v/window 90000", result.DataPoints, want)
	}
}

func seedRawGrid(
	t *testing.T,
	store *SQLiteStore,
	subjectID, metricName string,
	kind MetricKind,
	from, to, interval int64,
	value func(index int64) (float64, int64),
) {
	t.Helper()
	ctx := context.Background()
	for timestamp, index := from, int64(0); timestamp < to; timestamp, index = timestamp+interval, index+1 {
		metricValue, windowMS := value(index)
		sample := testSample(timestamp, subjectID, metricName, kind, metricValue, windowMS)
		if err := store.SaveMetricAndCoverage(ctx, sample, testCoverage(ResolutionRaw, timestamp, sample, interval)); err != nil {
			t.Fatalf("seed raw grid %s/%s at %d: %v", subjectID, metricName, timestamp, err)
		}
	}
}

func mustQuerySeries(t *testing.T, store *SQLiteStore, query SeriesQuery) SeriesResult {
	t.Helper()
	result, err := store.QuerySeries(context.Background(), query)
	if err != nil {
		t.Fatalf("query series %#v: %v", query, err)
	}
	return result
}

func seedCoverageRow(
	t *testing.T,
	store *SQLiteStore,
	resolution Resolution,
	bucket int64,
	subjectID, metricName string,
	kind MetricKind,
	interval int64,
) {
	t.Helper()
	if err := store.SaveCoverage(context.Background(), CoverageBucket{
		Resolution: resolution, BucketStart: bucket, SubjectID: subjectID,
		MetricName: metricName, Kind: kind, SampleIntervalMS: interval,
	}); err != nil {
		t.Fatalf("seed %s coverage at %d: %v", resolution, bucket, err)
	}
}

func seedAggregateRow(
	t *testing.T,
	conn *litekit.Conn,
	resolution Resolution,
	bucket int64,
	subjectID, metricName string,
	kind MetricKind,
	first, last, increase float64,
	count, windowMS int64,
) {
	t.Helper()
	table, _, err := resolutionTable(resolution)
	if err != nil {
		t.Fatalf("aggregate table: %v", err)
	}
	statement := `INSERT INTO ` + table + `
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count,
     labels, metric_kind, first_value, last_value, increase_value, window_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?)` //nolint:gosec // table selected from resolution constants.
	avg := last
	sum := avg * float64(count)
	if _, err := conn.Exec(statement, bucket, subjectID, metricName, math.Min(first, last), math.Max(first, last),
		avg, sum, count, string(kind), first, last, increase, windowMS); err != nil {
		t.Fatalf("seed aggregate %s/%s at %d: %v", subjectID, metricName, bucket, err)
	}
}
