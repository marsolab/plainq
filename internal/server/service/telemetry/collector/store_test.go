package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestGetTopicMetricsSummarySingleSampleUsesInRangeValue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTelemetryTestStore(t)

	seedRawMetric(t, store, 100, "topic-1", MetricTopicMessagesPublishedTotal, 7)
	seedRawMetric(t, store, 100, "topic-1", MetricTopicDeliveriesTotal, 11)

	summary, err := store.GetTopicMetricsSummary(ctx, "topic-1", 50, 150)
	if err != nil {
		t.Fatalf("GetTopicMetricsSummary returned error: %v", err)
	}
	if summary.TotalPublished != 7 {
		t.Fatalf("TotalPublished = %d, want 7", summary.TotalPublished)
	}
	if summary.TotalDeliveries != 11 {
		t.Fatalf("TotalDeliveries = %d, want 11", summary.TotalDeliveries)
	}
}

func TestGetTopicMetricsSummaryMultipleSamplesUseLastInRangeValueWithoutPriorSample(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTelemetryTestStore(t)

	seedRawMetric(t, store, 100, "topic-1", MetricTopicMessagesPublishedTotal, 4)
	seedRawMetric(t, store, 120, "topic-1", MetricTopicMessagesPublishedTotal, 9)
	seedRawMetric(t, store, 100, "topic-1", MetricTopicDeliveriesTotal, 8)
	seedRawMetric(t, store, 120, "topic-1", MetricTopicDeliveriesTotal, 15)

	summary, err := store.GetTopicMetricsSummary(ctx, "topic-1", 50, 150)
	if err != nil {
		t.Fatalf("GetTopicMetricsSummary returned error: %v", err)
	}
	if summary.TotalPublished != 9 {
		t.Fatalf("TotalPublished = %d, want 9", summary.TotalPublished)
	}
	if summary.TotalDeliveries != 15 {
		t.Fatalf("TotalDeliveries = %d, want 15", summary.TotalDeliveries)
	}
}

func TestGetTopicMetricsSummarySubtractsLastSampleBeforeRange(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTelemetryTestStore(t)

	seedRawMetric(t, store, 90, "topic-1", MetricTopicMessagesPublishedTotal, 4)
	seedRawMetric(t, store, 100, "topic-1", MetricTopicMessagesPublishedTotal, 7)
	seedRawMetric(t, store, 110, "topic-1", MetricTopicMessagesPublishedTotal, 10)
	seedRawMetric(t, store, 90, "topic-1", MetricTopicDeliveriesTotal, 6)
	seedRawMetric(t, store, 100, "topic-1", MetricTopicDeliveriesTotal, 9)
	seedRawMetric(t, store, 110, "topic-1", MetricTopicDeliveriesTotal, 14)

	summary, err := store.GetTopicMetricsSummary(ctx, "topic-1", 100, 150)
	if err != nil {
		t.Fatalf("GetTopicMetricsSummary returned error: %v", err)
	}
	if summary.TotalPublished != 6 {
		t.Fatalf("TotalPublished = %d, want 6", summary.TotalPublished)
	}
	if summary.TotalDeliveries != 8 {
		t.Fatalf("TotalDeliveries = %d, want 8", summary.TotalDeliveries)
	}
}

func TestGetTopicMetricsSummaryReturnsErrorOnLookupFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTelemetryTestStore(t)

	if err := store.db.Close(); err != nil {
		t.Fatalf("close litekit connection: %v", err)
	}

	if _, err := store.GetTopicMetricsSummary(ctx, "topic-1", 100, 200); err == nil {
		t.Fatal("GetTopicMetricsSummary returned nil error, want lookup failure")
	}
}

func TestGetTopicMetricsSummaryHandlesCounterReset(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTelemetryTestStore(t)

	seedRawMetric(t, store, 90, "topic-1", MetricTopicMessagesPublishedTotal, 100)
	seedRawMetric(t, store, 100, "topic-1", MetricTopicMessagesPublishedTotal, 1)
	seedRawMetric(t, store, 110, "topic-1", MetricTopicMessagesPublishedTotal, 4)
	seedRawMetric(t, store, 90, "topic-1", MetricTopicDeliveriesTotal, 200)
	seedRawMetric(t, store, 100, "topic-1", MetricTopicDeliveriesTotal, 2)
	seedRawMetric(t, store, 110, "topic-1", MetricTopicDeliveriesTotal, 9)

	summary, err := store.GetTopicMetricsSummary(ctx, "topic-1", 100, 150)
	if err != nil {
		t.Fatalf("GetTopicMetricsSummary returned error: %v", err)
	}
	if summary.TotalPublished != 4 {
		t.Fatalf("TotalPublished = %d, want 4", summary.TotalPublished)
	}
	if summary.TotalDeliveries != 9 {
		t.Fatalf("TotalDeliveries = %d, want 9", summary.TotalDeliveries)
	}
}

func TestGetTopicMetricsSummaryUsesNilSubscriptionsWhenGaugeMissing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTelemetryTestStore(t)

	summary, err := store.GetTopicMetricsSummary(ctx, "topic-1", 100, 150)
	if err != nil {
		t.Fatalf("GetTopicMetricsSummary returned error: %v", err)
	}
	if summary.Subscriptions != nil {
		t.Fatalf("Subscriptions = %v, want nil", summary.Subscriptions)
	}
}

func newTelemetryTestStore(t *testing.T) *SQLiteStore {
	t.Helper()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("open litekit connection: %v", err)
	}

	schema, err := os.ReadFile(filepath.Join("..", "..", "..", "mutations", "telemetry", "3_metrics_enhanced.sql"))
	if err != nil {
		t.Fatalf("read telemetry schema: %v", err)
	}

	if _, err := conn.ExecContext(context.Background(), string(schema)); err != nil {
		t.Fatalf("apply telemetry schema: %v", err)
	}

	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("close litekit connection: %v", err)
		}
	})

	return NewSQLiteStore(conn)
}

func seedRawMetric(t *testing.T, store *SQLiteStore, timestamp int64, queueID, metricName string, value float64) {
	t.Helper()

	if err := store.SaveRawMetric(context.Background(), timestamp, queueID, metricName, value, ""); err != nil {
		t.Fatalf("SaveRawMetric(%s, %s): %v", queueID, metricName, err)
	}
}
