package collector

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestTopicMetricsRecordPublishAndRates(t *testing.T) {
	store := newRecordingStore()
	c := New(store)

	c.RecordTopicPublish("topic-1", 3, 9)
	c.calculateRates(context.Background())

	rates := c.GetTopicRates("topic-1")
	if rates.PublishRate != 3 {
		t.Fatalf("PublishRate = %v, want 3", rates.PublishRate)
	}
	if rates.DeliveryRate != 9 {
		t.Fatalf("DeliveryRate = %v, want 9", rates.DeliveryRate)
	}

	counters := c.GetTopicCounters("topic-1")
	if counters.MessagesPublished != 3 {
		t.Fatalf("MessagesPublished = %d, want 3", counters.MessagesPublished)
	}
	if counters.Deliveries != 9 {
		t.Fatalf("Deliveries = %d, want 9", counters.Deliveries)
	}

	store.assertRate(t, "topic-1", MetricTopicPublishRate, 3)
	store.assertRate(t, "topic-1", MetricTopicDeliveryRate, 9)
	store.assertRaw(t, "topic-1", MetricTopicMessagesPublishedTotal, 3)
	store.assertRaw(t, "topic-1", MetricTopicDeliveriesTotal, 9)
}

func TestTopicMetricsRecordSubscriptions(t *testing.T) {
	store := newRecordingStore()
	c := New(store)

	c.RecordTopicSubscriptionCreated("topic-1", 2)
	c.RecordTopicSubscriptionDeleted("topic-1", 1)
	c.calculateRates(context.Background())

	counters := c.GetTopicCounters("topic-1")
	if counters.SubscriptionsCreated != 1 {
		t.Fatalf("SubscriptionsCreated = %d, want 1", counters.SubscriptionsCreated)
	}
	if counters.SubscriptionsDeleted != 1 {
		t.Fatalf("SubscriptionsDeleted = %d, want 1", counters.SubscriptionsDeleted)
	}
	if current := c.GetTopicSubscriptionsCurrent("topic-1"); current != 1 {
		t.Fatalf("current subscriptions = %d, want 1", current)
	}

	system := c.GetTopicSystemCounters()
	if system.SubscriptionsCurrent != 1 {
		t.Fatalf("system current subscriptions = %d, want 1", system.SubscriptionsCurrent)
	}

	store.assertRaw(t, "topic-1", MetricTopicSubscriptionsCurrent, 1)
	store.assertRaw(t, "topic-1", MetricTopicSubscriptionsCreatedTotal, 1)
	store.assertRaw(t, "topic-1", MetricTopicSubscriptionsDeletedTotal, 1)
}

func TestTopicMetricsUnknownSubscriptionCountDoesNotPersistFalseZero(t *testing.T) {
	store := newRecordingStore()
	c := New(store)

	c.RecordTopicSubscriptionCreated("topic-1", -1)
	c.calculateRates(context.Background())

	if _, ok := c.GetTopicSubscriptionsCurrentKnown("topic-1"); ok {
		t.Fatal("current subscriptions marked known, want unknown")
	}

	system := c.GetTopicSystemCounters()
	if system.SubscriptionsCurrentKnown {
		t.Fatal("system current subscriptions marked known, want unknown")
	}

	store.assertRawAbsent(t, "topic-1", MetricTopicSubscriptionsCurrent)
	store.assertRawAbsent(t, "", MetricTopicSubscriptionsCurrent)
	store.assertRaw(t, "topic-1", MetricTopicSubscriptionsCreatedTotal, 1)
}

func TestTopicMetricsLastUpdatedTracksMetricEvents(t *testing.T) {
	c := New(nil)

	if got := c.GetTopicLastUpdated("topic-1"); got != 0 {
		t.Fatalf("last updated before activity = %d, want 0", got)
	}

	c.RecordTopicPublish("topic-1", 1, 1)
	firstUpdatedAt := c.GetTopicLastUpdated("topic-1")
	if firstUpdatedAt == 0 {
		t.Fatal("last updated after publish = 0, want non-zero timestamp")
	}

	time.Sleep(2 * time.Millisecond)
	c.RecordTopicSubscriptionCreated("topic-1", 1)
	secondUpdatedAt := c.GetTopicLastUpdated("topic-1")
	if secondUpdatedAt <= firstUpdatedAt {
		t.Fatalf("last updated after subscription = %d, want greater than %d", secondUpdatedAt, firstUpdatedAt)
	}
}

func TestTopicMetricsReconcileSubscriptionCountsRemovesMissingTopics(t *testing.T) {
	c := New(nil)
	c.RecordTopicSubscriptionCreated("topic-1", 2)
	c.RecordTopicSubscriptionCreated("topic-2", 1)

	c.ReconcileTopicSubscriptionCounts(map[string]int64{"topic-1": 1})

	if got := c.GetTopicSubscriptionsCurrent("topic-1"); got != 1 {
		t.Fatalf("topic-1 current subscriptions = %d, want 1", got)
	}
	if got := c.GetTopicSubscriptionsCurrent("topic-2"); got != 0 {
		t.Fatalf("topic-2 current subscriptions = %d, want 0", got)
	}
	if ids := c.GetAllTopicIDs(); slices.Contains(ids, "topic-2") {
		t.Fatalf("tracked topic IDs = %v, want topic-2 removed", ids)
	}

	system := c.GetTopicSystemCounters()
	if system.SubscriptionsCurrent != 1 {
		t.Fatalf("system current subscriptions = %d, want 1", system.SubscriptionsCurrent)
	}
}

func TestTopicMetricsReconcileSubscriptionCountsMarksZeroKnown(t *testing.T) {
	c := New(nil)

	c.ReconcileTopicSubscriptionCounts(map[string]int64{"topic-1": 0})

	current, ok := c.GetTopicSubscriptionsCurrentKnown("topic-1")
	if !ok {
		t.Fatal("topic-1 current subscriptions unknown, want known zero")
	}
	if current != 0 {
		t.Fatalf("topic-1 current subscriptions = %d, want 0", current)
	}
	if got := c.GetTopicLastUpdated("topic-1"); got == 0 {
		t.Fatal("topic-1 last updated = 0, want reconciliation timestamp")
	}
}

type recordingStore struct {
	rates []recordedMetric
	raw   []recordedMetric
}

type recordedMetric struct {
	scope string
	name  string
	value float64
}

func newRecordingStore() *recordingStore {
	return &recordingStore{}
}

func (s *recordingStore) SaveRawMetric(_ context.Context, _ int64, queueID, metricName string, value float64, _ string) error {
	s.raw = append(s.raw, recordedMetric{scope: queueID, name: metricName, value: value})
	return nil
}

func (s *recordingStore) SaveRateSnapshot(_ context.Context, _ int64, queueID, metricName string, ratePerSecond float64, _ int) error {
	s.rates = append(s.rates, recordedMetric{scope: queueID, name: metricName, value: ratePerSecond})
	return nil
}

func (s *recordingStore) SaveQueueStats(context.Context, int64, string, int64, int64, int64, float64, float64) error {
	return nil
}

func (s *recordingStore) UpdateInFlightCount(context.Context, string, int64) error { return nil }
func (s *recordingStore) Aggregate1m(context.Context, int64, int64) error          { return nil }
func (s *recordingStore) Aggregate1h(context.Context, int64, int64) error          { return nil }
func (s *recordingStore) Aggregate1d(context.Context, int64, int64) error          { return nil }
func (s *recordingStore) CleanupOldMetrics(context.Context, int64, int64, int64, int64, int64) error {
	return nil
}
func (s *recordingStore) GetMetrics(context.Context, string, string, int64, int64, string) ([]DataPoint, error) {
	return nil, nil
}
func (s *recordingStore) GetLatestRates(context.Context, string) (map[string]float64, error) {
	return nil, nil
}
func (s *recordingStore) GetQueueStats(context.Context, string, int64, int64) ([]QueueStatsPoint, error) {
	return nil, nil
}

func (s *recordingStore) assertRate(t *testing.T, scope, name string, value float64) {
	t.Helper()
	assertRecordedMetric(t, s.rates, scope, name, value)
}

func (s *recordingStore) assertRaw(t *testing.T, scope, name string, value float64) {
	t.Helper()
	assertRecordedMetric(t, s.raw, scope, name, value)
}

func (s *recordingStore) assertRawAbsent(t *testing.T, scope, name string) {
	t.Helper()

	for _, metric := range s.raw {
		if metric.scope == scope && metric.name == name {
			t.Fatalf("metric %s/%s unexpectedly recorded in %#v", scope, name, s.raw)
		}
	}
}

func assertRecordedMetric(t *testing.T, got []recordedMetric, scope, name string, value float64) {
	t.Helper()
	for _, metric := range got {
		if metric.scope == scope && metric.name == name && metric.value == value {
			return
		}
	}
	t.Fatalf("metric %s/%s = %v not recorded in %#v", scope, name, value, got)
}
