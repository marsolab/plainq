# Telemetry Dashboards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add first-class topic telemetry in the backend and render queue/topic metrics dashboards in Houston.

**Architecture:** Extend the existing internal telemetry collector/store pipeline with topic-scoped metrics and expose topic endpoints parallel to queue metrics endpoints. Houston consumes those endpoints through the shared API client, mounts queue metrics in queue detail pages, and adds a pub/sub dashboard above the existing topic management workflow.

**Tech Stack:** Go, Chi, stdlib `testing`, Astro, React 19, TypeScript, Tailwind CSS v4, Shadcn-style local UI components, Recharts, Bun.

## Global Constraints

- Metrics remain internal-only; do not add external observability services.
- Topic metrics are first-class backend telemetry, not inferred from subscribed queue metrics.
- Queue metrics remain queue-scoped; topic metrics remain topic-scoped.
- Metrics recording is best effort and must not fail publish, subscribe, or unsubscribe requests.
- Houston must treat missing or disabled telemetry as a non-fatal empty state.
- Use TDD: write the failing test, run it red, implement minimally, run it green, then commit.
- Keep changes scoped to telemetry, queue/pub-sub HTTP instrumentation, metrics APIs, and Houston dashboard surfaces.
- Do not stage or modify unrelated files such as `.serena/project.yml`.

---

## File Structure

Create:

- `internal/server/service/telemetry/collector/topic_test.go` - collector tests for topic counters, gauges, and rates.
- `internal/server/metrics_handler_test.go` - handler tests for topic overview, topic detail, and topic rates.
- `internal/houston/ui/src/lib/metrics.ts` - shared metric formatting and chart transformation utilities.
- `internal/houston/ui/src/lib/metrics.test.ts` - Bun tests for metrics utilities.
- `internal/houston/ui/src/components/metrics/queue-detail-metrics.tsx` - queue detail metrics panel using the shared API client.
- `internal/houston/ui/src/components/metrics/topic-metrics-dashboard.tsx` - pub/sub page summary cards, topic table, and chart area.
- `internal/houston/ui/src/components/metrics/topic-rate-chart.tsx` - topic publish/delivery chart.
- `internal/houston/ui/src/pages/queue/[id].astro` - dynamic queue detail route for `/queue/{queueId}`.

Modify:

- `internal/server/service/telemetry/collector/collector.go` - add topic metric constants, structs, collector methods, and rate persistence.
- `internal/server/service/telemetry/collector/store.go` - add topic summary query helper.
- `internal/server/metrics_handler.go` - add topic response types and handlers; generalize store dependency to an interface.
- `internal/server/server.go` - wire topic metrics routes and inject the collector into the queue service.
- `internal/server/service/queue/service.go` - add topic metrics recorder interface and setter.
- `internal/server/service/queue/pubsub_http.go` - record topic metrics after successful pub/sub operations.
- `internal/server/service/queue/service_test.go` - extend `mockStorage` with configurable pub/sub funcs.
- `internal/houston/ui/package.json` - add `test` script using Bun.
- `internal/houston/ui/src/lib/types.ts` - add metrics API response types.
- `internal/houston/ui/src/lib/api-client.ts` - add metrics client methods.
- `internal/houston/ui/src/components/queue/queue-detail-overview.tsx` - mount queue metrics panel in the Metrics tab.
- `internal/houston/ui/src/components/pubsub/topic-list.tsx` - render topic dashboard and refresh it after topic operations.
- `internal/houston/ui/src/components/metrics/index.js` - export new metrics components.

---

### Task 1: Add Topic Metrics To The Collector

**Files:**
- Create: `internal/server/service/telemetry/collector/topic_test.go`
- Modify: `internal/server/service/telemetry/collector/collector.go`

**Interfaces:**
- Consumes: existing `collector.Store`, `collector.New`, `Collector.calculateRates`.
- Produces:
  - `const MetricTopicPublishRate = "plainq_topic_publish_rate"`
  - `const MetricTopicDeliveryRate = "plainq_topic_delivery_rate"`
  - `const MetricTopicMessagesPublishedTotal = "plainq_topic_messages_published_total"`
  - `const MetricTopicDeliveriesTotal = "plainq_topic_deliveries_total"`
  - `const MetricTopicSubscriptionsCurrent = "plainq_topic_subscriptions_current"`
  - `const MetricTopicSubscriptionsCreatedTotal = "plainq_topic_subscriptions_created_total"`
  - `const MetricTopicSubscriptionsDeletedTotal = "plainq_topic_subscriptions_deleted_total"`
  - `type TopicRates struct { PublishRate float64; DeliveryRate float64 }`
  - `type TopicCounters struct { MessagesPublished uint64; Deliveries uint64; SubscriptionsCreated uint64; SubscriptionsDeleted uint64 }`
  - `type TopicSystemCounters struct { MessagesPublished uint64; Deliveries uint64; SubscriptionsCurrent int64; SubscriptionsCreated uint64; SubscriptionsDeleted uint64 }`
  - `func (c *Collector) RecordTopicPublish(topicID string, messagesPublished, deliveries uint64)`
  - `func (c *Collector) RecordTopicSubscriptionCreated(topicID string, currentCount int64)`
  - `func (c *Collector) RecordTopicSubscriptionDeleted(topicID string, currentCount int64)`
  - `func (c *Collector) GetTopicRates(topicID string) TopicRates`
  - `func (c *Collector) GetTopicSystemRates() TopicRates`
  - `func (c *Collector) GetTopicCounters(topicID string) TopicCounters`
  - `func (c *Collector) GetTopicSystemCounters() TopicSystemCounters`
  - `func (c *Collector) GetTopicSubscriptionsCurrent(topicID string) int64`
  - `func (c *Collector) GetAllTopicIDs() []string`

- [ ] **Step 1: Write the failing collector tests**

Create `internal/server/service/telemetry/collector/topic_test.go`:

```go
package collector

import (
	"context"
	"testing"
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

func assertRecordedMetric(t *testing.T, got []recordedMetric, scope, name string, value float64) {
	t.Helper()
	for _, metric := range got {
		if metric.scope == scope && metric.name == name && metric.value == value {
			return
		}
	}
	t.Fatalf("metric %s/%s = %v not recorded in %#v", scope, name, value, got)
}
```

- [ ] **Step 2: Run the collector tests and verify RED**

Run:

```bash
go test ./internal/server/service/telemetry/collector -run 'TestTopicMetrics' -count=1
```

Expected: FAIL because topic metric constants and collector methods are undefined.

- [ ] **Step 3: Implement topic metric state and public methods**

In `internal/server/service/telemetry/collector/collector.go`, add topic constants near the existing metric name constants:

```go
const (
	MetricTopicPublishRate  = "plainq_topic_publish_rate"
	MetricTopicDeliveryRate = "plainq_topic_delivery_rate"
)

const (
	MetricTopicMessagesPublishedTotal     = "plainq_topic_messages_published_total"
	MetricTopicDeliveriesTotal            = "plainq_topic_deliveries_total"
	MetricTopicSubscriptionsCreatedTotal  = "plainq_topic_subscriptions_created_total"
	MetricTopicSubscriptionsDeletedTotal  = "plainq_topic_subscriptions_deleted_total"
)

const (
	MetricTopicSubscriptionsCurrent = "plainq_topic_subscriptions_current"
)
```

Add these types after `QueueMetrics`:

```go
type TopicMetrics struct {
	messagesPublished    atomic.Uint64
	deliveries           atomic.Uint64
	subscriptionsCreated atomic.Uint64
	subscriptionsDeleted atomic.Uint64
	subscriptionsCurrent atomic.Int64

	prevMessagesPublished uint64
	prevDeliveries        uint64

	publishRate  atomic.Uint64
	deliveryRate atomic.Uint64
}

type TopicSystemMetrics struct {
	totalMessagesPublished    atomic.Uint64
	totalDeliveries           atomic.Uint64
	totalSubscriptionsCreated atomic.Uint64
	totalSubscriptionsDeleted atomic.Uint64
	subscriptionsCurrent      atomic.Int64

	prevTotalMessagesPublished uint64
	prevTotalDeliveries        uint64

	systemPublishRate  atomic.Uint64
	systemDeliveryRate atomic.Uint64
}

type TopicRates struct {
	PublishRate  float64
	DeliveryRate float64
}

type TopicCounters struct {
	MessagesPublished    uint64
	Deliveries           uint64
	SubscriptionsCreated uint64
	SubscriptionsDeleted uint64
}

type TopicSystemCounters struct {
	MessagesPublished    uint64
	Deliveries           uint64
	SubscriptionsCurrent int64
	SubscriptionsCreated uint64
	SubscriptionsDeleted uint64
}
```

Extend `Collector`:

```go
	topicMetrics map[string]*TopicMetrics
	topicMu      sync.RWMutex

	topicSystem TopicSystemMetrics
```

Initialize the map in `New`:

```go
topicMetrics: make(map[string]*TopicMetrics),
```

Add topic methods after `getOrCreateQueueMetrics`:

```go
func (c *Collector) getOrCreateTopicMetrics(topicID string) *TopicMetrics {
	c.topicMu.RLock()
	m, ok := c.topicMetrics[topicID]
	c.topicMu.RUnlock()
	if ok {
		return m
	}

	c.topicMu.Lock()
	defer c.topicMu.Unlock()
	if m, ok = c.topicMetrics[topicID]; ok {
		return m
	}

	m = &TopicMetrics{}
	c.topicMetrics[topicID] = m
	return m
}

func (c *Collector) RecordTopicPublish(topicID string, messagesPublished, deliveries uint64) {
	m := c.getOrCreateTopicMetrics(topicID)
	m.messagesPublished.Add(messagesPublished)
	m.deliveries.Add(deliveries)
	c.topicSystem.totalMessagesPublished.Add(messagesPublished)
	c.topicSystem.totalDeliveries.Add(deliveries)
}

func (c *Collector) RecordTopicSubscriptionCreated(topicID string, currentCount int64) {
	m := c.getOrCreateTopicMetrics(topicID)
	m.subscriptionsCreated.Add(1)
	c.topicSystem.totalSubscriptionsCreated.Add(1)
	c.setTopicSubscriptionsCurrent(m, currentCount)
}

func (c *Collector) RecordTopicSubscriptionDeleted(topicID string, currentCount int64) {
	m := c.getOrCreateTopicMetrics(topicID)
	m.subscriptionsDeleted.Add(1)
	c.topicSystem.totalSubscriptionsDeleted.Add(1)
	c.setTopicSubscriptionsCurrent(m, currentCount)
}

func (c *Collector) setTopicSubscriptionsCurrent(m *TopicMetrics, currentCount int64) {
	if currentCount < 0 {
		return
	}
	m.subscriptionsCurrent.Store(currentCount)
	c.recalculateTopicSystemSubscriptionsCurrent()
}

func (c *Collector) recalculateTopicSystemSubscriptionsCurrent() {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	var total int64
	for _, m := range c.topicMetrics {
		total += m.subscriptionsCurrent.Load()
	}
	c.topicSystem.subscriptionsCurrent.Store(total)
}

func (c *Collector) GetTopicRates(topicID string) TopicRates {
	m := c.getOrCreateTopicMetrics(topicID)
	return TopicRates{
		PublishRate:  float64FromBits(m.publishRate.Load()),
		DeliveryRate: float64FromBits(m.deliveryRate.Load()),
	}
}

func (c *Collector) GetTopicSystemRates() TopicRates {
	return TopicRates{
		PublishRate:  float64FromBits(c.topicSystem.systemPublishRate.Load()),
		DeliveryRate: float64FromBits(c.topicSystem.systemDeliveryRate.Load()),
	}
}

func (c *Collector) GetTopicCounters(topicID string) TopicCounters {
	m := c.getOrCreateTopicMetrics(topicID)
	return TopicCounters{
		MessagesPublished:    m.messagesPublished.Load(),
		Deliveries:           m.deliveries.Load(),
		SubscriptionsCreated: m.subscriptionsCreated.Load(),
		SubscriptionsDeleted: m.subscriptionsDeleted.Load(),
	}
}

func (c *Collector) GetTopicSystemCounters() TopicSystemCounters {
	return TopicSystemCounters{
		MessagesPublished:    c.topicSystem.totalMessagesPublished.Load(),
		Deliveries:           c.topicSystem.totalDeliveries.Load(),
		SubscriptionsCurrent: c.topicSystem.subscriptionsCurrent.Load(),
		SubscriptionsCreated: c.topicSystem.totalSubscriptionsCreated.Load(),
		SubscriptionsDeleted: c.topicSystem.totalSubscriptionsDeleted.Load(),
	}
}

func (c *Collector) GetTopicSubscriptionsCurrent(topicID string) int64 {
	return c.getOrCreateTopicMetrics(topicID).subscriptionsCurrent.Load()
}

func (c *Collector) GetAllTopicIDs() []string {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	ids := make([]string, 0, len(c.topicMetrics))
	for id := range c.topicMetrics {
		ids = append(ids, id)
	}
	return ids
}
```

- [ ] **Step 4: Persist topic rates and raw metrics from `calculateRates`**

In `calculateRates`, after queue rate persistence and before system-wide queue rates, call:

```go
c.calculateTopicRates(ctx, now)
```

Add:

```go
func (c *Collector) calculateTopicRates(ctx context.Context, now int64) {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	for topicID, m := range c.topicMetrics {
		currentPublished := m.messagesPublished.Load()
		currentDeliveries := m.deliveries.Load()

		publishRate := float64(currentPublished - m.prevMessagesPublished)
		deliveryRate := float64(currentDeliveries - m.prevDeliveries)

		m.publishRate.Store(float64ToBits(publishRate))
		m.deliveryRate.Store(float64ToBits(deliveryRate))
		m.prevMessagesPublished = currentPublished
		m.prevDeliveries = currentDeliveries

		if c.store != nil {
			_ = c.store.SaveRateSnapshot(ctx, now, topicID, MetricTopicPublishRate, publishRate, 1) //nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRateSnapshot(ctx, now, topicID, MetricTopicDeliveryRate, deliveryRate, 1) //nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicMessagesPublishedTotal, float64(currentPublished), "") //nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicDeliveriesTotal, float64(currentDeliveries), "") //nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicSubscriptionsCurrent, float64(m.subscriptionsCurrent.Load()), "") //nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicSubscriptionsCreatedTotal, float64(m.subscriptionsCreated.Load()), "") //nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicSubscriptionsDeletedTotal, float64(m.subscriptionsDeleted.Load()), "") //nolint:errcheck // best-effort metrics persistence
		}
	}

	currentSystemPublished := c.topicSystem.totalMessagesPublished.Load()
	currentSystemDeliveries := c.topicSystem.totalDeliveries.Load()

	systemPublishRate := float64(currentSystemPublished - c.topicSystem.prevTotalMessagesPublished)
	systemDeliveryRate := float64(currentSystemDeliveries - c.topicSystem.prevTotalDeliveries)

	c.topicSystem.systemPublishRate.Store(float64ToBits(systemPublishRate))
	c.topicSystem.systemDeliveryRate.Store(float64ToBits(systemDeliveryRate))
	c.topicSystem.prevTotalMessagesPublished = currentSystemPublished
	c.topicSystem.prevTotalDeliveries = currentSystemDeliveries

	if c.store != nil {
		_ = c.store.SaveRateSnapshot(ctx, now, "", MetricTopicPublishRate, systemPublishRate, 1) //nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRateSnapshot(ctx, now, "", MetricTopicDeliveryRate, systemDeliveryRate, 1) //nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicMessagesPublishedTotal, float64(currentSystemPublished), "") //nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicDeliveriesTotal, float64(currentSystemDeliveries), "") //nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicSubscriptionsCurrent, float64(c.topicSystem.subscriptionsCurrent.Load()), "") //nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicSubscriptionsCreatedTotal, float64(c.topicSystem.totalSubscriptionsCreated.Load()), "") //nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicSubscriptionsDeletedTotal, float64(c.topicSystem.totalSubscriptionsDeleted.Load()), "") //nolint:errcheck // best-effort metrics persistence
	}
}
```

- [ ] **Step 5: Run collector tests green**

Run:

```bash
go test ./internal/server/service/telemetry/collector -run 'TestTopicMetrics' -count=1
```

Expected: PASS.

- [ ] **Step 6: Run full collector package tests**

Run:

```bash
go test ./internal/server/service/telemetry/collector -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Task 1**

```bash
git add internal/server/service/telemetry/collector/collector.go internal/server/service/telemetry/collector/topic_test.go
git commit -m "feat: add topic metrics collector state"
```

---

### Task 2: Instrument Pub/Sub HTTP Operations

**Files:**
- Modify: `internal/server/service/queue/service.go`
- Modify: `internal/server/service/queue/pubsub_http.go`
- Modify: `internal/server/service/queue/service_test.go`
- Create: `internal/server/service/queue/pubsub_http_test.go`

**Interfaces:**
- Consumes: Task 1 collector methods through a small queue package interface.
- Produces:
  - `type TopicMetricsRecorder interface`
  - `func (s *Service) SetTopicMetricsRecorder(recorder TopicMetricsRecorder)`
  - pub/sub handlers record only after successful storage operations.

- [ ] **Step 1: Write failing HTTP instrumentation tests**

Create `internal/server/service/queue/pubsub_http_test.go`:

```go
package queue

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/servekit/logkit"
)

func TestPublishTopicRecordsTopicMetricsAfterSuccess(t *testing.T) {
	storage := &mockStorage{
		publishFunc: func(_ context.Context, topicID string, input *PublishRequest) (*PublishResponse, error) {
			if topicID != "topic-1" {
				t.Fatalf("topicID = %q, want topic-1", topicID)
			}
			return &PublishResponse{TopicID: topicID, DeliveredCount: 5}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodPost, "/topics/topic-1/publish", strings.NewReader(`{"messages":[{"body":"aGVsbG8="},{"body":"d29ybGQ="}]}`))
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	if recorder.publishTopicID != "topic-1" {
		t.Fatalf("publishTopicID = %q, want topic-1", recorder.publishTopicID)
	}
	if recorder.messagesPublished != 2 {
		t.Fatalf("messagesPublished = %d, want 2", recorder.messagesPublished)
	}
	if recorder.deliveries != 5 {
		t.Fatalf("deliveries = %d, want 5", recorder.deliveries)
	}
}

func TestSubscribeTopicRecordsCurrentSubscriptionCount(t *testing.T) {
	storage := &mockStorage{
		subscribeFunc: func(context.Context, string, *SubscribeRequest) (*SubscribeResponse, error) {
			return &SubscribeResponse{SubscriptionID: "sub-1"}, nil
		},
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{
				TopicID: "topic-1",
				Subscriptions: []Subscription{
					{SubscriptionID: "sub-1"},
					{SubscriptionID: "sub-2"},
				},
			}}}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodPost, "/topics/topic-1/subscriptions", strings.NewReader(`{"queueId":"c5s8b4p9e8rg5u5fgq10"}`))
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if recorder.createdTopicID != "topic-1" {
		t.Fatalf("createdTopicID = %q, want topic-1", recorder.createdTopicID)
	}
	if recorder.createdCurrentCount != 2 {
		t.Fatalf("createdCurrentCount = %d, want 2", recorder.createdCurrentCount)
	}
}

func TestUnsubscribeTopicRecordsCurrentSubscriptionCount(t *testing.T) {
	storage := &mockStorage{
		unsubscribeFunc: func(context.Context, string, string) error {
			return nil
		},
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{
				TopicID: "topic-1",
				Subscriptions: []Subscription{
					{SubscriptionID: "sub-remaining"},
				},
			}}}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodDelete, "/topics/topic-1/subscriptions/sub-1", nil)
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if recorder.deletedTopicID != "topic-1" {
		t.Fatalf("deletedTopicID = %q, want topic-1", recorder.deletedTopicID)
	}
	if recorder.deletedCurrentCount != 1 {
		t.Fatalf("deletedCurrentCount = %d, want 1", recorder.deletedCurrentCount)
	}
}

var _ TopicMetricsRecorder = (*fakeTopicMetricsRecorder)(nil)

type fakeTopicMetricsRecorder struct {
	publishTopicID    string
	messagesPublished uint64
	deliveries        uint64

	createdTopicID       string
	createdCurrentCount  int64
	deletedTopicID       string
	deletedCurrentCount  int64
}

func (f *fakeTopicMetricsRecorder) RecordTopicPublish(topicID string, messagesPublished, deliveries uint64) {
	f.publishTopicID = topicID
	f.messagesPublished = messagesPublished
	f.deliveries = deliveries
}

func (f *fakeTopicMetricsRecorder) RecordTopicSubscriptionCreated(topicID string, currentCount int64) {
	f.createdTopicID = topicID
	f.createdCurrentCount = currentCount
}

func (f *fakeTopicMetricsRecorder) RecordTopicSubscriptionDeleted(topicID string, currentCount int64) {
	f.deletedTopicID = topicID
	f.deletedCurrentCount = currentCount
}
```

- [ ] **Step 2: Extend `mockStorage` with configurable pub/sub funcs**

In `internal/server/service/queue/service_test.go`, add fields:

```go
	listTopicsFunc   func(ctx context.Context) (*ListTopicsResponse, error)
	createTopicFunc  func(ctx context.Context, input *CreateTopicRequest) (*CreateTopicResponse, error)
	deleteTopicFunc  func(ctx context.Context, topicID string) error
	subscribeFunc    func(ctx context.Context, topicID string, input *SubscribeRequest) (*SubscribeResponse, error)
	unsubscribeFunc  func(ctx context.Context, topicID, subscriptionID string) error
	publishFunc      func(ctx context.Context, topicID string, input *PublishRequest) (*PublishResponse, error)
```

Replace the pub/sub methods with nil-safe dispatch:

```go
func (m *mockStorage) ListTopics(ctx context.Context) (*ListTopicsResponse, error) {
	if m.listTopicsFunc != nil {
		return m.listTopicsFunc(ctx)
	}
	return &ListTopicsResponse{}, nil
}

func (m *mockStorage) CreateTopic(ctx context.Context, input *CreateTopicRequest) (*CreateTopicResponse, error) {
	if m.createTopicFunc != nil {
		return m.createTopicFunc(ctx, input)
	}
	return &CreateTopicResponse{}, nil
}

func (m *mockStorage) DeleteTopic(ctx context.Context, topicID string) error {
	if m.deleteTopicFunc != nil {
		return m.deleteTopicFunc(ctx, topicID)
	}
	return nil
}

func (m *mockStorage) Subscribe(ctx context.Context, topicID string, input *SubscribeRequest) (*SubscribeResponse, error) {
	if m.subscribeFunc != nil {
		return m.subscribeFunc(ctx, topicID, input)
	}
	return &SubscribeResponse{}, nil
}

func (m *mockStorage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	if m.unsubscribeFunc != nil {
		return m.unsubscribeFunc(ctx, topicID, subscriptionID)
	}
	return nil
}

func (m *mockStorage) Publish(ctx context.Context, topicID string, input *PublishRequest) (*PublishResponse, error) {
	if m.publishFunc != nil {
		return m.publishFunc(ctx, topicID, input)
	}
	return &PublishResponse{}, nil
}
```

- [ ] **Step 3: Run pub/sub instrumentation tests and verify RED**

Run:

```bash
go test ./internal/server/service/queue -run 'Test.*TopicRecords' -count=1
```

Expected: FAIL because `TopicMetricsRecorder`, `SetTopicMetricsRecorder`, and handler recording calls are missing.

- [ ] **Step 4: Add recorder interface and setter**

In `internal/server/service/queue/service.go`, add after `Storage`:

```go
type TopicMetricsRecorder interface {
	RecordTopicPublish(topicID string, messagesPublished, deliveries uint64)
	RecordTopicSubscriptionCreated(topicID string, currentCount int64)
	RecordTopicSubscriptionDeleted(topicID string, currentCount int64)
}
```

Add a field to `Service`:

```go
	topicMetrics TopicMetricsRecorder
```

Add after `NewService`:

```go
func (s *Service) SetTopicMetricsRecorder(recorder TopicMetricsRecorder) {
	s.topicMetrics = recorder
}
```

- [ ] **Step 5: Record metrics after successful pub/sub operations**

In `internal/server/service/queue/pubsub_http.go`, add helper functions:

```go
func (s *Service) recordTopicSubscriptionCreated(ctx context.Context, topicID string) {
	if s.topicMetrics == nil {
		return
	}
	s.topicMetrics.RecordTopicSubscriptionCreated(topicID, s.topicSubscriptionCount(ctx, topicID))
}

func (s *Service) recordTopicSubscriptionDeleted(ctx context.Context, topicID string) {
	if s.topicMetrics == nil {
		return
	}
	s.topicMetrics.RecordTopicSubscriptionDeleted(topicID, s.topicSubscriptionCount(ctx, topicID))
}

func (s *Service) topicSubscriptionCount(ctx context.Context, topicID string) int64 {
	output, err := s.storage.ListTopics(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "count topic subscriptions for metrics",
			slog.String("topic_id", topicID),
			slog.String("error", err.Error()),
		)
		return -1
	}

	for _, topic := range output.Topics {
		if topic.TopicID == topicID {
			return int64(len(topic.Subscriptions))
		}
	}
	return -1
}
```

In `subscribeTopicHandler`, after successful storage call and before JSON response:

```go
topicID := chi.URLParam(r, "topicID")
output, err := s.storage.Subscribe(r.Context(), topicID, &input)
if err != nil {
	httpkit.ErrorHTTP(w, r, err)
	return
}
s.recordTopicSubscriptionCreated(r.Context(), topicID)
```

In `unsubscribeTopicHandler`, after successful storage call and before JSON response:

```go
topicID := chi.URLParam(r, "topicID")
if err := s.storage.Unsubscribe(r.Context(), topicID, chi.URLParam(r, "subscriptionID")); err != nil {
	httpkit.ErrorHTTP(w, r, err)
	return
}
s.recordTopicSubscriptionDeleted(r.Context(), topicID)
```

In `publishTopicHandler`, after successful storage call and before JSON response:

```go
topicID := chi.URLParam(r, "topicID")
output, err := s.storage.Publish(r.Context(), topicID, &input)
if err != nil {
	httpkit.ErrorHTTP(w, r, err)
	return
}
if s.topicMetrics != nil {
	s.topicMetrics.RecordTopicPublish(topicID, uint64(len(input.Messages)), uint64(output.DeliveredCount))
}
```

- [ ] **Step 6: Run pub/sub instrumentation tests green**

Run:

```bash
go test ./internal/server/service/queue -run 'Test.*TopicRecords' -count=1
```

Expected: PASS.

- [ ] **Step 7: Run queue package tests**

Run:

```bash
go test ./internal/server/service/queue -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit Task 2**

```bash
git add internal/server/service/queue/service.go internal/server/service/queue/pubsub_http.go internal/server/service/queue/service_test.go internal/server/service/queue/pubsub_http_test.go
git commit -m "feat: record topic metrics from pubsub operations"
```

---

### Task 3: Add Topic Metrics API Endpoints

**Files:**
- Create: `internal/server/metrics_handler_test.go`
- Modify: `internal/server/metrics_handler.go`
- Modify: `internal/server/service/telemetry/collector/store.go`
- Modify: `internal/server/server.go`

**Interfaces:**
- Consumes: Task 1 topic collector methods.
- Produces:
  - `type MetricsStore interface`
  - `type TopicMetricsSummary`
  - `func (s *SQLiteStore) GetTopicMetricsSummary(ctx context.Context, topicID string, from, to int64) (*TopicMetricsSummary, error)`
  - `func (h *MetricsHandler) GetTopicDashboardOverview(w http.ResponseWriter, r *http.Request)`
  - `func (h *MetricsHandler) GetTopicMetrics(w http.ResponseWriter, r *http.Request)`
  - `func (h *MetricsHandler) GetTopicRatesChart(w http.ResponseWriter, r *http.Request)`

- [ ] **Step 1: Write failing handler tests with a fake metrics store**

Create `internal/server/metrics_handler_test.go`:

```go
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
)

func TestGetTopicDashboardOverview(t *testing.T) {
	c := collector.New(nil)
	c.RecordTopicPublish("topic-1", 4, 8)
	c.RecordTopicSubscriptionCreated("topic-1", 2)
	c.RecordTopicPublish("topic-2", 1, 1)
	c.RecordTopicSubscriptionCreated("topic-2", 1)

	h := NewMetricsHandler(c, &fakeMetricsStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topics/overview", nil)
	rec := httptest.NewRecorder()

	h.GetTopicDashboardOverview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got TopicDashboardOverviewResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got.SystemMetrics.MessagesPublished != 5 {
		t.Fatalf("MessagesPublished = %d, want 5", got.SystemMetrics.MessagesPublished)
	}
	if got.SystemMetrics.Deliveries != 9 {
		t.Fatalf("Deliveries = %d, want 9", got.SystemMetrics.Deliveries)
	}
	if got.SystemMetrics.SubscriptionsCurrent != 3 {
		t.Fatalf("SubscriptionsCurrent = %d, want 3", got.SystemMetrics.SubscriptionsCurrent)
	}
	if len(got.TopicMetrics) != 2 {
		t.Fatalf("len(TopicMetrics) = %d, want 2", len(got.TopicMetrics))
	}
}

func TestGetTopicMetrics(t *testing.T) {
	c := collector.New(nil)
	c.RecordTopicPublish("topic-1", 4, 8)
	c.RecordTopicSubscriptionCreated("topic-1", 2)

	h := NewMetricsHandler(c, &fakeMetricsStore{
		topicSummary: &collector.TopicMetricsSummary{
			TopicID:           "topic-1",
			TotalPublished:    4,
			TotalDeliveries:   8,
			AvgPublishRate:    1.5,
			AvgDeliveryRate:   3,
			MaxPublishRate:    4,
			MaxDeliveryRate:   8,
			Subscriptions:     2,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topic/topic-1?range=1h", nil)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}", h.GetTopicMetrics)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got struct {
		*collector.TopicMetricsSummary
		CurrentPublishRate  float64 `json:"currentPublishRate"`
		CurrentDeliveryRate float64 `json:"currentDeliveryRate"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.TopicID != "topic-1" {
		t.Fatalf("TopicID = %q, want topic-1", got.TopicID)
	}
	if got.CurrentPublishRate != 0 {
		t.Fatalf("CurrentPublishRate = %v, want 0 before rate worker tick", got.CurrentPublishRate)
	}
}

func TestGetTopicRatesChart(t *testing.T) {
	c := collector.New(nil)
	h := NewMetricsHandler(c, &fakeMetricsStore{
		rateHistory: map[string][]collector.DataPoint{
			collector.MetricTopicPublishRate:  {{Timestamp: 1000, Value: 2}},
			collector.MetricTopicDeliveryRate: {{Timestamp: 1000, Value: 4}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topic/topic-1/rates?range=1h", nil)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}/rates", h.GetTopicRatesChart)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got MultiMetricsChartResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Metrics) != 2 {
		t.Fatalf("len(Metrics) = %d, want 2", len(got.Metrics))
	}
}

```

Add the fake store in the same file:

```go
type fakeMetricsStore struct {
	topicSummary *collector.TopicMetricsSummary
	rateHistory  map[string][]collector.DataPoint
}

func (s *fakeMetricsStore) GetMetrics(context.Context, string, string, int64, int64, string) ([]collector.DataPoint, error) {
	return nil, nil
}
func (s *fakeMetricsStore) GetRateHistory(_ context.Context, metricName, _ string, _, _ int64) ([]collector.DataPoint, error) {
	return s.rateHistory[metricName], nil
}
func (s *fakeMetricsStore) GetMetricsSummary(context.Context, string, int64, int64) (*collector.MetricsSummary, error) {
	return &collector.MetricsSummary{}, nil
}
func (s *fakeMetricsStore) GetTopicMetricsSummary(context.Context, string, int64, int64) (*collector.TopicMetricsSummary, error) {
	return s.topicSummary, nil
}
```

- [ ] **Step 2: Run handler tests and verify RED**

Run:

```bash
go test ./internal/server -run 'TestGetTopic' -count=1
```

Expected: FAIL because the store interface, topic summary type, and handlers do not exist.

- [ ] **Step 3: Add topic summary query type and method**

In `internal/server/service/telemetry/collector/store.go`, add after `MetricsSummary`:

```go
type TopicMetricsSummary struct {
	TopicID         string  `json:"topicId"`
	From            int64   `json:"from"`
	To              int64   `json:"to"`
	TotalPublished  int64   `json:"totalPublished"`
	TotalDeliveries int64   `json:"totalDeliveries"`
	AvgPublishRate  float64 `json:"avgPublishRate"`
	AvgDeliveryRate float64 `json:"avgDeliveryRate"`
	MaxPublishRate  float64 `json:"maxPublishRate"`
	MaxDeliveryRate  float64 `json:"maxDeliveryRate"`
	Subscriptions   int64   `json:"subscriptions"`
}

func (s *SQLiteStore) GetTopicMetricsSummary(ctx context.Context, topicID string, from, to int64) (*TopicMetricsSummary, error) {
	summary := &TopicMetricsSummary{TopicID: topicID, From: from, To: to}

	totalQuery := `SELECT COALESCE(MAX(metric_value) - MIN(metric_value), 0)
		FROM metrics_raw
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	_ = s.db.QueryRowContext(ctx, totalQuery, MetricTopicMessagesPublishedTotal, topicID, from, to).Scan(&summary.TotalPublished) //nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, totalQuery, MetricTopicDeliveriesTotal, topicID, from, to).Scan(&summary.TotalDeliveries) //nolint:errcheck // best-effort metrics summary

	avgRateQuery := `SELECT COALESCE(AVG(rate_per_second), 0)
		FROM rate_snapshots
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	_ = s.db.QueryRowContext(ctx, avgRateQuery, MetricTopicPublishRate, topicID, from, to).Scan(&summary.AvgPublishRate) //nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, avgRateQuery, MetricTopicDeliveryRate, topicID, from, to).Scan(&summary.AvgDeliveryRate) //nolint:errcheck // best-effort metrics summary

	maxRateQuery := `SELECT COALESCE(MAX(rate_per_second), 0)
		FROM rate_snapshots
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricTopicPublishRate, topicID, from, to).Scan(&summary.MaxPublishRate) //nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricTopicDeliveryRate, topicID, from, to).Scan(&summary.MaxDeliveryRate) //nolint:errcheck // best-effort metrics summary

	latestSubscriptions, err := s.GetLatestMetricValue(ctx, MetricTopicSubscriptionsCurrent, topicID)
	if err != nil {
		return nil, fmt.Errorf("topic subscriptions summary: %w", err)
	}
	summary.Subscriptions = int64(latestSubscriptions.Value)

	return summary, nil
}
```

- [ ] **Step 4: Generalize `MetricsHandler` store dependency and add response types**

In `internal/server/metrics_handler.go`, replace the concrete store field:

```go
type MetricsStore interface {
	GetMetrics(ctx context.Context, metricName, queueID string, from, to int64, resolution string) ([]collector.DataPoint, error)
	GetRateHistory(ctx context.Context, metricName, queueID string, from, to int64) ([]collector.DataPoint, error)
	GetMetricsSummary(ctx context.Context, queueID string, from, to int64) (*collector.MetricsSummary, error)
	GetTopicMetricsSummary(ctx context.Context, topicID string, from, to int64) (*collector.TopicMetricsSummary, error)
}

type MetricsHandler struct {
	collector *collector.Collector
	store     MetricsStore
}

func NewMetricsHandler(c *collector.Collector, s MetricsStore) *MetricsHandler {
	return &MetricsHandler{collector: c, store: s}
}
```

Add response types after `QueueMetricsData`:

```go
type TopicDashboardOverviewResponse struct {
	SystemMetrics TopicSystemMetricsData `json:"systemMetrics"`
	TopicMetrics  []TopicMetricsData     `json:"topicMetrics"`
	TimeRange     TimeRange              `json:"timeRange"`
	UpdatedAt     int64                  `json:"updatedAt"`
}

type TopicSystemMetricsData struct {
	PublishRate          float64 `json:"publishRate"`
	DeliveryRate         float64 `json:"deliveryRate"`
	MessagesPublished    uint64  `json:"messagesPublished"`
	Deliveries           uint64  `json:"deliveries"`
	SubscriptionsCurrent int64   `json:"subscriptionsCurrent"`
	SubscriptionsCreated uint64  `json:"subscriptionsCreated"`
	SubscriptionsDeleted uint64  `json:"subscriptionsDeleted"`
}

type TopicMetricsData struct {
	TopicID              string  `json:"topicId"`
	PublishRate          float64 `json:"publishRate"`
	DeliveryRate         float64 `json:"deliveryRate"`
	MessagesPublished    uint64  `json:"messagesPublished"`
	Deliveries           uint64  `json:"deliveries"`
	SubscriptionsCurrent int64   `json:"subscriptionsCurrent"`
	SubscriptionsCreated uint64  `json:"subscriptionsCreated"`
	SubscriptionsDeleted uint64  `json:"subscriptionsDeleted"`
}
```

Add `TopicID string json:"topicId,omitempty"` to `MetricsChartResponse`.

- [ ] **Step 5: Add topic handler methods**

In `internal/server/metrics_handler.go`, add:

```go
func (h *MetricsHandler) GetTopicDashboardOverview(w http.ResponseWriter, r *http.Request) {
	systemRates := h.collector.GetTopicSystemRates()
	systemCounters := h.collector.GetTopicSystemCounters()

	topicIDs := h.collector.GetAllTopicIDs()
	topicMetrics := make([]TopicMetricsData, 0, len(topicIDs))
	for _, topicID := range topicIDs {
		rates := h.collector.GetTopicRates(topicID)
		counters := h.collector.GetTopicCounters(topicID)
		topicMetrics = append(topicMetrics, TopicMetricsData{
			TopicID:              topicID,
			PublishRate:          rates.PublishRate,
			DeliveryRate:         rates.DeliveryRate,
			MessagesPublished:    counters.MessagesPublished,
			Deliveries:           counters.Deliveries,
			SubscriptionsCurrent: h.collector.GetTopicSubscriptionsCurrent(topicID),
			SubscriptionsCreated: counters.SubscriptionsCreated,
			SubscriptionsDeleted: counters.SubscriptionsDeleted,
		})
	}

	now := time.Now().UnixMilli()
	resp := TopicDashboardOverviewResponse{
		SystemMetrics: TopicSystemMetricsData{
			PublishRate:          systemRates.PublishRate,
			DeliveryRate:         systemRates.DeliveryRate,
			MessagesPublished:    systemCounters.MessagesPublished,
			Deliveries:           systemCounters.Deliveries,
			SubscriptionsCurrent: systemCounters.SubscriptionsCurrent,
			SubscriptionsCreated: systemCounters.SubscriptionsCreated,
			SubscriptionsDeleted: systemCounters.SubscriptionsDeleted,
		},
		TopicMetrics: topicMetrics,
		TimeRange:    TimeRange{From: time.Now().Add(-1 * time.Hour).UnixMilli(), To: now},
		UpdatedAt:    now,
	}

	httpkit.JSON(w, r, resp)
}

func (h *MetricsHandler) GetTopicMetrics(w http.ResponseWriter, r *http.Request) {
	topicID := chi.URLParam(r, "id")
	tr := parseRequestTimeRange(w, r)
	if tr == nil {
		return
	}

	summary, err := h.store.GetTopicMetricsSummary(r.Context(), topicID, tr.From, tr.To)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	rates := h.collector.GetTopicRates(topicID)
	resp := struct {
		*collector.TopicMetricsSummary
		CurrentPublishRate  float64   `json:"currentPublishRate"`
		CurrentDeliveryRate float64   `json:"currentDeliveryRate"`
		TimeRange           TimeRange `json:"timeRange"`
	}{
		TopicMetricsSummary: summary,
		CurrentPublishRate:  rates.PublishRate,
		CurrentDeliveryRate: rates.DeliveryRate,
		TimeRange:           *tr,
	}

	httpkit.JSON(w, r, resp)
}

func (h *MetricsHandler) GetTopicRatesChart(w http.ResponseWriter, r *http.Request) {
	topicID := chi.URLParam(r, "id")
	tr := parseRequestTimeRange(w, r)
	if tr == nil {
		return
	}

	publishRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricTopicPublishRate, topicID, tr.From, tr.To) //nolint:errcheck // best-effort metrics retrieval
	deliveryRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricTopicDeliveryRate, topicID, tr.From, tr.To) //nolint:errcheck // best-effort metrics retrieval

	resp := MultiMetricsChartResponse{
		Metrics: []MetricsChartResponse{
			{MetricName: collector.MetricTopicPublishRate, TopicID: topicID, DataPoints: publishRates},
			{MetricName: collector.MetricTopicDeliveryRate, TopicID: topicID, DataPoints: deliveryRates},
		},
		TimeRange: *tr,
	}

	httpkit.JSON(w, r, resp)
}
```

Extract the repeated time-range parsing used by queue/topic handlers into:

```go
func parseRequestTimeRange(w http.ResponseWriter, r *http.Request) *TimeRange {
	preset := r.URL.Query().Get("range")
	var customFrom, customTo int64
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		v, err := strconv.ParseInt(fromStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'from' parameter"}`, http.StatusBadRequest)
			return nil
		}
		customFrom = v
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		v, err := strconv.ParseInt(toStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'to' parameter"}`, http.StatusBadRequest)
			return nil
		}
		customTo = v
	}
	tr := ParseTimeRange(preset, customFrom, customTo)
	return &tr
}
```

Use this helper in the new topic handlers first. Refactoring existing queue handlers to use it is optional and should happen only if it keeps the diff small.

- [ ] **Step 6: Add topic routes and collector injection**

In `internal/server/server.go`, after the collector is created:

```go
pq.queue.SetTopicMetricsRecorder(pq.metricsCollector)
```

In the `/metrics` route block, add:

```go
metrics.Get("/topics/overview", pq.metricsHandler.GetTopicDashboardOverview)
metrics.Route("/topic/{id}", func(topicMetrics chi.Router) {
	topicMetrics.Get("/", pq.metricsHandler.GetTopicMetrics)
	topicMetrics.Get("/rates", pq.metricsHandler.GetTopicRatesChart)
})
```

In `GetAvailableMetrics`, append topic metrics:

```go
{collector.MetricTopicPublishRate, metricTypeGauge, "Messages published to a topic per second"},
{collector.MetricTopicDeliveryRate, metricTypeGauge, "Topic message deliveries per second"},
{collector.MetricTopicMessagesPublishedTotal, metricTypeCounter, "Total messages published to a topic"},
{collector.MetricTopicDeliveriesTotal, metricTypeCounter, "Total topic message deliveries"},
{collector.MetricTopicSubscriptionsCurrent, metricTypeGauge, "Current subscriptions on a topic"},
{collector.MetricTopicSubscriptionsCreatedTotal, metricTypeCounter, "Total topic subscriptions created"},
{collector.MetricTopicSubscriptionsDeletedTotal, metricTypeCounter, "Total topic subscriptions deleted"},
```

- [ ] **Step 7: Run handler tests green**

Run:

```bash
go test ./internal/server -run 'TestGetTopic' -count=1
```

Expected: PASS.

- [ ] **Step 8: Run server and telemetry package tests**

Run:

```bash
go test ./internal/server ./internal/server/service/telemetry/collector -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit Task 3**

```bash
git add internal/server/metrics_handler.go internal/server/metrics_handler_test.go internal/server/server.go internal/server/service/telemetry/collector/store.go
git commit -m "feat: expose topic metrics endpoints"
```

---

### Task 4: Add Houston Metrics Types, API Methods, And Utilities

**Files:**
- Modify: `internal/houston/ui/package.json`
- Modify: `internal/houston/ui/src/lib/types.ts`
- Modify: `internal/houston/ui/src/lib/api-client.ts`
- Create: `internal/houston/ui/src/lib/metrics.ts`
- Create: `internal/houston/ui/src/lib/metrics.test.ts`

**Interfaces:**
- Consumes: Task 3 API response shapes.
- Produces:
  - `api.metrics.overview()`
  - `api.metrics.queue(id, range)`
  - `api.metrics.queueRates(id, range)`
  - `api.metrics.queueInFlight(id, range)`
  - `api.metrics.topicOverview()`
  - `api.metrics.topic(id, range)`
  - `api.metrics.topicRates(id, range)`
  - formatting and chart transform helpers.

- [ ] **Step 1: Add failing Bun tests for metrics utilities**

Create `internal/houston/ui/src/lib/metrics.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import {
  formatMetricNumber,
  formatMetricRate,
  isTelemetryUnavailableError,
  transformRateMetrics,
} from "./metrics";

describe("formatMetricNumber", () => {
  test("formats compact values", () => {
    expect(formatMetricNumber(0)).toBe("0");
    expect(formatMetricNumber(999)).toBe("999");
    expect(formatMetricNumber(1200)).toBe("1.20K");
    expect(formatMetricNumber(2_500_000)).toBe("2.50M");
  });
});

describe("formatMetricRate", () => {
  test("formats rates with two decimals", () => {
    expect(formatMetricRate(0)).toBe("0.00");
    expect(formatMetricRate(12.345)).toBe("12.35");
    expect(formatMetricRate(1500)).toBe("1.50K");
  });
});

describe("transformRateMetrics", () => {
  test("merges metric series by timestamp", () => {
    const rows = transformRateMetrics([
      {
        metricName: "plainq_topic_publish_rate",
        dataPoints: [{ timestamp: 1000, value: 2 }],
      },
      {
        metricName: "plainq_topic_delivery_rate",
        dataPoints: [{ timestamp: 1000, value: 4 }],
      },
    ]);

    expect(rows).toEqual([
      {
        timestamp: 1000,
        publish: 2,
        delivery: 4,
      },
    ]);
  });
});

describe("isTelemetryUnavailableError", () => {
  test("matches disabled telemetry errors", () => {
    expect(isTelemetryUnavailableError(new Error("404: not found"))).toBe(true);
    expect(isTelemetryUnavailableError(new Error("503: telemetry unavailable"))).toBe(true);
    expect(isTelemetryUnavailableError(new Error("network failed"))).toBe(false);
  });
});
```

- [ ] **Step 2: Add test script and verify RED**

In `internal/houston/ui/package.json`, add:

```json
"test": "bun test"
```

Run:

```bash
cd internal/houston/ui
bun test src/lib/metrics.test.ts
```

Expected: FAIL because `src/lib/metrics.ts` does not exist.

- [ ] **Step 3: Add metrics response types**

In `internal/houston/ui/src/lib/types.ts`, add:

```ts
export interface TimeRange {
  from: number;
  to: number;
}

export interface MetricDataPoint {
  timestamp: number;
  value: number;
  min?: number;
  max?: number;
  avg?: number;
  sum?: number;
  count?: number;
}

export interface MetricsChartResponse {
  metricName: string;
  queueId?: string;
  topicId?: string;
  timeRange?: TimeRange;
  resolution?: string;
  dataPoints: MetricDataPoint[];
}

export interface MultiMetricsChartResponse {
  metrics: MetricsChartResponse[];
  timeRange: TimeRange;
}

export interface QueueMetricsSummary {
  queueId: string;
  totalSent: number;
  totalReceived: number;
  totalDeleted: number;
  avgSendRate: number;
  avgReceiveRate: number;
  avgDeleteRate: number;
  maxSendRate: number;
  maxReceiveRate: number;
  maxDeleteRate: number;
  currentInFlight: number;
  currentSendRate: number;
  currentReceiveRate: number;
  currentDeleteRate: number;
  timeRange: TimeRange;
}

export interface TopicMetricsSummary {
  topicId: string;
  totalPublished: number;
  totalDeliveries: number;
  avgPublishRate: number;
  avgDeliveryRate: number;
  maxPublishRate: number;
  maxDeliveryRate: number;
  subscriptions: number;
  currentPublishRate: number;
  currentDeliveryRate: number;
  timeRange: TimeRange;
}

export interface TopicMetricsRow {
  topicId: string;
  publishRate: number;
  deliveryRate: number;
  messagesPublished: number;
  deliveries: number;
  subscriptionsCurrent: number;
  subscriptionsCreated: number;
  subscriptionsDeleted: number;
}

export interface TopicMetricsOverview {
  systemMetrics: {
    publishRate: number;
    deliveryRate: number;
    messagesPublished: number;
    deliveries: number;
    subscriptionsCurrent: number;
    subscriptionsCreated: number;
    subscriptionsDeleted: number;
  };
  topicMetrics: TopicMetricsRow[];
  timeRange: TimeRange;
  updatedAt: number;
}
```

- [ ] **Step 4: Add metrics utilities**

Create `internal/houston/ui/src/lib/metrics.ts`:

```ts
import type { MetricsChartResponse } from "./types";

export interface RateChartRow {
  timestamp: number;
  send?: number;
  receive?: number;
  delete?: number;
  publish?: number;
  delivery?: number;
}

const RATE_KEYS: Record<string, keyof RateChartRow> = {
  plainq_send_rate: "send",
  plainq_receive_rate: "receive",
  plainq_delete_rate: "delete",
  plainq_topic_publish_rate: "publish",
  plainq_topic_delivery_rate: "delivery",
};

export function transformRateMetrics(metrics: Pick<MetricsChartResponse, "metricName" | "dataPoints">[]): RateChartRow[] {
  const rows = new Map<number, RateChartRow>();

  for (const metric of metrics) {
    const key = RATE_KEYS[metric.metricName] ?? metric.metricName.replace(/^plainq_/, "").replace(/_rate$/, "");
    for (const point of metric.dataPoints ?? []) {
      const existing = rows.get(point.timestamp) ?? { timestamp: point.timestamp };
      (existing as Record<string, number>)[key] = point.value;
      rows.set(point.timestamp, existing);
    }
  }

  return Array.from(rows.values()).sort((a, b) => a.timestamp - b.timestamp);
}

export function formatMetricNumber(value?: number | null): string {
  if (value === undefined || value === null) return "0";
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)}K`;
  return String(value);
}

export function formatMetricRate(value?: number | null): string {
  if (value === undefined || value === null) return "0.00";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)}K`;
  return value.toFixed(2);
}

export function formatMetricTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function isTelemetryUnavailableError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.message.includes("404") || error.message.includes("503");
}
```

- [ ] **Step 5: Add shared API client metrics methods**

In `internal/houston/ui/src/lib/api-client.ts`, preserve HTTP status codes in thrown API errors so dashboard components can distinguish disabled telemetry from other failures. Replace the final error throw in `apiFetch` with:

```ts
throw new Error(`${response.status}: ${error.message || response.statusText}`);
```

Import metric types and add:

```ts
metrics: {
  overview: () => apiFetch<DashboardOverviewResponse>("/metrics/overview"),
  queue: (id: string, range = "1h") =>
    apiFetch<QueueMetricsSummary>(`/metrics/queue/${id}?range=${range}`),
  queueRates: (id: string, range = "1h") =>
    apiFetch<MultiMetricsChartResponse>(`/metrics/queue/${id}/rates?range=${range}`),
  queueInFlight: (id: string, range = "1h") =>
    apiFetch<InFlightMetricsResponse>(`/metrics/queue/${id}/inflight?range=${range}`),
  topicOverview: () => apiFetch<TopicMetricsOverview>("/metrics/topics/overview"),
  topic: (id: string, range = "1h") =>
    apiFetch<TopicMetricsSummary>(`/metrics/topic/${id}?range=${range}`),
  topicRates: (id: string, range = "1h") =>
    apiFetch<MultiMetricsChartResponse>(`/metrics/topic/${id}/rates?range=${range}`),
},
```

Add any missing exported types from `types.ts`:

```ts
export interface InFlightMetricsResponse {
  current: number;
  queueId?: string;
  history: MetricDataPoint[];
  timeRange: TimeRange;
}

export interface DashboardOverviewResponse {
  systemMetrics: Record<string, number>;
  queueMetrics: Array<Record<string, string | number>>;
  timeRange: TimeRange;
  updatedAt: number;
}
```

- [ ] **Step 6: Run frontend utility tests green**

Run:

```bash
cd internal/houston/ui
bun test src/lib/metrics.test.ts
```

Expected: PASS.

- [ ] **Step 7: Run Houston build**

Run:

```bash
cd internal/houston/ui
bun run build
```

Expected: PASS.

- [ ] **Step 8: Commit Task 4**

```bash
git add internal/houston/ui/package.json internal/houston/ui/src/lib/types.ts internal/houston/ui/src/lib/api-client.ts internal/houston/ui/src/lib/metrics.ts internal/houston/ui/src/lib/metrics.test.ts
git commit -m "feat: add houston metrics client utilities"
```

---

### Task 5: Mount Queue Metrics On Queue Detail Pages

**Files:**
- Create: `internal/houston/ui/src/pages/queue/[id].astro`
- Create: `internal/houston/ui/src/components/metrics/queue-detail-metrics.tsx`
- Modify: `internal/houston/ui/src/components/queue/queue-detail-overview.tsx`
- Modify: `internal/houston/ui/src/components/metrics/index.js`

**Interfaces:**
- Consumes: Task 4 `api.metrics.queue`, `api.metrics.queueRates`, `api.metrics.queueInFlight`, and formatting helpers.
- Produces: Queue detail metrics tab with cards, throughput chart, in-flight chart, time range selection, refresh, empty state, and telemetry-disabled state.

- [ ] **Step 1: Create the dynamic queue route**

Create `internal/houston/ui/src/pages/queue/[id].astro`:

```astro
---
import Layout from "@/layouts/Layout.astro";
import { AppShell } from "@/components/layout/app-shell";
import { QueueDetailPage } from "@/components/queue/queue-detail-page";
---

<Layout title="Queue Details - PlainQ">
  <AppShell currentPath="/queue" title="Queue Details" client:load>
    <QueueDetailPage client:load />
  </AppShell>
</Layout>
```

- [ ] **Step 2: Add queue metrics component**

Create `internal/houston/ui/src/components/metrics/queue-detail-metrics.tsx`:

```tsx
import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/lib/api-client";
import type { InFlightMetricsResponse, MultiMetricsChartResponse, QueueMetricsSummary } from "@/lib/types";
import { formatMetricNumber, formatMetricRate, formatMetricTimestamp, isTelemetryUnavailableError, transformRateMetrics } from "@/lib/metrics";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";

const TIME_RANGES = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

interface QueueDetailMetricsProps {
  queueId: string;
  queueName: string;
}

export function QueueDetailMetrics({ queueId, queueName }: QueueDetailMetricsProps) {
  const [timeRange, setTimeRange] = useState("1h");
  const [summary, setSummary] = useState<QueueMetricsSummary | null>(null);
  const [rates, setRates] = useState<MultiMetricsChartResponse | null>(null);
  const [inFlight, setInFlight] = useState<InFlightMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [summaryData, rateData, inFlightData] = await Promise.all([
        api.metrics.queue(queueId, timeRange),
        api.metrics.queueRates(queueId, timeRange),
        api.metrics.queueInFlight(queueId, timeRange),
      ]);
      setSummary(summaryData);
      setRates(rateData);
      setInFlight(inFlightData);
      setUnavailable(false);
    } catch (err) {
      if (isTelemetryUnavailableError(err)) {
        setUnavailable(true);
      } else {
        setError(err instanceof Error ? err.message : "Failed to load queue metrics");
      }
    } finally {
      setLoading(false);
    }
  }, [queueId, timeRange]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const rateRows = useMemo(() => transformRateMetrics(rates?.metrics ?? []), [rates]);
  const inFlightRows = inFlight?.history ?? [];

  if (loading && !summary) {
    return <QueueMetricsSkeleton />;
  }

  if (unavailable) {
    return <MetricsEmptyState title="Telemetry is not enabled" body="Queue operations still work. Start PlainQ with telemetry storage configured to collect dashboard data." />;
  }

  if (error) {
    return <MetricsEmptyState title="Metrics could not be loaded" body={error} />;
  }

  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold">Queue metrics</h3>
          <p className="text-sm text-muted-foreground">{queueName}</p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TIME_RANGES.map((range) => (
                <SelectItem key={range.value} value={range.value}>{range.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="icon" onClick={refresh} aria-label="Refresh metrics">
            <RefreshCw className="size-4" />
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Send rate" value={formatMetricRate(summary?.currentSendRate)} unit="msg/s" />
        <MetricTile label="Receive rate" value={formatMetricRate(summary?.currentReceiveRate)} unit="msg/s" />
        <MetricTile label="Delete rate" value={formatMetricRate(summary?.currentDeleteRate)} unit="msg/s" />
        <MetricTile label="In flight" value={formatMetricNumber(summary?.currentInFlight)} unit="msgs" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Throughput</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            {rateRows.length === 0 ? <ChartEmptyState /> : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rateRows}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" tickFormatter={formatMetricTimestamp} />
                  <YAxis />
                  <Tooltip labelFormatter={(value) => new Date(Number(value)).toLocaleString()} />
                  <Line type="monotone" dataKey="send" stroke="#2563eb" dot={false} name="Send" />
                  <Line type="monotone" dataKey="receive" stroke="#16a34a" dot={false} name="Receive" />
                  <Line type="monotone" dataKey="delete" stroke="#9333ea" dot={false} name="Delete" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">In-flight messages</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            {inFlightRows.length === 0 ? <ChartEmptyState /> : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={inFlightRows}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" tickFormatter={formatMetricTimestamp} />
                  <YAxis />
                  <Tooltip labelFormatter={(value) => new Date(Number(value)).toLocaleString()} />
                  <Area type="monotone" dataKey="value" stroke="#2563eb" fill="#bfdbfe" name="In flight" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function MetricTile({ label, value, unit }: { label: string; value: string; unit: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-semibold">{value}</span>
          <span className="text-xs text-muted-foreground">{unit}</span>
        </div>
      </CardContent>
    </Card>
  );
}

function QueueMetricsSkeleton() {
  return (
    <div className="mt-4 space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-72" />
    </div>
  );
}

function MetricsEmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="mt-4 flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed text-center">
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">{body}</p>
    </div>
  );
}

function ChartEmptyState() {
  return <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No data for this range</div>;
}
```

- [ ] **Step 3: Mount queue metrics in the Metrics tab**

In `internal/houston/ui/src/components/queue/queue-detail-overview.tsx`, import:

```tsx
import { QueueDetailMetrics } from "@/components/metrics/queue-detail-metrics";
```

Replace the Metrics tab placeholder with:

```tsx
<TabsContent value="metrics">
  <QueueDetailMetrics queueId={queue.queueId} queueName={queue.queueName} />
</TabsContent>
```

In `internal/houston/ui/src/components/metrics/index.js`, add:

```js
export { QueueDetailMetrics } from "./queue-detail-metrics";
```

- [ ] **Step 4: Build Houston**

Run:

```bash
cd internal/houston/ui
bun run build
```

Expected: PASS. If path aliases fail for Bun tests later, keep Astro build authoritative for component integration.

- [ ] **Step 5: Commit Task 5**

```bash
git add internal/houston/ui/src/pages/queue/[id].astro internal/houston/ui/src/components/metrics/queue-detail-metrics.tsx internal/houston/ui/src/components/queue/queue-detail-overview.tsx internal/houston/ui/src/components/metrics/index.js
git commit -m "feat: show queue metrics in houston"
```

---

### Task 6: Add Pub/Sub Topic Metrics Dashboard

**Files:**
- Create: `internal/houston/ui/src/components/metrics/topic-rate-chart.tsx`
- Create: `internal/houston/ui/src/components/metrics/topic-metrics-dashboard.tsx`
- Modify: `internal/houston/ui/src/components/pubsub/topic-list.tsx`
- Modify: `internal/houston/ui/src/components/metrics/index.js`

**Interfaces:**
- Consumes: Task 4 `api.metrics.topicOverview`, `api.metrics.topicRates`, formatting helpers, and `Topic[]`.
- Produces: Pub/Sub page dashboard with summary cards, topic metrics table, and per-topic publish/delivery chart.

- [ ] **Step 1: Add topic rate chart component**

Create `internal/houston/ui/src/components/metrics/topic-rate-chart.tsx`:

```tsx
import { useEffect, useMemo, useState } from "react";
import { Line, LineChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "@/lib/api-client";
import type { MultiMetricsChartResponse } from "@/lib/types";
import { formatMetricTimestamp, transformRateMetrics } from "@/lib/metrics";
import { Skeleton } from "@/components/ui/skeleton";

interface TopicRateChartProps {
  topicId: string;
  timeRange: string;
}

export function TopicRateChart({ topicId, timeRange }: TopicRateChartProps) {
  const [data, setData] = useState<MultiMetricsChartResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api.metrics.topicRates(topicId, timeRange)
      .then((response) => {
        if (!cancelled) setData(response);
      })
      .catch(() => {
        if (!cancelled) setData(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [topicId, timeRange]);

  const rows = useMemo(() => transformRateMetrics(data?.metrics ?? []), [data]);

  if (loading) return <Skeleton className="h-72" />;
  if (rows.length === 0) {
    return <div className="flex h-72 items-center justify-center text-sm text-muted-foreground">No topic metrics for this range</div>;
  }

  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="timestamp" tickFormatter={formatMetricTimestamp} />
          <YAxis />
          <Tooltip labelFormatter={(value) => new Date(Number(value)).toLocaleString()} />
          <Line type="monotone" dataKey="publish" stroke="#2563eb" dot={false} name="Publish" />
          <Line type="monotone" dataKey="delivery" stroke="#16a34a" dot={false} name="Delivery" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
```

- [ ] **Step 2: Add topic metrics dashboard component**

Create `internal/houston/ui/src/components/metrics/topic-metrics-dashboard.tsx`:

```tsx
import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api } from "@/lib/api-client";
import type { Topic, TopicMetricsOverview, TopicMetricsRow } from "@/lib/types";
import { formatMetricNumber, formatMetricRate, isTelemetryUnavailableError } from "@/lib/metrics";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TopicRateChart } from "./topic-rate-chart";

const TIME_RANGES = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

interface TopicMetricsDashboardProps {
  topics: Topic[];
  refreshKey: number;
}

export function TopicMetricsDashboard({ topics, refreshKey }: TopicMetricsDashboardProps) {
  const [overview, setOverview] = useState<TopicMetricsOverview | null>(null);
  const [timeRange, setTimeRange] = useState("1h");
  const [selectedTopicId, setSelectedTopicId] = useState("");
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.metrics.topicOverview();
      setOverview(data);
      setUnavailable(false);
      const firstTopicID = data.topicMetrics[0]?.topicId ?? topics[0]?.topicId ?? "";
      setSelectedTopicId((current) => current || firstTopicID);
    } catch (err) {
      if (isTelemetryUnavailableError(err)) {
        setUnavailable(true);
      } else {
        setError(err instanceof Error ? err.message : "Failed to load topic metrics");
      }
    } finally {
      setLoading(false);
    }
  }, [topics]);

  useEffect(() => {
    refresh();
  }, [refresh, refreshKey]);

  const topicNames = useMemo(() => new Map(topics.map((topic) => [topic.topicId, topic.topicName])), [topics]);
  const rows = overview?.topicMetrics ?? [];
  const selectedTopic = selectedTopicId || rows[0]?.topicId || topics[0]?.topicId || "";

  if (unavailable) {
    return (
      <div className="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">
        Telemetry is not enabled. Pub/Sub management still works.
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Pub/Sub metrics</h2>
          <p className="text-sm text-muted-foreground">Publish activity, deliveries, and active subscriptions by topic.</p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TIME_RANGES.map((range) => (
                <SelectItem key={range.value} value={range.value}>{range.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="icon" onClick={refresh} disabled={loading} aria-label="Refresh topic metrics">
            <RefreshCw className="size-4" />
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Publish rate" value={formatMetricRate(overview?.systemMetrics.publishRate)} unit="msg/s" />
        <MetricTile label="Delivery rate" value={formatMetricRate(overview?.systemMetrics.deliveryRate)} unit="msg/s" />
        <MetricTile label="Published" value={formatMetricNumber(overview?.systemMetrics.messagesPublished)} unit="msgs" />
        <MetricTile label="Subscriptions" value={formatMetricNumber(overview?.systemMetrics.subscriptionsCurrent)} unit="active" />
      </div>

      {selectedTopic ? (
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="text-sm">{topicNames.get(selectedTopic) ?? selectedTopic}</CardTitle>
            <Select value={selectedTopic} onValueChange={setSelectedTopicId}>
              <SelectTrigger className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {topics.map((topic) => (
                  <SelectItem key={topic.topicId} value={topic.topicId}>{topic.topicName}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </CardHeader>
          <CardContent>
            <TopicRateChart topicId={selectedTopic} timeRange={timeRange} />
          </CardContent>
        </Card>
      ) : null}

      <TopicMetricsTable rows={rows} topicNames={topicNames} />
    </div>
  );
}

function TopicMetricsTable({ rows, topicNames }: { rows: TopicMetricsRow[]; topicNames: Map<string, string> }) {
  if (rows.length === 0) {
    return <div className="rounded-lg border p-6 text-center text-sm text-muted-foreground">No topic metrics have been recorded yet.</div>;
  }
  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Topic</TableHead>
            <TableHead>Publish rate</TableHead>
            <TableHead>Delivery rate</TableHead>
            <TableHead>Published</TableHead>
            <TableHead>Deliveries</TableHead>
            <TableHead>Subscriptions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row.topicId}>
              <TableCell className="font-medium">{topicNames.get(row.topicId) ?? row.topicId}</TableCell>
              <TableCell>{formatMetricRate(row.publishRate)} msg/s</TableCell>
              <TableCell>{formatMetricRate(row.deliveryRate)} msg/s</TableCell>
              <TableCell>{formatMetricNumber(row.messagesPublished)}</TableCell>
              <TableCell>{formatMetricNumber(row.deliveries)}</TableCell>
              <TableCell>{formatMetricNumber(row.subscriptionsCurrent)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function MetricTile({ label, value, unit }: { label: string; value: string; unit: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-semibold">{value}</span>
          <span className="text-xs text-muted-foreground">{unit}</span>
        </div>
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 3: Render dashboard from the pub/sub page component**

In `internal/houston/ui/src/components/pubsub/topic-list.tsx`, import:

```tsx
import { TopicMetricsDashboard } from "@/components/metrics/topic-metrics-dashboard";
```

Add state:

```tsx
const [metricsRefreshKey, setMetricsRefreshKey] = useState(0);
```

After successful `createTopic`, `subscribe`, `publish`, and unsubscribe refresh flows, call:

```tsx
setMetricsRefreshKey((key) => key + 1);
```

Render dashboard after `<Toaster />` and before the existing page header:

```tsx
<TopicMetricsDashboard topics={topics} refreshKey={metricsRefreshKey} />
```

In `internal/houston/ui/src/components/metrics/index.js`, add:

```js
export { TopicMetricsDashboard } from "./topic-metrics-dashboard";
export { TopicRateChart } from "./topic-rate-chart";
```

- [ ] **Step 4: Build Houston**

Run:

```bash
cd internal/houston/ui
bun run build
```

Expected: PASS.

- [ ] **Step 5: Run frontend tests**

Run:

```bash
cd internal/houston/ui
bun test
```

Expected: PASS.

- [ ] **Step 6: Commit Task 6**

```bash
git add internal/houston/ui/src/components/metrics/topic-rate-chart.tsx internal/houston/ui/src/components/metrics/topic-metrics-dashboard.tsx internal/houston/ui/src/components/pubsub/topic-list.tsx internal/houston/ui/src/components/metrics/index.js
git commit -m "feat: show pubsub topic metrics in houston"
```

---

### Task 7: Final Verification And Polish

**Files:**
- Modify only files already touched if verification finds compile, test, or lint issues.

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: passing backend tests, passing Houston tests/build, and a clean reviewable diff.

- [ ] **Step 1: Run targeted Go tests**

Run:

```bash
go test ./internal/server/service/telemetry/collector ./internal/server/service/queue ./internal/server -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full Go test suite**

Run:

```bash
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 3: Run Houston tests and build**

Run:

```bash
cd internal/houston/ui
bun test
bun run build
```

Expected: both PASS.

- [ ] **Step 4: Manual smoke test with local server**

Start the app using the existing project command or Makefile target. If no existing target is documented for telemetry-enabled local startup, report that manual UI verification is blocked by missing local startup instructions.

Manual checks:

- Open `/`.
- Create or identify a queue.
- Open `/queue/{queueId}`.
- Confirm the Metrics tab renders cards and chart empty states without crashing.
- Open `/pubsub`.
- Create a topic.
- Subscribe the queue.
- Publish two messages.
- Confirm Pub/Sub metrics summary and topic row update after refresh.

- [ ] **Step 5: Check final worktree**

Run:

```bash
git status --short
```

Expected: only intended files are modified. `.serena/project.yml` may remain modified from tooling and must not be staged unless the user explicitly asks.

- [ ] **Step 6: Final commit if verification required fixes**

If Step 1-4 required fixes after the last feature commit:

```bash
git add <only-files-fixed-for-verification>
git commit -m "fix: polish telemetry dashboards"
```

If no fixes were needed, do not create an empty commit.

---

## Plan Self-Review

Spec coverage:

- Topic metrics recording is covered by Tasks 1 and 2.
- Topic metrics API endpoints are covered by Task 3.
- Queue detail dashboard and route fix are covered by Task 5.
- Pub/Sub dashboard is covered by Task 6.
- Shared API client, utilities, and telemetry-disabled handling are covered by Tasks 4-6.
- Tests and manual verification are covered in every task and Task 7.

Placeholder scan:

- No unresolved placeholders, TODOs, or "implement later" markers are present.
- The only conditional instruction is the verification-only commit in Task 7, which has explicit behavior for both outcomes.

Type consistency:

- Backend names use `TopicMetricsRecorder`, `TopicRates`, `TopicCounters`, and `TopicMetricsSummary` consistently across tasks.
- Frontend names use `TopicMetricsOverview`, `TopicMetricsSummary`, `MultiMetricsChartResponse`, and `transformRateMetrics` consistently across tasks.

Risk notes:

- The plan intentionally reuses the existing `queue_id` column as a generic metric scope for topic IDs. Metric names disambiguate queue versus topic data.
- The queue service gets the collector through a setter in `server.NewServer` because the collector is created after `queue.NewService` in current startup wiring.
- The frontend plan uses Bun's built-in test runner to avoid adding a new test framework dependency.
