package collector

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
)

var _ telemetry.TopicRecorder = (*Collector)(nil)

func TestTopicRequestsPersistSystemAndAttributableSeries(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_500))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))

	c.RecordTopicRequest(telemetry.TopicOperationEvent{
		Backend: metrics.BackendSQLite, Operation: metrics.OpSubscribe,
		Result: metrics.ResultError, TopicID: "topic-1", Duration: 250 * time.Millisecond,
	})
	requireCollectTopicBoundary(t, c, 2_000)

	batch := store.lastBatch(t)
	labels := `{"backend":"sqlite","operation":"subscribe","result":"error"}`
	durationLabels := `{"backend":"sqlite","operation":"subscribe"}`
	for _, subject := range []string{"", "topic-1"} {
		assertTask9Sample(t, batch.Samples, MetricSample{
			Timestamp: 1_000, SubjectID: subject, MetricName: MetricTopicRequestsTotal,
			Kind: MetricKindCounter, Value: 1, Labels: labels,
		})
		assertTask9Sample(t, batch.Samples, MetricSample{
			Timestamp: 1_500, SubjectID: subject, MetricName: MetricTopicRequestDuration,
			Kind: MetricKindEvent, Value: 0.25, Labels: durationLabels,
		})
	}
}

func TestTopicStorageOperationsRemainSeparate(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_250))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	event := telemetry.TopicOperationEvent{
		Backend: metrics.BackendPostgres, Operation: metrics.OpDeleteTopic,
		Result: metrics.ResultOK, TopicID: "topic-1", Duration: 125 * time.Millisecond,
	}

	c.RecordTopicRequest(event)
	c.RecordTopicOperation(event)
	requireCollectTopicBoundary(t, c, 2_000)

	batch := store.lastBatch(t)
	for _, subject := range []string{"", "topic-1"} {
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicRequestsTotal, 1)
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicOperationsTotal, 1)
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicRequestDuration, 0.125)
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicOperationDuration, 0.125)
	}
}

func TestTopicPublishPersistsBytesFailuresAndFanoutEvents(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_400))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))

	c.RecordTopicPublish(telemetry.TopicPublishEvent{
		TopicID: "topic-1", Messages: 2, Bytes: 30, Destinations: 4, Delivered: 6, Failed: 2,
	})
	requireCollectTopicBoundary(t, c, 2_000)

	batch := store.lastBatch(t)
	for _, subject := range []string{"", "topic-1"} {
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicMessagesPublishedTotal, 2)
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicPublishedBytesTotal, 30)
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicDeliveriesTotal, 6)
		assertTask9MetricValue(t, batch.Samples, subject, MetricTopicDeliveryFailuresTotal, 2)
		assertTask9Sample(t, batch.Samples, MetricSample{
			Timestamp: 1_400, SubjectID: subject, MetricName: MetricTopicFanout,
			Kind: MetricKindEvent, Value: 4,
		})
	}
}

func TestTopicLifecyclePersistsCreatedAndDeletedCounters(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_300))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))

	c.RecordTopicSubscriptionCreated("topic-1")
	c.RecordTopicSubscriptionDeleted("topic-1")
	if _, known := c.GetTopicSubscriptionsCurrentKnown("topic-1"); known {
		t.Fatal("lifecycle event made exact subscription gauge known")
	}
	requireCollectTopicBoundary(t, c, 2_000)

	for _, subject := range []string{"", "topic-1"} {
		assertTask9MetricValue(t, store.lastBatch(t).Samples, subject, MetricTopicSubscriptionsCreatedTotal, 1)
		assertTask9MetricValue(t, store.lastBatch(t).Samples, subject, MetricTopicSubscriptionsDeletedTotal, 1)
	}
}

func TestTopicReconciliationDoesNotFabricateLifecycle(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_200))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))

	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 3},
	})
	requireCollectTopicBoundary(t, c, 2_000)

	batch := store.lastBatch(t)
	assertTask9MetricValue(t, batch.Samples, "", MetricTopicsExist, 1)
	assertTask9MetricValue(t, batch.Samples, "", MetricTopicSubscriptionsCurrent, 3)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCurrent, 3)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCreatedTotal, 0)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsDeletedTotal, 0)
}

func TestTopicStatePersistsTopicsExist(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_200))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist:   2,
		Subscriptions: map[string]int64{"topic-1": 1, "topic-2": 0},
	})

	requireCollectTopicBoundary(t, c, 2_000)
	assertTask9MetricValue(t, store.lastBatch(t).Samples, "", MetricTopicsExist, 2)
}

func TestTopicStateUnavailableWithholdsGaugeCoverage(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_200))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 3},
	})
	c.RecordTopicStateUnavailable()

	requireCollectTopicBoundary(t, c, 2_000)
	batch := store.lastBatch(t)
	assertTask9MetricAbsent(t, batch.Samples, "", MetricTopicsExist)
	assertTask9MetricAbsent(t, batch.Samples, "", MetricTopicSubscriptionsCurrent)
	assertTask9MetricAbsent(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCurrent)
	assertTask9CoverageAbsent(t, batch.Coverage, "", MetricTopicsExist)
	assertTask9CoverageAbsent(t, batch.Coverage, "topic-1", MetricTopicSubscriptionsCurrent)
}

func TestTopicEventAtCutoverBoundaryStaysForNextBucket(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_999))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Messages: 1, Destinations: 2})

	c.cutoverMu.Lock()
	c.eventWatermark = 2_000
	clock.Set(time.UnixMilli(1_000))
	c.cutoverMu.Unlock()
	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Messages: 1, Destinations: 3})

	requireCollectTopicBoundary(t, c, 2_000)
	first := store.lastBatch(t)
	assertTask9EventCount(t, first.Samples, MetricTopicFanout, 2)
	for _, sample := range first.Samples {
		if sample.Kind == MetricKindEvent && sample.Timestamp >= 2_000 {
			t.Fatalf("first boundary persisted open event %#v", sample)
		}
	}

	clock.Set(time.UnixMilli(2_500))
	requireCollectTopicBoundary(t, c, 3_000)
	second := store.lastBatch(t)
	assertTask9Sample(t, second.Samples, MetricSample{
		Timestamp: 2_000, SubjectID: "", MetricName: MetricTopicFanout,
		Kind: MetricKindEvent, Value: 3,
	})
}

func TestBlockedEnqueueCannotArriveBehindCoverage(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_500))
	store := newTask9Store()
	store.saveStarted = make(chan struct{})
	store.saveRelease = make(chan struct{})
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))

	collectDone := make(chan error, 1)
	go func() { collectDone <- c.collectTopicBoundary(context.Background(), 2_000) }()
	<-store.saveStarted

	clock.Set(time.UnixMilli(1_000))
	requestDone := make(chan struct{})
	go func() {
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpListTopics,
			Result: metrics.ResultOK, Duration: time.Millisecond,
		})
		close(requestDone)
	}()
	<-requestDone
	close(store.saveRelease)
	if err := <-collectDone; err != nil {
		t.Fatalf("collect blocked boundary: %v", err)
	}

	first := store.lastBatch(t)
	assertTask9MetricValue(t, first.Samples, "", MetricTopicRequestsTotal, 0)
	assertTask9MetricAbsent(t, first.Samples, "", MetricTopicRequestDuration)
	clock.Set(time.UnixMilli(2_500))
	requireCollectTopicBoundary(t, c, 3_000)
	second := store.lastBatch(t)
	assertTask9MetricValue(t, second.Samples, "", MetricTopicRequestsTotal, 1)
	assertTask9Sample(t, second.Samples, MetricSample{
		Timestamp: 2_000, MetricName: MetricTopicRequestDuration,
		Kind: MetricKindEvent, Value: 0.001,
		Labels: `{"backend":"sqlite","operation":"list_topics"}`,
	})
}

func TestTopicEventBufferReportsOverflow(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(newTask9Store(), WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.eventBufferLimit = 3
	dropped := vm.GetOrCreateCounter(
		`plainq_telemetry_event_buffer_dropped_total{metric="plainq_topic_fanout"}`,
	)
	before := dropped.Get()

	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Destinations: 1})
	if got := len(c.eventQueue); got != 2 {
		t.Fatalf("dual-attributed queue length = %d, want 2", got)
	}
	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Destinations: 2})
	if got := len(c.eventQueue); got != 2 {
		t.Fatalf("one spare slot accepted half a dual event: length = %d", got)
	}
	if got := len(c.eventDirty); got != 1 {
		t.Fatalf("dirty metric count = %d, want 1", got)
	}
	if got := dropped.Get() - before; got != 1 {
		t.Fatalf("Prometheus dropped delta = %d, want 1", got)
	}
}

func TestTopicEventDirtyIntervalsStayBoundedAcrossManyBuckets(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(newTask9Store(), WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.eventBufferLimit = 0

	for bucket := int64(1); bucket <= 100; bucket++ {
		clock.Set(time.UnixMilli(bucket*1_000 + 1))
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpPublish,
			Result: metrics.ResultOK, Duration: time.Millisecond,
		})
		c.RecordTopicOperation(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpPublish,
			Result: metrics.ResultOK, Duration: time.Millisecond,
		})
		c.RecordTopicPublish(telemetry.TopicPublishEvent{Destinations: 1})
	}

	if got := len(c.eventQueue); got != 0 {
		t.Fatalf("event queue length = %d, want 0", got)
	}
	if got := len(c.eventDirty); got != 3 {
		t.Fatalf("dirty metric count = %d, want fixed three families", got)
	}
	for metric, interval := range c.eventDirty {
		if interval.fromBucket != 1_000 || interval.toBucket != 100_000 {
			t.Fatalf("dirty interval %s = %#v, want [1000,100000]", metric, interval)
		}
	}
}

func TestFrozenBoundarySharesEventCapAndRetriesByteForByte(t *testing.T) {
	sentinel := errors.New("lost commit acknowledgment")
	clock := newTask9Clock(time.UnixMilli(1_500))
	store := newTask9Store()
	store.saveErrors = []error{sentinel, nil}
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.eventBufferLimit = 3
	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Messages: 2, Destinations: 4})

	if err := c.collectTopicBoundary(context.Background(), 2_000); !errors.Is(err, sentinel) {
		t.Fatalf("first collect error = %v, want %v", err, sentinel)
	}
	first := store.lastBatch(t)
	if c.frozenBoundary == nil {
		t.Fatal("failed batch was not frozen")
	}

	clock.Set(time.UnixMilli(2_500))
	c.RecordTopicPublish(telemetry.TopicPublishEvent{Destinations: 7})
	c.RecordTopicPublish(telemetry.TopicPublishEvent{Destinations: 8})
	if got := len(c.eventQueue); got != 1 {
		t.Fatalf("live queue length with two frozen entries = %d, want 1", got)
	}

	if err := c.collectTopicBoundary(context.Background(), 3_000); err != nil {
		t.Fatalf("retry collection: %v", err)
	}
	second := store.lastBatch(t)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("retry batch changed\nfirst: %#v\nsecond: %#v", first, second)
	}
	if c.frozenBoundary != nil {
		t.Fatal("successful retry did not release frozen batch")
	}
}

func TestTopicOwnedStateStaysBoundedForRandomAttributedIDs(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(nil, WithClock(clock.Now))
	c.topicLimit = 2
	dropped := vm.GetOrCreateCounter(
		`plainq_telemetry_event_buffer_dropped_total{metric="plainq_topic_requests_total"}`,
	)
	before := dropped.Get()

	for _, topicID := range []string{"c9q00000000000000001", "c9q00000000000000002", "c9q00000000000000003"} {
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpDeleteTopic,
			Result: metrics.ResultError, TopicID: topicID, Duration: time.Millisecond,
		})
	}

	c.topicMu.RLock()
	got := len(c.topicMetrics)
	c.topicMu.RUnlock()
	if got != 2 {
		t.Fatalf("tracked topic count = %d, want bounded 2", got)
	}
	if got := dropped.Get() - before; got != 1 {
		t.Fatalf("Prometheus attribution-loss delta = %d, want 1", got)
	}
}

func TestRequestOnlySubjectsNeverBecomeTerminalOrPoisonKnownGauge(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	c := New(store, WithClock(clock.Now))
	c.RecordTopicRequest(telemetry.TopicOperationEvent{
		Backend: metrics.BackendSQLite, Operation: metrics.OpDeleteTopic,
		Result: metrics.ResultError, TopicID: "request-only", Duration: time.Millisecond,
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})

	if got := c.terminalReservationCount(); got != 0 {
		t.Fatalf("terminal reservations = %d, want 0", got)
	}
	if got := c.GetTopicSystemCounters(); !got.SubscriptionsCurrentKnown || got.SubscriptionsCurrent != 0 {
		t.Fatalf("system subscription state = %#v, want exact known zero", got)
	}
}

func TestTopicRemovalQueuesTerminalZeroBeforeStateRemoval(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	c := New(store, WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 2},
	})
	clock.Set(time.UnixMilli(1_500))
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})

	if _, known := c.GetTopicSubscriptionsCurrentKnown("topic-1"); known {
		t.Fatal("terminal-pending topic remained eligible for current gauge reads")
	}
	c.topicMu.RLock()
	_, retained := c.topicMetrics["topic-1"]
	c.topicMu.RUnlock()
	if !retained {
		t.Fatal("topic state was removed before terminal work became durable")
	}
	if got := c.terminalReservationCount(); got != 1 {
		t.Fatalf("terminal reservations = %d, want 1", got)
	}

	if err := c.promoteTerminalStates(context.Background()); err != nil {
		t.Fatalf("promote terminal state: %v", err)
	}
	states, err := store.ListTerminalStates(context.Background())
	if err != nil || len(states) != 1 || states[0].SubjectID != "topic-1" || states[0].ObservedAt != 1_500 {
		t.Fatalf("durable terminal states = %#v, %v", states, err)
	}
}

func TestTerminalStateBufferReportsOverflowAndStaysBounded(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	c := New(store, WithClock(clock.Now))
	c.terminalLimit = 1
	dropped := vm.GetOrCreateCounter("plainq_telemetry_terminal_state_dropped_total")
	before := dropped.Get()
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 2, Subscriptions: map[string]int64{"topic-1": 1, "topic-2": 1},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})

	if got := c.terminalReservationCount(); got != 1 {
		t.Fatalf("terminal reservations = %d, want 1", got)
	}
	c.cutoverMu.Lock()
	preDurable := len(c.preDurableTerminals)
	c.cutoverMu.Unlock()
	if preDurable != 1 {
		t.Fatalf("pre-durable terminal count = %d, want 1", preDurable)
	}
	if got := dropped.Get() - before; got != 1 {
		t.Fatalf("Prometheus terminal dropped delta = %d, want 1", got)
	}
}

func TestTerminalStateSurvivesCollectorRestart(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	first := New(store, WithClock(clock.Now))
	first.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})
	first.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})
	if err := first.promoteTerminalStates(context.Background()); err != nil {
		t.Fatalf("promote terminal state: %v", err)
	}

	restarted := New(store, WithClock(clock.Now))
	if got := restarted.terminalReservationCount(); got != 1 {
		t.Fatalf("restart terminal reservations = %d, want durable 1", got)
	}
	if due := restarted.terminalStatesDue(1_100); len(due) != 0 {
		t.Fatalf("terminal due at equal observed boundary = %#v, want none", due)
	}
	if due := restarted.terminalStatesDue(1_101); len(due) != 1 || due[0].SubjectID != "topic-1" {
		t.Fatalf("terminal due after observed boundary = %#v", due)
	}
}

func TestTerminalEnqueueFailureUsesBoundedPreDurableRetry(t *testing.T) {
	blocked := make(chan struct{})
	release := make(chan struct{})
	store := newTask9Store()
	store.enqueueStarted = blocked
	store.enqueueRelease = release
	store.enqueueErr = errors.New("sqlite unavailable")
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(store, WithClock(clock.Now))
	c.terminalLimit = 1
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})

	done := make(chan error, 1)
	go func() { done <- c.promoteTerminalStates(context.Background()) }()
	<-blocked

	requestDone := make(chan struct{})
	go func() {
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpListTopics,
			Result: metrics.ResultOK, Duration: time.Millisecond,
		})
		close(requestDone)
	}()
	<-requestDone
	if got := c.GetTopicSystemCounters().Requests; got != 1 {
		t.Fatalf("request count while terminal store blocked = %d, want 1", got)
	}

	close(release)
	if err := <-done; err == nil {
		t.Fatal("terminal promotion error = nil, want store failure")
	}
	if got := c.terminalReservationCount(); got != 1 {
		t.Fatalf("reservation after failure = %d, want retained 1", got)
	}
}

func TestTerminalDurableRejectionDropsWithoutZeroOrCoverage(t *testing.T) {
	store := newTask9Store()
	store.rejectTerminal = true
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(store, WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 2},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})

	if err := c.promoteTerminalStates(context.Background()); err != nil {
		t.Fatalf("reject terminal state: %v", err)
	}
	if got := c.terminalReservationCount(); got != 0 {
		t.Fatalf("terminal reservations after rejection = %d, want 0", got)
	}
	c.topicMu.RLock()
	_, retained := c.topicMetrics["topic-1"]
	c.topicMu.RUnlock()
	if retained {
		t.Fatal("durably rejected terminal retained stale current state")
	}
	if len(store.terminalSamples) != 0 {
		t.Fatalf("durably rejected terminal wrote samples: %#v", store.terminalSamples)
	}
}

func TestTerminalReservationFailsClosedWhenDurableInventoryCannotLoad(t *testing.T) {
	store := newTask9Store()
	store.listErr = errors.New("cannot inspect durable terminal rows")
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(store, WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 2},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})

	if got := c.terminalReservationCount(); got != 0 {
		t.Fatalf("reservation with unknown durable usage = %d, want fail-closed zero", got)
	}
}

func TestTerminalAssignmentAndCompletionReleaseExactlyOnce(t *testing.T) {
	store := newTask9Store()
	clock := newTask9Clock(time.UnixMilli(1_500))
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 2},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})
	if err := c.promoteTerminalStates(context.Background()); err != nil {
		t.Fatalf("promote terminal: %v", err)
	}
	if err := c.assignTerminalStates(context.Background(), 2_000); err != nil {
		t.Fatalf("assign terminal: %v", err)
	}
	due := c.terminalStatesDue(2_000)
	if len(due) != 1 || due[0].TargetBucket == nil || *due[0].TargetBucket != 1_000 {
		t.Fatalf("assigned terminal = %#v, want stable bucket 1000", due)
	}
	if err := c.completeTerminalState(context.Background(), due[0]); err != nil {
		t.Fatalf("complete terminal: %v", err)
	}
	if err := c.completeTerminalState(context.Background(), due[0]); err != nil {
		t.Fatalf("idempotent terminal completion: %v", err)
	}
	if got := c.terminalReservationCount(); got != 0 {
		t.Fatalf("terminal reservations after completion = %d, want 0", got)
	}
	if len(store.terminalSamples) != 1 || store.terminalSamples[0].Value != 0 {
		t.Fatalf("terminal samples = %#v, want one zero", store.terminalSamples)
	}
}

func TestCleanZeroEventCoverageHasNoFabricatedRow(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 0},
	})
	requireCollectTopicBoundary(t, c, 2_000)

	batch := store.lastBatch(t)
	assertTask9MetricAbsent(t, batch.Samples, "topic-1", MetricTopicFanout)
	assertTask9Coverage(t, batch.Coverage, "topic-1", MetricTopicFanout, MetricKindEvent)
}

func TestDelayedTopicEventsPersistWithoutOldCoverage(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_500))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Destinations: 2})

	requireCollectTopicBoundary(t, c, 3_000)
	batch := store.lastBatch(t)
	assertTask9Sample(t, batch.Samples, MetricSample{
		Timestamp: 1_500, SubjectID: "topic-1", MetricName: MetricTopicFanout,
		Kind: MetricKindEvent, Value: 2,
	})
	for _, coverage := range batch.Coverage {
		if coverage.SubjectID == "topic-1" && coverage.MetricName == MetricTopicFanout &&
			coverage.BucketStart != 2_000 {
			t.Fatalf("delayed event fabricated old coverage: %#v", coverage)
		}
	}
}

func TestTopicCollectionBatchPersistsThroughSQLite(t *testing.T) {
	store := newTelemetryTestStore(t)
	clock := newTask9Clock(time.UnixMilli(1_500))
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 2},
	})
	c.RecordTopicRequest(telemetry.TopicOperationEvent{
		Backend: metrics.BackendCluster, Operation: metrics.OpPublish,
		Result: metrics.ResultOK, TopicID: "topic-1", Duration: 50 * time.Millisecond,
	})
	c.RecordTopicPublish(telemetry.TopicPublishEvent{
		TopicID: "topic-1", Messages: 2, Bytes: 20, Destinations: 3, Delivered: 6,
	})
	requireCollectTopicBoundary(t, c, 2_000)

	queries := []SeriesQuery{
		{
			MetricName: MetricTopicRequestsTotal, SubjectID: "topic-1",
			Labels: `{"backend":"cluster","operation":"publish","result":"ok"}`,
			Kind:   MetricKindCounter, Resolution: ResolutionRaw, From: 1_000, To: 2_000,
		},
		{
			MetricName: MetricTopicRequestDuration, SubjectID: "topic-1",
			Labels: `{"backend":"cluster","operation":"publish"}`,
			Kind:   MetricKindEvent, Resolution: ResolutionRaw, From: 1_000, To: 2_000,
		},
		{
			MetricName: MetricTopicFanout, SubjectID: "topic-1",
			Kind: MetricKindEvent, Resolution: ResolutionRaw, From: 1_000, To: 2_000,
		},
		{
			MetricName: MetricTopicSubscriptionsCurrent, SubjectID: "topic-1",
			Kind: MetricKindGauge, Resolution: ResolutionRaw, From: 1_000, To: 2_000,
		},
	}
	for _, query := range queries {
		result, err := store.QuerySeries(context.Background(), query)
		if err != nil {
			t.Fatalf("query %s/%s: %v", query.MetricName, query.Kind, err)
		}
		if len(result.DataPoints) != 1 || len(result.Coverage) != 1 {
			t.Fatalf("query %s/%s = %#v, want one point and coverage", query.MetricName, query.Kind, result)
		}
	}
}

type task9Clock struct {
	mu  sync.Mutex
	now time.Time
}

func newTask9Clock(now time.Time) *task9Clock { return &task9Clock{now: now} }

func (c *task9Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *task9Clock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type task9Store struct {
	*recordingStore

	mu              sync.Mutex
	batches         []CollectionBatch
	saveErrors      []error
	saveStarted     chan struct{}
	saveRelease     chan struct{}
	terminals       map[string]TerminalState
	enqueueStarted  chan struct{}
	enqueueRelease  chan struct{}
	enqueueErr      error
	rejectTerminal  bool
	listErr         error
	terminalSamples []MetricSample
}

func newTask9Store() *task9Store {
	return &task9Store{recordingStore: newRecordingStore(), terminals: make(map[string]TerminalState)}
}

func (s *task9Store) SaveCollectionBoundary(_ context.Context, batch CollectionBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.batches = append(s.batches, cloneTask9Batch(batch))
	if s.saveStarted != nil {
		close(s.saveStarted)
		<-s.saveRelease
		s.saveStarted = nil
	}
	if len(s.saveErrors) == 0 {
		return nil
	}
	err := s.saveErrors[0]
	s.saveErrors = s.saveErrors[1:]

	return err
}

func (s *task9Store) EnqueueTerminalState(
	_ context.Context, subjectID string, observedAt int64, limit int,
) (bool, error) {
	if s.enqueueStarted != nil {
		close(s.enqueueStarted)
		<-s.enqueueRelease
	}
	if s.enqueueErr != nil {
		return false, s.enqueueErr
	}
	if s.rejectTerminal {
		return false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.terminals[subjectID]; exists {
		return true, nil
	}
	if len(s.terminals) >= limit {
		return false, nil
	}
	s.terminals[subjectID] = TerminalState{SubjectID: subjectID, ObservedAt: observedAt}

	return true, nil
}

func (s *task9Store) ListTerminalStates(context.Context) ([]TerminalState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	states := make([]TerminalState, 0, len(s.terminals))
	for _, state := range s.terminals {
		states = append(states, state)
	}
	slices.SortFunc(states, func(a, b TerminalState) int {
		if a.ObservedAt < b.ObservedAt {
			return -1
		}
		if a.ObservedAt > b.ObservedAt {
			return 1
		}
		if a.SubjectID < b.SubjectID {
			return -1
		}
		if a.SubjectID > b.SubjectID {
			return 1
		}

		return 0
	})

	return states, nil
}

func (s *task9Store) AssignTerminalBucket(
	_ context.Context, subjectID string, targetBucket, sampleIntervalMS int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.terminals[subjectID]
	if !exists {
		return errors.New("terminal state absent")
	}
	if state.TargetBucket != nil {
		if *state.TargetBucket != targetBucket || state.SampleIntervalMS == nil ||
			*state.SampleIntervalMS != sampleIntervalMS {
			return errors.New("conflicting terminal assignment")
		}

		return nil
	}
	targetCopy, intervalCopy := targetBucket, sampleIntervalMS
	state.TargetBucket = &targetCopy
	state.SampleIntervalMS = &intervalCopy
	s.terminals[subjectID] = state

	return nil
}

func (s *task9Store) CompleteTerminalState(
	_ context.Context, subjectID string, sample MetricSample, _ CoverageBucket,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.terminals[subjectID]; !exists {
		return nil
	}
	s.terminalSamples = append(s.terminalSamples, sample)
	delete(s.terminals, subjectID)

	return nil
}

func (s *task9Store) lastBatch(t *testing.T) CollectionBatch {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 {
		t.Fatal("no collection batch saved")
	}

	return cloneTask9Batch(s.batches[len(s.batches)-1])
}

func cloneTask9Batch(batch CollectionBatch) CollectionBatch {
	batch.Samples = append([]MetricSample(nil), batch.Samples...)
	batch.RateSnapshots = append([]RateSnapshot(nil), batch.RateSnapshots...)
	batch.Coverage = append([]CoverageBucket(nil), batch.Coverage...)

	return batch
}

func requireCollectTopicBoundary(t *testing.T, c *Collector, boundary int64) {
	t.Helper()
	if err := c.collectTopicBoundary(context.Background(), boundary); err != nil {
		t.Fatalf("collect topic boundary %d: %v", boundary, err)
	}
}

func assertTask9Sample(t *testing.T, samples []MetricSample, want MetricSample) {
	t.Helper()
	for _, sample := range samples {
		if reflect.DeepEqual(sample, want) {
			return
		}
	}
	t.Fatalf("sample %#v absent from %#v", want, samples)
}

func assertTask9MetricValue(t *testing.T, samples []MetricSample, subject, name string, want float64) {
	t.Helper()
	for _, sample := range samples {
		if sample.SubjectID == subject && sample.MetricName == name && sample.Value == want {
			return
		}
	}
	t.Fatalf("metric %q/%q=%v absent from %#v", subject, name, want, samples)
}

func assertTask9MetricAbsent(t *testing.T, samples []MetricSample, subject, name string) {
	t.Helper()
	for _, sample := range samples {
		if sample.SubjectID == subject && sample.MetricName == name {
			t.Fatalf("metric %q/%q unexpectedly present as %#v", subject, name, sample)
		}
	}
}

func assertTask9EventCount(t *testing.T, samples []MetricSample, metric string, want int) {
	t.Helper()
	got := 0
	for _, sample := range samples {
		if sample.MetricName == metric && sample.Kind == MetricKindEvent {
			got++
		}
	}
	if got != want {
		t.Fatalf("event sample count for %s = %d, want %d", metric, got, want)
	}
}

func assertTask9Coverage(
	t *testing.T, coverage []CoverageBucket, subject, metric string, kind MetricKind,
) {
	t.Helper()
	for _, bucket := range coverage {
		if bucket.SubjectID == subject && bucket.MetricName == metric && bucket.Kind == kind {
			return
		}
	}
	t.Fatalf("coverage %q/%q/%q absent from %#v", subject, metric, kind, coverage)
}

func assertTask9CoverageAbsent(t *testing.T, coverage []CoverageBucket, subject, metric string) {
	t.Helper()
	for _, bucket := range coverage {
		if bucket.SubjectID == subject && bucket.MetricName == metric {
			t.Fatalf("coverage %q/%q unexpectedly present as %#v", subject, metric, bucket)
		}
	}
}

func TestTopicMetricsRecordPublishAndRates(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_500))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 0},
	})
	requireCollectTopicBoundary(t, c, 2_000)
	clock.Set(time.UnixMilli(2_500))
	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Messages: 3, Delivered: 9})
	requireCollectTopicBoundary(t, c, 3_000)

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

	batch := store.lastBatch(t)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicPublishRate, 3)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicDeliveryRate, 9)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicMessagesPublishedTotal, 3)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicDeliveriesTotal, 9)
}

func TestTopicMetricsRecordSubscriptions(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_500))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicSubscriptionCreated("topic-1")
	c.RecordTopicSubscriptionDeleted("topic-1")
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})
	requireCollectTopicBoundary(t, c, 2_000)

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

	batch := store.lastBatch(t)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCurrent, 1)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCreatedTotal, 1)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsDeletedTotal, 1)
}

func TestTopicMetricsUnknownSubscriptionCountDoesNotPersistFalseZero(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_500))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicSubscriptionCreated("topic-1")
	requireCollectTopicBoundary(t, c, 2_000)

	if _, ok := c.GetTopicSubscriptionsCurrentKnown("topic-1"); ok {
		t.Fatal("current subscriptions marked known, want unknown")
	}

	system := c.GetTopicSystemCounters()
	if system.SubscriptionsCurrentKnown {
		t.Fatal("system current subscriptions marked known, want unknown")
	}

	batch := store.lastBatch(t)
	assertTask9MetricAbsent(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCurrent)
	assertTask9MetricAbsent(t, batch.Samples, "", MetricTopicSubscriptionsCurrent)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCreatedTotal, 1)
}

func TestTopicMetricsLastUpdatedTracksMetricEvents(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_000))
	c := New(nil, WithClock(clock.Now))

	if got := c.GetTopicLastUpdated("topic-1"); got != 0 {
		t.Fatalf("last updated before activity = %d, want 0", got)
	}

	c.RecordTopicPublish(telemetry.TopicPublishEvent{TopicID: "topic-1", Messages: 1, Delivered: 1})
	firstUpdatedAt := c.GetTopicLastUpdated("topic-1")
	if firstUpdatedAt == 0 {
		t.Fatal("last updated after publish = 0, want non-zero timestamp")
	}

	clock.Set(time.UnixMilli(1_001))
	c.RecordTopicSubscriptionCreated("topic-1")
	secondUpdatedAt := c.GetTopicLastUpdated("topic-1")
	if secondUpdatedAt <= firstUpdatedAt {
		t.Fatalf("last updated after subscription = %d, want greater than %d", secondUpdatedAt, firstUpdatedAt)
	}
}

func TestTopicMetricsReconcileSubscriptionCountsRemovesMissingTopics(t *testing.T) {
	c := New(nil)
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 2, Subscriptions: map[string]int64{"topic-1": 2, "topic-2": 1},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})

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

	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 0},
	})

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

func (s *recordingStore) SaveRateSnapshot(_ context.Context, _ int64, queueID, metricName string, ratePerSecond float64, _ int64) error {
	s.rates = append(s.rates, recordedMetric{scope: queueID, name: metricName, value: ratePerSecond})
	return nil
}

func (s *recordingStore) SaveQueueStats(context.Context, int64, string, int64, int64, int64, float64, float64) error {
	return nil
}

func (s *recordingStore) UpdateInFlightCount(context.Context, string, int64) error { return nil }
func (s *recordingStore) SaveMetric(context.Context, MetricSample) error           { return nil }
func (s *recordingStore) SaveCoverage(context.Context, CoverageBucket) error       { return nil }
func (s *recordingStore) SaveMetricAndCoverage(context.Context, MetricSample, CoverageBucket) error {
	return nil
}
func (s *recordingStore) QuerySeries(context.Context, SeriesQuery) (SeriesResult, error) {
	return SeriesResult{}, nil
}
func (s *recordingStore) QuerySubjectCoverage(context.Context, SubjectCoverageQuery) ([]CoverageBucket, error) {
	return nil, nil
}
func (s *recordingStore) SaveRateSnapshotAndMetric(context.Context, int64, string, string, float64, int64, MetricSample) error {
	return nil
}
func (s *recordingStore) SaveCollectionBoundary(context.Context, CollectionBatch) error { return nil }
func (s *recordingStore) Rollup(context.Context, Resolution, int64) error               { return nil }
func (s *recordingStore) ResetRawInterval(context.Context, int64) (bool, error)         { return false, nil }
func (s *recordingStore) EnqueueTerminalState(context.Context, string, int64, int) (bool, error) {
	return false, nil
}
func (s *recordingStore) ListTerminalStates(context.Context) ([]TerminalState, error) {
	return nil, nil
}
func (s *recordingStore) AssignTerminalBucket(context.Context, string, int64, int64) error {
	return nil
}
func (s *recordingStore) CompleteTerminalState(context.Context, string, MetricSample, CoverageBucket) error {
	return nil
}
func (s *recordingStore) Aggregate1m(context.Context, int64, int64) error { return nil }
func (s *recordingStore) Aggregate1h(context.Context, int64, int64) error { return nil }
func (s *recordingStore) Aggregate1d(context.Context, int64, int64) error { return nil }
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
