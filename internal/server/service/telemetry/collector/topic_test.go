package collector

import (
	"context"
	"errors"
	"fmt"
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

func TestTerminalPendingTopicKeepsFinalCountersRatesAndEventCoverage(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 2},
	})
	requireCollectTopicBoundary(t, c, 2_000)

	recordTerminalPendingDeleteProductionOrder(clock, c, 2_000)
	requireCollectTopicBoundary(t, c, 3_000)

	batch := store.lastBatch(t)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicOperationsTotal, 1)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicRequestsTotal, 1)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsDeletedTotal, 2)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicSubscriptionsDeletedRate, 2)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicOperationDuration, 0.01)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicRequestDuration, 0.02)
	assertTask9Coverage(t, batch.Coverage, "topic-1", MetricTopicOperationDuration, MetricKindEvent)
	assertTask9Coverage(t, batch.Coverage, "topic-1", MetricTopicRequestDuration, MetricKindEvent)
	assertTask9MetricAbsent(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCurrent)
	assertTask9CoverageAbsent(t, batch.Coverage, "topic-1", MetricTopicSubscriptionsCurrent)
}

func TestTerminalTopicPersistsZeroAndCoverageBeforeRemoval(t *testing.T) {
	ctx := context.Background()
	store, _ := newTelemetryTestStoreWithConn(t)
	if reset, err := store.ResetRawInterval(ctx, 1_000); err != nil || !reset {
		t.Fatalf("reset raw interval = %t, %v; want true, nil", reset, err)
	}

	clock := newTask9Clock(time.UnixMilli(58_100))
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 2},
	})
	requireCollectTopicBoundary(t, c, 59_000)

	recordTerminalPendingDeleteProductionOrder(clock, c, 59_000)
	requireCollectTopicBoundary(t, c, 60_000)

	operationLabels := canonicalResultLabels(metrics.BackendSQLite, metrics.OpDeleteTopic, metrics.ResultOK)
	durationLabels := canonicalDurationLabels(metrics.BackendSQLite, metrics.OpDeleteTopic)
	assertSQLiteSeriesPoint := func(
		resolution Resolution, metricName, labels string, kind MetricKind,
		from, to int64, wantValue float64, wantCoverage int,
	) DataPoint {
		t.Helper()
		result := mustQuerySeries(t, store, SeriesQuery{
			SubjectID: "topic-1", MetricName: metricName, Labels: labels,
			Kind: kind, Resolution: resolution, From: from, To: to,
		})
		if len(result.DataPoints) != 1 || result.DataPoints[0].Value != wantValue {
			t.Fatalf("%s %s points = %#v, want one value %v", resolution, metricName, result.DataPoints, wantValue)
		}
		if wantCoverage >= 0 && len(result.Coverage) != wantCoverage {
			t.Fatalf("%s %s coverage = %#v, want %d", resolution, metricName, result.Coverage, wantCoverage)
		}

		return result.DataPoints[0]
	}

	preTerminalGauge := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "topic-1", MetricName: MetricTopicSubscriptionsCurrent,
		Kind: MetricKindGauge, Resolution: ResolutionRaw, From: 59_000, To: 60_000,
	})
	if len(preTerminalGauge.DataPoints) != 0 || len(preTerminalGauge.Coverage) != 0 {
		t.Fatalf("terminal-pending active gauge = %#v, want no point or coverage", preTerminalGauge)
	}

	assertSQLiteSeriesPoint(ResolutionRaw, MetricTopicOperationsTotal, operationLabels,
		MetricKindCounter, 59_000, 60_000, 1, 1)
	assertSQLiteSeriesPoint(ResolutionRaw, MetricTopicRequestsTotal, operationLabels,
		MetricKindCounter, 59_000, 60_000, 1, 1)
	assertSQLiteSeriesPoint(ResolutionRaw, MetricTopicSubscriptionsDeletedTotal, "",
		MetricKindCounter, 59_000, 60_000, 2, 1)
	assertSQLiteSeriesPoint(ResolutionRaw, MetricTopicSubscriptionsDeletedRate, "",
		MetricKindRate, 59_000, 60_000, 2, 1)
	assertSQLiteSeriesPoint(ResolutionRaw, MetricTopicOperationDuration, durationLabels,
		MetricKindEvent, 59_000, 60_000, 0.01, 1)
	assertSQLiteSeriesPoint(ResolutionRaw, MetricTopicRequestDuration, durationLabels,
		MetricKindEvent, 59_000, 60_000, 0.02, 1)

	if err := c.promoteTerminalStates(ctx); err != nil {
		t.Fatalf("promote terminal state: %v", err)
	}
	if err := c.assignTerminalStates(ctx, 60_000); err != nil {
		t.Fatalf("assign terminal state: %v", err)
	}
	due := c.terminalStatesDue(60_000)
	if len(due) != 1 || due[0].TargetBucket == nil || *due[0].TargetBucket != 59_000 {
		t.Fatalf("terminal due = %#v, want target 59000", due)
	}
	if err := c.completeTerminalState(ctx, due[0]); err != nil {
		t.Fatalf("complete terminal state: %v", err)
	}

	terminalPoint := assertSQLiteSeriesPoint(ResolutionRaw, MetricTopicSubscriptionsCurrent, "",
		MetricKindGauge, 59_000, 60_000, 0, 1)
	if terminalPoint.Timestamp != 59_000 {
		t.Fatalf("terminal zero timestamp = %d, want 59000", terminalPoint.Timestamp)
	}

	if err := store.Rollup(ctx, Resolution1m, 60_000); err != nil {
		t.Fatalf("roll up terminal production order: %v", err)
	}
	coarseGauge := assertSQLiteSeriesPoint(Resolution1m, MetricTopicSubscriptionsCurrent, "",
		MetricKindGauge, 0, 60_000, 0, -1)
	if coarseGauge.Last != 0 {
		t.Fatalf("coarse terminal gauge = %#v, want last zero", coarseGauge)
	}
	assertSQLiteSeriesPoint(Resolution1m, MetricTopicOperationsTotal, operationLabels,
		MetricKindCounter, 0, 60_000, 1, -1)
	assertSQLiteSeriesPoint(Resolution1m, MetricTopicRequestsTotal, operationLabels,
		MetricKindCounter, 0, 60_000, 1, -1)
	assertSQLiteSeriesPoint(Resolution1m, MetricTopicSubscriptionsDeletedTotal, "",
		MetricKindCounter, 0, 60_000, 2, -1)
	assertSQLiteSeriesPoint(Resolution1m, MetricTopicSubscriptionsDeletedRate, "",
		MetricKindRate, 0, 60_000, 2, -1)
	assertSQLiteSeriesPoint(Resolution1m, MetricTopicOperationDuration, durationLabels,
		MetricKindEvent, 0, 60_000, 0.01, -1)
	assertSQLiteSeriesPoint(Resolution1m, MetricTopicRequestDuration, durationLabels,
		MetricKindEvent, 0, 60_000, 0.02, -1)
}

func TestTerminalCompletionPreservesPostCutoverAccumulator(t *testing.T) {
	ctx := context.Background()
	completeStarted := make(chan struct{})
	completeRelease := make(chan struct{})
	store := newTask9Store()
	store.completeStarted = completeStarted
	store.completeRelease = completeRelease
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})
	requireCollectTopicBoundary(t, c, 2_000)

	clock.Set(time.UnixMilli(2_500))
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})
	if err := c.promoteTerminalStates(ctx); err != nil {
		t.Fatalf("promote terminal state: %v", err)
	}
	requireCollectTopicBoundary(t, c, 3_000)
	if err := c.assignTerminalStates(ctx, 3_000); err != nil {
		t.Fatalf("assign terminal state: %v", err)
	}
	due := c.terminalStatesDue(3_000)
	if len(due) != 1 {
		t.Fatalf("terminal due = %#v, want one assigned state", due)
	}

	completionDone := make(chan error, 1)
	go func() { completionDone <- c.completeTerminalState(ctx, due[0]) }()
	<-completeStarted

	clock.Set(time.UnixMilli(3_100))
	requestDone := make(chan struct{})
	go func() {
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpDeleteTopic,
			Result: metrics.ResultOK, TopicID: "topic-1", Duration: 25 * time.Millisecond,
		})
		close(requestDone)
	}()
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("same-ID request blocked behind terminal SQLite completion")
	}

	close(completeRelease)
	if err := <-completionDone; err != nil {
		t.Fatalf("complete terminal state: %v", err)
	}
	if got := c.terminalReservationCount(); got != 0 {
		t.Fatalf("terminal reservations after completion = %d, want zero", got)
	}

	c.topicMu.RLock()
	retained, exists := c.topicMetrics["topic-1"]
	if !exists || retained.authoritative || retained.subscriptionsKnown || retained.terminalPending ||
		retained.terminalGeneration != 0 || retained.cacheElement == nil {
		c.topicMu.RUnlock()
		t.Fatalf("retained attribution-only topic = %#v, exists=%t", retained, exists)
	}
	c.topicMu.RUnlock()

	requireCollectTopicBoundary(t, c, 4_000)
	batch := store.lastBatch(t)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicRequestsTotal, 1)
	assertTask9MetricValue(t, batch.Samples, "topic-1", MetricTopicRequestDuration, 0.025)
	assertTask9Coverage(t, batch.Coverage, "topic-1", MetricTopicRequestsTotal, MetricKindCounter)
	assertTask9Coverage(t, batch.Coverage, "topic-1", MetricTopicRequestDuration, MetricKindEvent)
	assertTask9MetricAbsent(t, batch.Samples, "topic-1", MetricTopicSubscriptionsCurrent)
	assertTask9CoverageAbsent(t, batch.Coverage, "topic-1", MetricTopicSubscriptionsCurrent)
}

func recordTerminalPendingDeleteProductionOrder(clock *task9Clock, c *Collector, bucketStart int64) {
	clock.Set(time.UnixMilli(bucketStart + 100))
	c.RecordTopicOperation(telemetry.TopicOperationEvent{
		Backend: metrics.BackendSQLite, Operation: metrics.OpDeleteTopic,
		Result: metrics.ResultOK, TopicID: "topic-1", Duration: 10 * time.Millisecond,
	})
	clock.Set(time.UnixMilli(bucketStart + 200))
	c.RecordTopicSubscriptionDeleted("topic-1")
	c.RecordTopicSubscriptionDeleted("topic-1")
	clock.Set(time.UnixMilli(bucketStart + 300))
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})
	clock.Set(time.UnixMilli(bucketStart + 400))
	c.RecordTopicRequest(telemetry.TopicOperationEvent{
		Backend: metrics.BackendSQLite, Operation: metrics.OpDeleteTopic,
		Result: metrics.ResultOK, TopicID: "topic-1", Duration: 20 * time.Millisecond,
	})
}

func TestCollectionRetainsFutureBucketEvents(t *testing.T) {
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

func TestEventAtBoundaryCannotArriveBehindCoverage(t *testing.T) {
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

func TestDirtyEventIntervalAdvancesWithoutGrowingAcrossCutover(t *testing.T) {
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

	requireCollectTopicBoundary(t, c, 101_000)
	if got := len(c.eventDirty); got != 0 {
		t.Fatalf("committed cutover retained expired dirty families = %#v", c.eventDirty)
	}
}

func TestDirtyEventBucketNeverGetsCoverage(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.eventBufferLimit = 0
	c.RecordTopicRequest(telemetry.TopicOperationEvent{
		Backend: metrics.BackendSQLite, Operation: metrics.OpPublish,
		Result: metrics.ResultOK, Duration: time.Millisecond,
	})

	requireCollectTopicBoundary(t, c, 2_000)
	assertTask9CoverageAbsent(t, store.lastBatch(t).Coverage, "", MetricTopicRequestDuration)
}

func TestFailedBoundaryRetainsDirtyStateUntilCommit(t *testing.T) {
	sentinel := errors.New("write failed")
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	store.saveErrors = []error{sentinel}
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.eventBufferLimit = 0
	c.RecordTopicPublish(telemetry.TopicPublishEvent{Destinations: 1})

	if err := c.collectTopicBoundary(context.Background(), 2_000); !errors.Is(err, sentinel) {
		t.Fatalf("failed boundary error = %v, want %v", err, sentinel)
	}
	if _, exists := c.eventDirty[MetricTopicFanout]; !exists {
		t.Fatal("failed boundary cleared live dirty interval")
	}
	if err := c.collectTopicBoundary(context.Background(), 2_000); err != nil {
		t.Fatalf("retry boundary: %v", err)
	}
	if _, exists := c.eventDirty[MetricTopicFanout]; exists {
		t.Fatal("committed boundary retained expired dirty interval")
	}
}

func TestSameBoundaryRetryDoesNotDuplicateRawSeriesOrEvents(t *testing.T) {
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

	for _, topicID := range []string{
		"c9q00000000000000001",
		"c9q00000000000000002",
		"c9q00000000000000003",
		"c9q00000000000000004",
		"c9q00000000000000005",
	} {
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
	if got := len(c.topicDirty); got > c.topicLimit {
		t.Fatalf("topic dirty subject count = %d, want <= %d", got, c.topicLimit)
	}
	if got := len(c.topicDirtyOverflow); got != 2 {
		t.Fatalf("fixed overflow dirty metric count = %d, want request counter and duration", got)
	}
	if got := dropped.Get() - before; got != 3 {
		t.Fatalf("Prometheus attribution-loss delta = %d, want 3", got)
	}
}

func TestTopicAccumulatorCapPreservesUncommittedCountersAndExactCoverage(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTelemetryTestStore(t)
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.topicLimit = 1

	recordAllTopicCounters := func(topicID string, messages uint64) {
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpPublish,
			Result: metrics.ResultOK, TopicID: topicID, Duration: time.Millisecond,
		})
		c.RecordTopicPublish(telemetry.TopicPublishEvent{
			TopicID: topicID, Messages: messages, Bytes: messages * 10,
			Destinations: 1, Delivered: messages,
		})
		c.RecordTopicSubscriptionCreated(topicID)
	}

	recordAllTopicCounters("topic-a", 2)
	recordAllTopicCounters("topic-b", 7)
	recordAllTopicCounters("topic-a", 3)
	requireCollectTopicBoundary(t, c, 2_000)

	clock.Set(time.UnixMilli(2_100))
	recordAllTopicCounters("topic-a", 4)
	requireCollectTopicBoundary(t, c, 3_000)

	// A successful boundary makes topic-a safe to replace. Topic-b can then be
	// admitted and, after its own commit, topic-a can be admitted again as a
	// deliberate reset rather than losing an uncommitted cumulative value.
	clock.Set(time.UnixMilli(3_100))
	recordAllTopicCounters("topic-b", 5)
	requireCollectTopicBoundary(t, c, 4_000)
	clock.Set(time.UnixMilli(4_100))
	recordAllTopicCounters("topic-a", 6)
	requireCollectTopicBoundary(t, c, 5_000)

	requestLabels := `{"backend":"sqlite","operation":"publish","result":"ok"}`
	assertTask9CounterSeries(t, store, SeriesQuery{
		MetricName: MetricTopicRequestsTotal, SubjectID: "topic-a", Labels: requestLabels,
		Kind: MetricKindCounter, Resolution: ResolutionRaw, From: 1_000, To: 5_000,
	}, []float64{2, 3, 1}, []float64{1, 1})
	assertTask9CounterSeries(t, store, SeriesQuery{
		MetricName: MetricTopicMessagesPublishedTotal, SubjectID: "topic-a",
		Kind: MetricKindCounter, Resolution: ResolutionRaw, From: 1_000, To: 5_000,
	}, []float64{5, 9, 6}, []float64{4, 6})
	assertTask9CounterSeries(t, store, SeriesQuery{
		MetricName: MetricTopicSubscriptionsCreatedTotal, SubjectID: "topic-a",
		Kind: MetricKindCounter, Resolution: ResolutionRaw, From: 1_000, To: 5_000,
	}, []float64{2, 3, 1}, []float64{1, 1})

	bDropped := mustQueryTask9Series(t, store, SeriesQuery{
		MetricName: MetricTopicRequestDuration, SubjectID: "topic-b",
		Labels: `{"backend":"sqlite","operation":"publish"}`,
		Kind:   MetricKindEvent, Resolution: ResolutionRaw, From: 1_000, To: 3_000,
	})
	if len(bDropped.DataPoints) != 0 || len(bDropped.Coverage) != 0 {
		t.Fatalf("dropped topic-b attribution = %#v, want no row or exact coverage", bDropped)
	}

	bReadmitted := mustQueryTask9Series(t, store, SeriesQuery{
		MetricName: MetricTopicMessagesPublishedTotal, SubjectID: "topic-b",
		Kind: MetricKindCounter, Resolution: ResolutionRaw, From: 3_000, To: 4_000,
	})
	if len(bReadmitted.DataPoints) != 1 || bReadmitted.DataPoints[0].Value != 5 ||
		len(bReadmitted.Coverage) != 1 {
		t.Fatalf("re-admitted topic-b series = %#v, want value 5 with exact coverage", bReadmitted)
	}
}

func TestTopicBoundaryCommitCannotMarkReadmittedAccumulatorDurable(t *testing.T) {
	clock := newTask9Clock(time.UnixMilli(1_100))
	store := newTask9Store()
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.topicLimit = 1
	recordRequest := func(topicID string) {
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpPublish,
			Result: metrics.ResultOK, TopicID: topicID, Duration: time.Millisecond,
		})
	}

	recordRequest("topic-a")
	requireCollectTopicBoundary(t, c, 2_000)

	store.saveStarted = make(chan struct{})
	store.saveRelease = make(chan struct{})
	boundaryDone := make(chan error, 1)
	go func() { boundaryDone <- c.collectTopicBoundary(context.Background(), 3_000) }()
	<-store.saveStarted

	clock.Set(time.UnixMilli(3_100))
	recordRequest("topic-b")
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-b": 0},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})
	store.rejectTerminal = true
	if err := c.promoteTerminalStates(context.Background()); err != nil {
		t.Fatalf("drop topic-b terminal reservation: %v", err)
	}

	callbackDone := make(chan struct{})
	go func() {
		recordRequest("topic-a")
		close(callbackDone)
	}()
	<-callbackDone

	close(store.saveRelease)
	if err := <-boundaryDone; err != nil {
		t.Fatalf("finish blocked boundary: %v", err)
	}

	// The completed boundary held an older topic-a accumulator. It must not
	// make the newly admitted topic-a safe to evict before that new value commits.
	recordRequest("topic-c")
	requireCollectTopicBoundary(t, c, 4_000)
	requestLabels := `{"backend":"sqlite","operation":"publish","result":"ok"}`
	batch := store.lastBatch(t)
	assertTask9Sample(t, batch.Samples, MetricSample{
		Timestamp: 3_000, SubjectID: "topic-a", MetricName: MetricTopicRequestsTotal,
		Kind: MetricKindCounter, Value: 1, Labels: requestLabels,
	})
	assertTask9MetricAbsent(t, batch.Samples, "topic-c", MetricTopicRequestsTotal)
}

func TestTerminalMaintenanceOrderingNeverHoldsCutoverAndVisitsLinearly(t *testing.T) {
	const backlog = 32

	store := newTask9Store()
	clock := newTask9Clock(time.UnixMilli(1_100))
	c := New(store, WithClock(clock.Now))
	c.terminalLimit = backlog

	subscriptions := make(map[string]int64, backlog)
	for i := range backlog {
		subscriptions[fmt.Sprintf("topic-%02d", i)] = 1
	}
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: backlog, Subscriptions: subscriptions})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})

	promotionEntered := make(chan struct{})
	promotionRelease := make(chan struct{})
	promotionVisits := 0
	var promotionBarrier sync.Once
	c.terminalVisit = func() {
		promotionVisits++
		promotionBarrier.Do(func() {
			close(promotionEntered)
			<-promotionRelease
		})
	}
	promotionDone := make(chan error, 1)
	go func() { promotionDone <- c.promoteTerminalStates(context.Background()) }()
	<-promotionEntered
	assertTopicRequestCompletesWhileTerminalMaintenanceBlocked(t, c)
	close(promotionRelease)
	if err := <-promotionDone; err != nil {
		t.Fatalf("promote terminal backlog: %v", err)
	}
	if promotionVisits != backlog {
		t.Fatalf("promotion visits = %d, want exactly %d", promotionVisits, backlog)
	}

	dueEntered := make(chan struct{})
	dueRelease := make(chan struct{})
	dueVisits := 0
	var dueBarrier sync.Once
	c.terminalVisit = func() {
		dueVisits++
		dueBarrier.Do(func() {
			close(dueEntered)
			<-dueRelease
		})
	}
	dueDone := make(chan []TerminalState, 1)
	go func() { dueDone <- c.terminalStatesDue(2_000) }()
	<-dueEntered
	assertTopicRequestCompletesWhileTerminalMaintenanceBlocked(t, c)
	close(dueRelease)
	if got := len(<-dueDone); got != backlog {
		t.Fatalf("due states = %d, want %d", got, backlog)
	}
	if dueVisits != backlog {
		t.Fatalf("due-order visits = %d, want exactly %d", dueVisits, backlog)
	}
}

func TestTerminalDueMaintenanceIsLinearAndDeterministic(t *testing.T) {
	for _, backlog := range []int{64, 128} {
		t.Run(fmt.Sprintf("backlog=%d", backlog), func(t *testing.T) {
			c := New(nil)
			c.terminalLimit = backlog

			c.terminalMu.Lock()
			c.topicMu.Lock()
			for i := backlog - 1; i >= 0; i-- {
				subjectID := fmt.Sprintf("topic-%03d", i)
				observedAt := int64(100 + (i*37)%backlog)
				if !c.reserveTerminalLocked(subjectID, &TopicMetrics{}, observedAt) {
					t.Fatalf("reserve shuffled terminal %q", subjectID)
				}
				c.terminalReservations[subjectID].durable = true
			}
			c.topicMu.Unlock()
			c.terminalMu.Unlock()

			visits := 0
			c.terminalVisit = func() { visits++ }
			first := c.terminalStatesDue(1_000)
			if visits != backlog {
				t.Fatalf("due maintenance work = %d, want exactly one visit for each of %d states", visits, backlog)
			}
			assertTerminalStatesOrdered(t, first)

			visits = 0
			second := c.terminalStatesDue(1_000)
			if visits != backlog {
				t.Fatalf("repeat due maintenance work = %d, want exactly one visit for each of %d states", visits, backlog)
			}
			if !reflect.DeepEqual(second, first) {
				t.Fatalf("repeat due order = %#v, want deterministic %#v", second, first)
			}
		})
	}
}

func assertTerminalStatesOrdered(t *testing.T, states []TerminalState) {
	t.Helper()
	for i := 1; i < len(states); i++ {
		previous, current := states[i-1], states[i]
		if previous.ObservedAt > current.ObservedAt ||
			(previous.ObservedAt == current.ObservedAt && previous.SubjectID > current.SubjectID) ||
			(previous.ObservedAt == current.ObservedAt && previous.SubjectID == current.SubjectID &&
				previous.Generation > current.Generation) {
			t.Fatalf("terminal states out of order at %d: %#v before %#v", i, previous, current)
		}
	}
}

func assertTopicRequestCompletesWhileTerminalMaintenanceBlocked(t *testing.T, c *Collector) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		c.RecordTopicRequest(telemetry.TopicOperationEvent{
			Backend: metrics.BackendSQLite, Operation: metrics.OpListTopics,
			Result: metrics.ResultOK, Duration: time.Millisecond,
		})
		close(done)
	}()
	<-done
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
	c.terminalMu.Lock()
	preDurable := c.terminalQueue.Len()
	c.terminalMu.Unlock()
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
	if err := restarted.loadDurableTerminalReservations(context.Background()); err != nil {
		t.Fatalf("load restart terminal states: %v", err)
	}
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

func TestTerminalReappearanceCancelsExactDurableGenerationAndAllowsRedeletion(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart=%t", restart), func(t *testing.T) {
			ctx := context.Background()
			store, _ := newTelemetryTestStoreWithConn(t)
			if reset, err := store.ResetRawInterval(ctx, 1_000); err != nil || !reset {
				t.Fatalf("reset raw interval = %t, %v; want true, nil", reset, err)
			}

			clock := newTask9Clock(time.UnixMilli(1_100))
			current := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
			current.RecordTopicState(telemetry.TopicStateEvent{
				TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 3},
			})
			requireCollectTopicBoundary(t, current, 2_000)

			clock.Set(time.UnixMilli(2_500))
			current.RecordTopicState(telemetry.TopicStateEvent{
				TopicsExist: 0, Subscriptions: map[string]int64{},
			})
			if err := current.promoteTerminalStates(ctx); err != nil {
				t.Fatalf("promote first deletion: %v", err)
			}
			if err := current.assignTerminalStates(ctx, 3_000); err != nil {
				t.Fatalf("assign first deletion: %v", err)
			}
			first, err := store.ListTerminalStates(ctx)
			if err != nil || len(first) != 1 || first[0].TargetBucket == nil || *first[0].TargetBucket != 2_000 {
				t.Fatalf("first durable deletion = %#v, %v; want assigned target 2000", first, err)
			}

			if restart {
				current = New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
				if err := current.loadDurableTerminalReservations(ctx); err != nil {
					t.Fatalf("load restart terminal states: %v", err)
				}
			}

			clock.Set(time.UnixMilli(2_600))
			current.RecordTopicState(telemetry.TopicStateEvent{
				TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 4},
			})
			if err := current.promoteTerminalStates(ctx); err != nil {
				t.Fatalf("cancel stale deletion: %v", err)
			}
			if states, err := store.ListTerminalStates(ctx); err != nil || len(states) != 0 {
				t.Fatalf("terminal states after reappearance = %#v, %v; want none", states, err)
			}
			if due := current.terminalStatesDue(3_000); len(due) != 0 {
				t.Fatalf("stale assigned state remained due after reappearance: %#v", due)
			}
			requireCollectTopicBoundary(t, current, 3_000)

			result := mustQuerySeries(t, store, SeriesQuery{
				SubjectID: "topic-1", MetricName: MetricTopicSubscriptionsCurrent,
				Kind: MetricKindGauge, Resolution: ResolutionRaw, From: 2_000, To: 3_000,
			})
			if len(result.DataPoints) != 1 || result.DataPoints[0].Value != 4 || len(result.Coverage) != 1 {
				t.Fatalf("reappeared gauge = %#v, want one exact active value 4", result)
			}

			clock.Set(time.UnixMilli(3_500))
			current.RecordTopicState(telemetry.TopicStateEvent{
				TopicsExist: 0, Subscriptions: map[string]int64{},
			})
			if err := current.promoteTerminalStates(ctx); err != nil {
				t.Fatalf("promote second deletion: %v", err)
			}
			second, err := store.ListTerminalStates(ctx)
			if err != nil || len(second) != 1 || second[0].ObservedAt != 3_500 {
				t.Fatalf("second durable deletion = %#v, %v; want fresh transition at 3500", second, err)
			}
			if second[0].Generation <= first[0].Generation {
				t.Fatalf("second generation = %d, want greater than first %d", second[0].Generation, first[0].Generation)
			}
		})
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
	if err := c.loadDurableTerminalReservations(context.Background()); err == nil {
		t.Fatal("durable inventory load returned nil, want failure")
	}
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

func TestTerminalTopicFailureAcrossMinuteDoesNotRetarget(t *testing.T) {
	ctx := context.Background()
	store, conn := newTelemetryTestStoreWithConn(t)
	if reset, err := store.ResetRawInterval(ctx, 1_000); err != nil || !reset {
		t.Fatalf("reset raw interval = %t, %v; want true, nil", reset, err)
	}
	seedRawGrid(t, store, "topic-1", MetricTopicSubscriptionsCurrent, MetricKindGauge,
		0, 59_000, 1_000, func(int64) (float64, int64) { return 1, 0 })

	clock := newTask9Clock(time.UnixMilli(59_100))
	first := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	first.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})
	clock.Set(time.UnixMilli(59_500))
	first.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 0, Subscriptions: map[string]int64{},
	})
	if err := first.promoteTerminalStates(ctx); err != nil {
		t.Fatalf("promote terminal: %v", err)
	}
	if err := first.assignTerminalStates(ctx, 60_000); err != nil {
		t.Fatalf("assign terminal: %v", err)
	}

	restarted := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	if err := restarted.loadDurableTerminalReservations(ctx); err != nil {
		t.Fatalf("load assigned state after restart: %v", err)
	}
	due := restarted.terminalStatesDue(60_000)
	if len(due) != 1 || due[0].TargetBucket == nil || *due[0].TargetBucket != 59_000 {
		t.Fatalf("assigned state after restart = %#v, want original target 59000", due)
	}
	if _, err := conn.Exec(`CREATE TRIGGER fail_terminal_rollup_coverage BEFORE INSERT ON telemetry_coverage
WHEN NEW.subject_id = 'topic-1' AND NEW.metric_name = 'plainq_topic_subscriptions_current'
BEGIN SELECT RAISE(ABORT, 'terminal coverage failure'); END;`); err != nil {
		t.Fatalf("install terminal failure trigger: %v", err)
	}
	if err := restarted.completeTerminalState(ctx, due[0]); err == nil {
		t.Fatal("terminal completion returned nil, want injected coverage failure")
	}
	failedRaw := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "topic-1", MetricName: MetricTopicSubscriptionsCurrent,
		Kind: MetricKindGauge, Resolution: ResolutionRaw, From: 59_000, To: 60_000,
	})
	if len(failedRaw.DataPoints) != 0 || len(failedRaw.Coverage) != 0 {
		t.Fatalf("failed completion leaked zero or coverage: %#v", failedRaw)
	}
	assertTableCount(t, conn, "telemetry_terminal_state", 1)
	if _, err := conn.Exec(`DROP TRIGGER fail_terminal_rollup_coverage`); err != nil {
		t.Fatalf("drop terminal failure trigger: %v", err)
	}

	clock.Set(time.UnixMilli(61_500))
	afterMinute := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	if err := afterMinute.loadDurableTerminalReservations(ctx); err != nil {
		t.Fatalf("load retry state after minute advance: %v", err)
	}
	due = afterMinute.terminalStatesDue(62_000)
	if len(due) != 1 || due[0].TargetBucket == nil || *due[0].TargetBucket != 59_000 {
		t.Fatalf("retry state after minute advance = %#v, want stable target 59000", due)
	}
	if err := afterMinute.completeTerminalState(ctx, due[0]); err != nil {
		t.Fatalf("retry terminal completion: %v", err)
	}
	if err := afterMinute.completeTerminalState(ctx, due[0]); err != nil {
		t.Fatalf("repeat terminal completion: %v", err)
	}
	if err := store.Rollup(ctx, Resolution1m, 60_000); err != nil {
		t.Fatalf("roll up retried terminal zero: %v", err)
	}

	raw := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "topic-1", MetricName: MetricTopicSubscriptionsCurrent,
		Kind: MetricKindGauge, Resolution: ResolutionRaw, From: 59_000, To: 60_000,
	})
	if len(raw.DataPoints) != 1 || raw.DataPoints[0].Value != 0 || len(raw.Coverage) != 1 {
		t.Fatalf("terminal raw result = %#v, want exactly one covered zero", raw)
	}
	coarse := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "topic-1", MetricName: MetricTopicSubscriptionsCurrent,
		Kind: MetricKindGauge, Resolution: Resolution1m, From: 0, To: 60_000,
	})
	if len(coarse.DataPoints) != 1 || coarse.DataPoints[0].Value != 0 ||
		coarse.DataPoints[0].Last != 0 || len(coarse.Coverage) != 1 {
		t.Fatalf("terminal coarse result = %#v, want exactly one covered bucket ending at zero", coarse)
	}
	assertTableCount(t, conn, "telemetry_terminal_state", 0)
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

func TestDelayedCoordinatorLeavesSkippedRawBucketsUncovered(t *testing.T) {
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
	terminals       map[terminalKey]TerminalState
	enqueueStarted  chan struct{}
	enqueueRelease  chan struct{}
	enqueueErr      error
	rejectTerminal  bool
	listErr         error
	terminalSamples []MetricSample
	onEnqueue       func()
	completeStarted chan struct{}
	completeRelease chan struct{}
	completeOnce    sync.Once
}

func newTask9Store() *task9Store {
	return &task9Store{recordingStore: newRecordingStore(), terminals: make(map[terminalKey]TerminalState)}
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
	_ context.Context, state TerminalState, limit int,
) (bool, error) {
	if s.onEnqueue != nil {
		s.onEnqueue()
	}
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
	key := terminalKey{subjectID: state.SubjectID, generation: state.Generation}
	if _, exists := s.terminals[key]; exists {
		return true, nil
	}
	if len(s.terminals) >= limit {
		return false, nil
	}
	s.terminals[key] = state

	return true, nil
}

func (s *task9Store) CancelTerminalState(_ context.Context, subjectID string, generation int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.terminals, terminalKey{subjectID: subjectID, generation: generation})

	return nil
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
		if a.Generation < b.Generation {
			return -1
		}
		if a.Generation > b.Generation {
			return 1
		}

		return 0
	})

	return states, nil
}

func (s *task9Store) AssignTerminalBucket(
	_ context.Context, subjectID string, generation, targetBucket, sampleIntervalMS int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := terminalKey{subjectID: subjectID, generation: generation}
	state, exists := s.terminals[key]
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
	s.terminals[key] = state

	return nil
}

func (s *task9Store) CompleteTerminalState(
	_ context.Context, subjectID string, generation int64, sample MetricSample, _ CoverageBucket,
) error {
	s.completeOnce.Do(func() {
		if s.completeStarted != nil {
			close(s.completeStarted)
			<-s.completeRelease
		}
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	key := terminalKey{subjectID: subjectID, generation: generation}
	if _, exists := s.terminals[key]; !exists {
		return nil
	}
	s.terminalSamples = append(s.terminalSamples, sample)
	delete(s.terminals, key)

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

func mustQueryTask9Series(t *testing.T, store Store, query SeriesQuery) SeriesResult {
	t.Helper()
	result, err := store.QuerySeries(context.Background(), query)
	if err != nil {
		t.Fatalf("query %s/%s: %v", query.SubjectID, query.MetricName, err)
	}

	return result
}

func assertTask9CounterSeries(
	t *testing.T, store Store, query SeriesQuery, wantValues, wantDeltas []float64,
) {
	t.Helper()
	result := mustQueryTask9Series(t, store, query)
	if len(result.DataPoints) != len(wantValues) {
		t.Fatalf("%s/%s points = %#v, want values %v", query.SubjectID, query.MetricName, result, wantValues)
	}
	if len(result.Coverage) != len(wantValues) {
		t.Fatalf("%s/%s coverage = %#v, want %d buckets", query.SubjectID, query.MetricName, result.Coverage, len(wantValues))
	}
	for i, want := range wantValues {
		if got := result.DataPoints[i].Value; got != want {
			t.Fatalf("%s/%s value[%d] = %v, want %v", query.SubjectID, query.MetricName, i, got, want)
		}
	}
	if len(wantDeltas) != len(wantValues)-1 {
		t.Fatalf("invalid test fixture: %d deltas for %d values", len(wantDeltas), len(wantValues))
	}
	for i, want := range wantDeltas {
		previous := result.DataPoints[i].Value
		current := result.DataPoints[i+1].Value
		got := current - previous
		if current < previous {
			got = current
		}
		if got != want {
			t.Fatalf("%s/%s delta[%d] = %v, want %v", query.SubjectID, query.MetricName, i, got, want)
		}
	}
}

func task9QueueRewriteDistance(previous, current []string) int {
	maximum := max(len(previous), len(current))
	distance := 0
	for i := range maximum {
		if i >= len(previous) || i >= len(current) || previous[i] != current[i] {
			distance++
		}
	}

	return distance
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
func (s *recordingStore) LatestCollectionBoundary(context.Context, int64) (CollectionBoundaryState, error) {
	return CollectionBoundaryState{}, nil
}
func (s *recordingStore) Rollup(context.Context, Resolution, int64) error       { return nil }
func (s *recordingStore) ResetRawInterval(context.Context, int64) (bool, error) { return false, nil }
func (s *recordingStore) EnqueueTerminalState(context.Context, TerminalState, int) (bool, error) {
	return false, nil
}
func (s *recordingStore) CancelTerminalState(context.Context, string, int64) error { return nil }
func (s *recordingStore) ListTerminalStates(context.Context) ([]TerminalState, error) {
	return nil, nil
}
func (s *recordingStore) AssignTerminalBucket(context.Context, string, int64, int64, int64) error {
	return nil
}
func (s *recordingStore) CompleteTerminalState(context.Context, string, int64, MetricSample, CoverageBucket) error {
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
