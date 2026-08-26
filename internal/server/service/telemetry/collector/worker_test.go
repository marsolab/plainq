package collector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/service/telemetry"
)

func TestCalculateRatesDividesByActualElapsedSeconds(t *testing.T) {
	c, store := newRateTestCollector(time.Second)
	c.RecordSend("queue-1", 4, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))
	c.RecordSend("queue-1", 6, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(4_000))

	assertRateSample(t, store.lastBatch(t), "queue-1", MetricSendRate, 2, 3_000)
}

func TestCalculateRatesTreatsCounterResetAsNewEpoch(t *testing.T) {
	c, store := newRateTestCollector(time.Second)
	c.RecordSend("queue-1", 10, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))
	c.getOrCreateQueueMetrics("queue-1").messagesSent.Store(3)
	requireCalculateRatesAt(t, c, time.UnixMilli(2_000))

	assertRateSample(t, store.lastBatch(t), "queue-1", MetricSendRate, 3, 1_000)
}

func TestCalculateRatesRequiresKnownBaseline(t *testing.T) {
	c, store := newRateTestCollector(time.Second)
	c.RecordSend("queue-1", 4, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))

	assertMetricSampleAbsent(t, store.lastBatch(t), "queue-1", MetricSendRate)
}

func TestCalculateRatesPreservesNonWholeSecondWindowMS(t *testing.T) {
	c, store := newRateTestCollector(1_500 * time.Millisecond)
	c.RecordSend("queue-1", 2, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_500))
	c.RecordSend("queue-1", 3, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(3_000))

	assertRateSample(t, store.lastBatch(t), "queue-1", MetricSendRate, 2, 1_500)
}

func TestFailedRateWriteDoesNotCommitBaseline(t *testing.T) {
	c, store := newRateTestCollector(time.Second)
	sentinel := errors.New("write failed")
	store.saveErrors = []error{sentinel}
	c.RecordSend("queue-1", 5, 0)
	if err := c.calculateRatesAt(context.Background(), time.UnixMilli(1_000)); !errors.Is(err, sentinel) {
		t.Fatalf("first collection error = %v, want %v", err, sentinel)
	}

	c.RecordSend("queue-1", 5, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))
	requireCalculateRatesAt(t, c, time.UnixMilli(2_000))
	assertRateSample(t, store.lastBatch(t), "queue-1", MetricSendRate, 5, 1_000)
}

func TestSuccessfulRateWriteCommitsBaselineOnce(t *testing.T) {
	c, store := newRateTestCollector(time.Second)
	c.RecordSend("queue-1", 5, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))
	c.RecordSend("queue-1", 3, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(2_000))

	assertRateSample(t, store.lastBatch(t), "queue-1", MetricSendRate, 3, 1_000)
}

func TestFailedRateWriteLeavesGapWithoutSmearingNextBucket(t *testing.T) {
	c, store := newRateTestCollector(time.Second)
	c.RecordSend("queue-1", 2, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))
	c.RecordSend("queue-1", 6, 0)
	store.saveErrors = []error{errors.New("write failed")}
	if err := c.calculateRatesAt(context.Background(), time.UnixMilli(4_000)); err == nil {
		t.Fatal("delayed collection returned nil, want write failure")
	}
	requireCalculateRatesAt(t, c, time.UnixMilli(4_000))
	delayed := store.lastBatch(t)
	assertRateSample(t, delayed, "queue-1", MetricSendRate, 2, 3_000)
	assertMetricCoverageAbsent(t, delayed, "queue-1", MetricSendRate, MetricKindRate)

	c.RecordSend("queue-1", 2, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(5_000))
	next := store.lastBatch(t)
	assertRateSample(t, next, "queue-1", MetricSendRate, 2, 1_000)
	assertMetricCoverage(t, next, "queue-1", MetricSendRate, MetricKindRate)
}

func TestRateWritesSnapshotAndTypedRawHistoryTogether(t *testing.T) {
	store, conn := newTelemetryTestStoreWithConn(t)
	c := New(store, WithCollectionInterval(time.Second))
	c.RecordSend("queue-1", 2, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(1_000))
	c.RecordSend("queue-1", 3, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(2_000))

	result := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "queue-1", MetricName: MetricSendRate,
		Kind: MetricKindRate, Resolution: ResolutionRaw, From: 1_000, To: 2_000,
	})
	if len(result.DataPoints) != 1 || result.DataPoints[0].Value != 3 ||
		result.DataPoints[0].WindowMS != 1_000 || len(result.Coverage) != 1 {
		t.Fatalf("typed rate history = %#v, want one covered 3/s point over 1000ms", result)
	}

	var (
		snapshotRate   float64
		snapshotWindow int64
	)
	if err := conn.QueryRow(`SELECT rate_per_second, window_ms FROM rate_snapshots
WHERE queue_id = 'queue-1' AND metric_name = ? ORDER BY timestamp DESC, id DESC LIMIT 1`,
		MetricSendRate).Scan(&snapshotRate, &snapshotWindow); err != nil {
		t.Fatalf("query compatibility rate snapshot: %v", err)
	}
	if snapshotRate != 3 || snapshotWindow != 1_000 {
		t.Fatalf("compatibility snapshot = %v/%d, want 3/1000", snapshotRate, snapshotWindow)
	}
}

func TestCollectorOptionsExposeCollectionAndRetention(t *testing.T) {
	c := New(nil,
		WithCollectionInterval(2*time.Second),
		WithCleanupInterval(3*time.Minute),
		WithRetentionPeriod(48*time.Hour),
	)
	if got := c.CollectionInterval(); got != 2*time.Second {
		t.Fatalf("collection interval = %v", got)
	}
	if got := c.cleanupInterval; got != 3*time.Minute {
		t.Fatalf("cleanup interval = %v", got)
	}
	if got := c.RetentionPeriod(); got != 48*time.Hour {
		t.Fatalf("retention period = %v", got)
	}
}

func TestCollectionAlignsToConfiguredWallClockBucket(t *testing.T) {
	c, store := newRateTestCollector(2 * time.Second)
	c.RecordSend("queue-1", 1, 0)
	requireCalculateRatesAt(t, c, time.UnixMilli(4_000))

	batch := store.lastBatch(t)
	if batch.Boundary != 4_000 || batch.SampleIntervalMS != 2_000 {
		t.Fatalf("batch grid = boundary %d interval %d", batch.Boundary, batch.SampleIntervalMS)
	}
	for _, sample := range batch.Samples {
		if sample.Kind != MetricKindEvent && sample.Timestamp != 2_000 {
			t.Fatalf("periodic sample stamped outside closed bucket: %#v", sample)
		}
	}
	for _, coverage := range batch.Coverage {
		if coverage.BucketStart != 2_000 {
			t.Fatalf("coverage stamped outside closed bucket: %#v", coverage)
		}
	}
}

func TestAggregationCatchesUpBeforeWaitingForNextBoundary(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(90_500))
	requireCoordinatorPass(t, c, time.UnixMilli(90_500))

	assertCallsInOrder(t, store.callsSnapshot(), "list", "rollup:1m:60000",
		"rollup:1h:0", "rollup:1d:0", "reset:1000", "collect:90000")
}

func TestAggregationCatchUpRunsSourceBeforeDependentTier(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(90_061_000))
	requireCoordinatorPass(t, c, time.UnixMilli(90_061_000))

	assertCallsInOrder(t, store.callsSnapshot(), "rollup:1m:90060000",
		"rollup:1h:90000000", "rollup:1d:86400000")
}

func TestAggregationFailureStopsDependentTiersAndCleanup(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(59_500), WithCleanupInterval(time.Second))
	requireCoordinatorPass(t, c, time.UnixMilli(59_500))
	store.clearCalls()
	store.rollupErrors[Resolution1m] = errors.New("minute rollup failed")

	if err := c.runCoordinatorPass(context.Background(), time.UnixMilli(3_600_000)); err == nil {
		t.Fatal("coordinator returned nil, want minute rollup failure")
	}
	calls := store.callsSnapshot()
	if slices.ContainsFunc(calls, func(call string) bool {
		return call == "rollup:1h:3600000" || call == "rollup:1d:0" || call == "cleanup"
	}) {
		t.Fatalf("dependent work ran after minute failure: %v", calls)
	}
}

func TestStartupRollupFailureDoesNotResetRawInterval(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(60_500))
	store.rollupErrors[Resolution1m] = errors.New("minute rollup failed")

	if err := c.runCoordinatorPass(context.Background(), time.UnixMilli(60_500)); err == nil {
		t.Fatal("startup coordinator returned nil, want rollup failure")
	}
	calls := store.callsSnapshot()
	if slices.Contains(calls, "reset:1000") || slices.ContainsFunc(calls, func(call string) bool {
		return len(call) >= len("collect:") && call[:len("collect:")] == "collect:"
	}) {
		t.Fatalf("startup advanced into reset/collection after rollup failure: %v", calls)
	}
}

func TestFailedRawIntervalResetBlocksNewGridCollection(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(60_500))
	store.resetErr = errors.New("reset failed")

	if err := c.runCoordinatorPass(context.Background(), time.UnixMilli(60_500)); err == nil {
		t.Fatal("startup coordinator returned nil, want reset failure")
	}
	if calls := store.callsSnapshot(); slices.Contains(calls, "collect:60000") {
		t.Fatalf("new-grid collection ran after reset failure: %v", calls)
	}
}

func TestPersistentCoordinatorFailureUsesBoundedRetry(t *testing.T) {
	for _, tt := range []struct {
		interval time.Duration
		want     time.Duration
	}{
		{time.Millisecond, time.Second},
		{5 * time.Second, 5 * time.Second},
		{time.Minute, 30 * time.Second},
	} {
		if got := coordinatorRetryDelay(tt.interval); got != tt.want {
			t.Fatalf("retry delay for %v = %v, want %v", tt.interval, got, tt.want)
		}
	}
}

func TestCollectionClosesRawBeforeMinuteCheckpointAdvances(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(59_500))
	requireCoordinatorPass(t, c, time.UnixMilli(59_500))
	store.clearCalls()

	requireCoordinatorPass(t, c, time.UnixMilli(60_000))
	assertCallsInOrder(t, store.callsSnapshot(), "collect:60000", "rollup:1m:60000")
}

func TestCoordinatorDoesNotAdvancePastRetriedBoundary(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(1_500))
	store.saveErrors = []error{errors.New("boundary write failed")}
	if err := c.runCoordinatorPass(context.Background(), time.UnixMilli(1_500)); err == nil {
		t.Fatal("first coordinator pass returned nil, want boundary failure")
	}
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})
	c.terminalMu.Lock()
	terminalGeneration := c.terminalReservations["topic-1"].state.Generation
	c.terminalMu.Unlock()
	store.clearCalls()

	requireCoordinatorPass(t, c, time.UnixMilli(3_500))
	if c.lastTopicBoundary != 1_000 {
		t.Fatalf("retry advanced raw boundary to %d, want committed frozen boundary 1000", c.lastTopicBoundary)
	}
	for _, call := range store.callsSnapshot() {
		if call == fmt.Sprintf("complete:topic-1:%d", terminalGeneration) ||
			call == "rollup:1m:60000" || call == "cleanup" {
			t.Fatalf("dependent work ran past retried boundary: %v", store.callsSnapshot())
		}
	}

	requireCoordinatorPass(t, c, time.UnixMilli(3_500))
	if c.lastTopicBoundary != 3_000 {
		t.Fatalf("next pass raw boundary = %d, want latest closed 3000", c.lastTopicBoundary)
	}
	if !slices.Contains(store.callsSnapshot(), fmt.Sprintf("complete:topic-1:%d", terminalGeneration)) {
		t.Fatalf("terminal did not complete after its final boundary committed: %v", store.callsSnapshot())
	}
}

func TestCleanupCannotRaceOrderedRollups(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(59_500), WithCleanupInterval(time.Second))
	requireCoordinatorPass(t, c, time.UnixMilli(59_500))
	store.clearCalls()

	requireCoordinatorPass(t, c, time.UnixMilli(61_000))
	assertCallsInOrder(t, store.callsSnapshot(), "collect:61000", "rollup:1m:60000", "cleanup")
}

func TestAssignedTerminalFlushesBeforeStartupRollup(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(60_500))
	target, interval := int64(59_000), int64(1_000)
	state := TerminalState{
		SubjectID: "topic-1", Generation: 7, ObservedAt: 59_500,
		TargetBucket: &target, SampleIntervalMS: &interval,
	}
	store.mu.Lock()
	store.terminals[terminalKey{subjectID: state.SubjectID, generation: state.Generation}] = state
	store.mu.Unlock()

	requireCoordinatorPass(t, c, time.UnixMilli(60_500))
	assertCallsInOrder(t, store.callsSnapshot(), "list", "complete:topic-1:7", "rollup:1m:60000")
}

func TestPreDurableTerminalPromotionFailsThenRecoversInOrder(t *testing.T) {
	c, store := newCoordinatorTestCollector(time.UnixMilli(2_500))
	c.terminalMu.Lock()
	c.topicMu.Lock()
	generations := make([]int64, 0, 2)
	for _, subjectID := range []string{"topic-a", "topic-b"} {
		topic := &TopicMetrics{authoritative: false, terminalPending: true}
		c.topicMetrics[subjectID] = topic
		if !c.reserveTerminalLocked(subjectID, topic, 1_500) {
			t.Fatalf("reserve terminal %q", subjectID)
		}
		generations = append(generations, c.terminalReservations[subjectID].state.Generation)
	}
	c.topicMu.Unlock()
	c.terminalMu.Unlock()
	store.enqueueErr = errors.New("enqueue failed")

	if err := c.runCoordinatorPass(context.Background(), time.UnixMilli(2_500)); err == nil {
		t.Fatal("first promotion returned nil, want enqueue failure")
	}
	firstCall := fmt.Sprintf("enqueue:topic-a:%d", generations[0])
	secondCall := fmt.Sprintf("enqueue:topic-b:%d", generations[1])
	if calls := store.callsSnapshot(); !slices.Equal(calls, []string{firstCall}) {
		t.Fatalf("failed promotion calls = %v, want only FIFO head", calls)
	}

	store.enqueueErr = nil
	store.clearCalls()
	requireCoordinatorPass(t, c, time.UnixMilli(2_500))
	assertCallsInOrder(t, store.callsSnapshot(), firstCall, secondCall, "list")
}

func TestTerminalTopicRetryKeepsOriginalBucketAcrossMinuteBoundary(t *testing.T) {
	store := newTask9Store()
	clock := newTask9Clock(time.UnixMilli(59_500))
	c := New(store, WithCollectionInterval(time.Second), WithClock(clock.Now))
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 1},
	})
	c.RecordTopicState(telemetry.TopicStateEvent{TopicsExist: 0, Subscriptions: map[string]int64{}})
	if err := c.promoteTerminalStates(context.Background()); err != nil {
		t.Fatalf("promote terminal: %v", err)
	}
	if err := c.assignTerminalStates(context.Background(), 60_000); err != nil {
		t.Fatalf("assign terminal: %v", err)
	}
	clock.Set(time.UnixMilli(61_500))
	if err := c.assignTerminalStates(context.Background(), 62_000); err != nil {
		t.Fatalf("repeat assignment: %v", err)
	}
	due := c.terminalStatesDue(62_000)
	if len(due) != 1 || due[0].TargetBucket == nil || *due[0].TargetBucket != 59_000 {
		t.Fatalf("terminal retry target = %#v, want original bucket 59000", due)
	}
}

func TestCleanupUsesConfiguredIntervalAndTierCutoffs(t *testing.T) {
	now := time.UnixMilli((72 * time.Hour).Milliseconds())
	c, store := newCoordinatorTestCollector(now,
		WithCleanupInterval(time.Second), WithRetentionPeriod(48*time.Hour))
	requireCoordinatorPass(t, c, now)
	store.clearCalls()
	requireCoordinatorPass(t, c, now.Add(time.Second))

	got := store.cleanupCutoffsSnapshot()
	want := []int64{
		now.Add(time.Second).Add(-time.Hour - time.Second).UnixMilli(),
		now.Add(time.Second).Add(-24*time.Hour - time.Minute).UnixMilli(),
		now.Add(time.Second).Add(-48*time.Hour - 5*time.Minute).UnixMilli(),
		now.Add(time.Second).Add(-48*time.Hour - time.Hour).UnixMilli(),
		now.Add(time.Second).Add(-48*time.Hour - 24*time.Hour).UnixMilli(),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("cleanup cutoffs = %v, want %v", got, want)
	}
}

func TestCleanupRetainsOneCompletedSourceBucket(t *testing.T) {
	now := time.UnixMilli((30 * 24 * time.Hour).Milliseconds())
	c, store := newCoordinatorTestCollector(now,
		WithCleanupInterval(time.Second), WithRetentionPeriod(24*time.Hour))
	requireCoordinatorPass(t, c, now)
	store.clearCalls()
	requireCoordinatorPass(t, c, now.Add(time.Second))

	cutoffs := store.cleanupCutoffsSnapshot()
	if cutoffs[0] != now.Add(time.Second).Add(-time.Hour-time.Second).UnixMilli() ||
		cutoffs[1] != now.Add(time.Second).Add(-24*time.Hour-time.Minute).UnixMilli() ||
		cutoffs[3] != now.Add(time.Second).Add(-24*time.Hour-time.Hour).UnixMilli() ||
		cutoffs[4] != now.Add(time.Second).Add(-48*time.Hour).UnixMilli() {
		t.Fatalf("produced-tier source-bucket cutoffs = %v", cutoffs)
	}
}

func TestCleanupRetainsLegacyFiveMinuteCompatibilityWindow(t *testing.T) {
	now := time.UnixMilli((30 * 24 * time.Hour).Milliseconds())
	c, store := newCoordinatorTestCollector(now,
		WithCleanupInterval(time.Second), WithRetentionPeriod(24*time.Hour))
	requireCoordinatorPass(t, c, now)
	store.clearCalls()
	requireCoordinatorPass(t, c, now.Add(time.Second))

	if got, want := store.cleanupCutoffsSnapshot()[2],
		now.Add(time.Second).Add(-24*time.Hour-5*time.Minute).UnixMilli(); got != want {
		t.Fatalf("legacy 5m cutoff = %d, want %d", got, want)
	}
}

func TestWorkersStopWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := New(nil, WithCollectionInterval(time.Hour))
	c.Start(ctx)
	c.Start(ctx)
	cancel()

	done := make(chan struct{})
	go func() {
		c.Stop()
		c.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collector workers did not join after context cancellation")
	}
}

func TestRawIntervalChangeCatchesUpThenCreatesExplicitGap(t *testing.T) {
	ctx := context.Background()
	store, conn := newTelemetryTestStoreWithConn(t)
	if reset, err := store.ResetRawInterval(ctx, 1_000); err != nil || !reset {
		t.Fatalf("seed raw interval reset = %t, %v", reset, err)
	}
	seedLegacyCollectionBoundary(t, store)

	c := New(store, WithCollectionInterval(2*time.Second), WithClock(func() time.Time {
		return time.UnixMilli(60_000)
	}))
	requireCoordinatorPass(t, c, time.UnixMilli(60_000))

	var intervalMS int64
	if err := conn.QueryRow(`SELECT raw_sample_interval_ms FROM telemetry_collection_state WHERE singleton = 1`).Scan(
		&intervalMS,
	); err != nil {
		t.Fatalf("query changed raw interval: %v", err)
	}
	if intervalMS != 2_000 {
		t.Fatalf("raw interval = %d, want 2000", intervalMS)
	}
	raw := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "legacy", MetricName: MetricMessagesSentTotal,
		Kind: MetricKindCounter, Resolution: ResolutionRaw, From: 0, To: 60_000,
	})
	if len(raw.DataPoints) != 0 || len(raw.Coverage) != 0 {
		t.Fatalf("old raw grid survived interval reset: %#v", raw)
	}
	rolled := mustQuerySeries(t, store, SeriesQuery{
		SubjectID: "legacy", MetricName: MetricMessagesSentTotal,
		Kind: MetricKindCounter, Resolution: Resolution1m, From: 0, To: 60_000,
	})
	if len(rolled.DataPoints) != 1 {
		t.Fatalf("old-grid catch-up was not retained before reset: %#v", rolled)
	}
}

func TestSameRawIntervalRestartPreservesGridAndHistory(t *testing.T) {
	ctx := context.Background()
	store, conn := newTelemetryTestStoreWithConn(t)
	if reset, err := store.ResetRawInterval(ctx, 1_000); err != nil || !reset {
		t.Fatalf("seed raw interval reset = %t, %v", reset, err)
	}
	seedLegacyCollectionBoundary(t, store)

	c := New(store, WithCollectionInterval(time.Second), WithClock(func() time.Time {
		return time.UnixMilli(2_500)
	}))
	requireCoordinatorPass(t, c, time.UnixMilli(2_500))

	var (
		intervalMS int64
		legacyRows int
	)
	if err := conn.QueryRow(`SELECT raw_sample_interval_ms FROM telemetry_collection_state WHERE singleton = 1`).Scan(
		&intervalMS,
	); err != nil {
		t.Fatalf("query stable raw interval: %v", err)
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM metrics_raw WHERE queue_id = 'legacy'`).Scan(&legacyRows); err != nil {
		t.Fatalf("count preserved legacy rows: %v", err)
	}
	if intervalMS != 1_000 || legacyRows != 1 {
		t.Fatalf("stable restart interval=%d legacyRows=%d, want 1000/1", intervalMS, legacyRows)
	}
}

func seedLegacyCollectionBoundary(t *testing.T, store *SQLiteStore) {
	t.Helper()
	sample := MetricSample{
		Timestamp: 1_000, SubjectID: "legacy", MetricName: MetricMessagesSentTotal,
		Kind: MetricKindCounter, Value: 7,
	}
	if err := store.SaveCollectionBoundary(context.Background(), CollectionBatch{
		Boundary: 2_000, SampleIntervalMS: 1_000,
		Samples: []MetricSample{sample},
		Coverage: []CoverageBucket{{
			Resolution: ResolutionRaw, BucketStart: 1_000,
			SubjectID: "legacy", MetricName: MetricMessagesSentTotal,
			Kind: MetricKindCounter, SampleIntervalMS: 1_000,
		}},
	}); err != nil {
		t.Fatalf("seed legacy collection boundary: %v", err)
	}
}

func newRateTestCollector(interval time.Duration) (*Collector, *task9Store) {
	store := newTask9Store()
	c := New(store, WithCollectionInterval(interval))

	return c, store
}

func requireCalculateRatesAt(t *testing.T, c *Collector, now time.Time) {
	t.Helper()
	if err := c.calculateRatesAt(context.Background(), now); err != nil {
		t.Fatalf("calculate rates at %v: %v", now, err)
	}
}

func assertRateSample(
	t *testing.T, batch CollectionBatch, subjectID, metricName string, value float64, windowMS int64,
) {
	t.Helper()
	for _, sample := range batch.Samples {
		if sample.SubjectID == subjectID && sample.MetricName == metricName && sample.Kind == MetricKindRate &&
			sample.Value == value && sample.WindowMS == windowMS {
			return
		}
	}
	t.Fatalf("rate sample %q/%q value=%v window=%d absent from %#v",
		subjectID, metricName, value, windowMS, batch.Samples)
}

func assertMetricSampleAbsent(t *testing.T, batch CollectionBatch, subjectID, metricName string) {
	t.Helper()
	for _, sample := range batch.Samples {
		if sample.SubjectID == subjectID && sample.MetricName == metricName {
			t.Fatalf("sample %q/%q unexpectedly present as %#v", subjectID, metricName, sample)
		}
	}
}

func assertMetricCoverage(
	t *testing.T, batch CollectionBatch, subjectID, metricName string, kind MetricKind,
) {
	t.Helper()
	for _, coverage := range batch.Coverage {
		if coverage.SubjectID == subjectID && coverage.MetricName == metricName && coverage.Kind == kind {
			return
		}
	}
	t.Fatalf("coverage %q/%q/%q absent from %#v", subjectID, metricName, kind, batch.Coverage)
}

func assertMetricCoverageAbsent(
	t *testing.T, batch CollectionBatch, subjectID, metricName string, kind MetricKind,
) {
	t.Helper()
	for _, coverage := range batch.Coverage {
		if coverage.SubjectID == subjectID && coverage.MetricName == metricName && coverage.Kind == kind {
			t.Fatalf("coverage %q/%q/%q unexpectedly present as %#v", subjectID, metricName, kind, coverage)
		}
	}
}

type coordinatorStore struct {
	*task9Store

	coordMu        sync.Mutex
	calls          []string
	rollupErrors   map[Resolution]error
	resetErr       error
	cleanupErr     error
	cleanupCutoffs []int64
}

func newCoordinatorStore() *coordinatorStore {
	return &coordinatorStore{
		task9Store: newTask9Store(), rollupErrors: make(map[Resolution]error),
	}
}

func (s *coordinatorStore) recordCall(call string) {
	s.coordMu.Lock()
	s.calls = append(s.calls, call)
	s.coordMu.Unlock()
}

func (s *coordinatorStore) callsSnapshot() []string {
	s.coordMu.Lock()
	defer s.coordMu.Unlock()

	return append([]string(nil), s.calls...)
}

func (s *coordinatorStore) clearCalls() {
	s.coordMu.Lock()
	s.calls = nil
	s.coordMu.Unlock()
}

func (s *coordinatorStore) SaveCollectionBoundary(ctx context.Context, batch CollectionBatch) error {
	s.recordCall(fmt.Sprintf("collect:%d", batch.Boundary))

	return s.task9Store.SaveCollectionBoundary(ctx, batch)
}

func (s *coordinatorStore) Rollup(_ context.Context, resolution Resolution, closedThrough int64) error {
	s.recordCall(fmt.Sprintf("rollup:%s:%d", resolution, closedThrough))

	return s.rollupErrors[resolution]
}

func (s *coordinatorStore) ResetRawInterval(_ context.Context, intervalMS int64) (bool, error) {
	s.recordCall(fmt.Sprintf("reset:%d", intervalMS))

	return s.resetErr == nil, s.resetErr
}

func (s *coordinatorStore) CleanupOldMetrics(
	_ context.Context, rawBefore, m1Before, m5Before, h1Before, d1Before int64,
) error {
	s.coordMu.Lock()
	s.cleanupCutoffs = []int64{rawBefore, m1Before, m5Before, h1Before, d1Before}
	s.coordMu.Unlock()
	s.recordCall("cleanup")

	return s.cleanupErr
}

func (s *coordinatorStore) cleanupCutoffsSnapshot() []int64 {
	s.coordMu.Lock()
	defer s.coordMu.Unlock()

	return append([]int64(nil), s.cleanupCutoffs...)
}

func (s *coordinatorStore) EnqueueTerminalState(
	ctx context.Context, state TerminalState, limit int,
) (bool, error) {
	s.recordCall(fmt.Sprintf("enqueue:%s:%d", state.SubjectID, state.Generation))

	return s.task9Store.EnqueueTerminalState(ctx, state, limit)
}

func (s *coordinatorStore) CompleteTerminalState(
	ctx context.Context, subjectID string, generation int64, sample MetricSample, coverage CoverageBucket,
) error {
	s.recordCall(fmt.Sprintf("complete:%s:%d", subjectID, generation))

	return s.task9Store.CompleteTerminalState(ctx, subjectID, generation, sample, coverage)
}

func (s *coordinatorStore) ListTerminalStates(ctx context.Context) ([]TerminalState, error) {
	s.recordCall("list")

	return s.task9Store.ListTerminalStates(ctx)
}

func newCoordinatorTestCollector(now time.Time, opts ...Option) (*Collector, *coordinatorStore) {
	store := newCoordinatorStore()
	allOptions := []Option{WithCollectionInterval(time.Second), WithClock(func() time.Time { return now })}
	allOptions = append(allOptions, opts...)
	c := New(store, allOptions...)
	store.clearCalls()

	return c, store
}

func requireCoordinatorPass(t *testing.T, c *Collector, now time.Time) {
	t.Helper()
	if err := c.runCoordinatorPass(context.Background(), now); err != nil {
		t.Fatalf("coordinator pass at %v: %v", now, err)
	}
}

func assertCallsInOrder(t *testing.T, calls []string, expected ...string) {
	t.Helper()
	position := 0
	for _, call := range calls {
		if position < len(expected) && call == expected[position] {
			position++
		}
	}
	if position != len(expected) {
		t.Fatalf("calls = %v, want ordered subsequence %v", calls, expected)
	}
}
