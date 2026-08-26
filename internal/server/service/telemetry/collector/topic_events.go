package collector

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
)

var _ telemetry.TopicRecorder = (*Collector)(nil)

type operationResultKey struct {
	backend   string
	operation string
	result    string
}

type operationResultLabels struct {
	Backend   string `json:"backend"`
	Operation string `json:"operation"`
	Result    string `json:"result"`
}

type operationDurationLabels struct {
	Backend   string `json:"backend"`
	Operation string `json:"operation"`
}

type topicAccumulator struct {
	requests   map[operationResultKey]uint64
	operations map[operationResultKey]uint64

	messagesPublished    uint64
	publishedBytes       uint64
	deliveries           uint64
	deliveryFailures     uint64
	subscriptionsCreated uint64
	subscriptionsDeleted uint64

	baseline topicBaseline
	rates    TopicRates

	revision          uint64
	committedRevision uint64
}

type TopicMetrics struct {
	topicAccumulator

	subscriptionsCurrent int64
	subscriptionsKnown   bool
	authoritative        bool
	terminalPending      bool
	terminalGeneration   int64
	lastUpdated          int64
	cacheElement         *list.Element
}

type TopicSystemMetrics struct {
	topicAccumulator

	subscriptionsCurrent int64
	subscriptionsKnown   bool
	topicsExist          int64
	topicsKnown          bool
}

type topicBaseline struct {
	boundary             int64
	messagesPublished    uint64
	publishedBytes       uint64
	deliveries           uint64
	deliveryFailures     uint64
	subscriptionsCreated uint64
	subscriptionsDeleted uint64
	revision             uint64
}

type topicCache struct {
	attributed *list.List
}

func newTopicCache() *topicCache { return &topicCache{attributed: list.New()} }

type dirtyInterval struct {
	fromBucket int64
	toBucket   int64
}

type frozenTopicBoundary struct {
	boundary         int64
	batch            CollectionBatch
	eventCount       int
	queueBaselines   map[string]queueRateBaselines
	queueRates       map[string]Rates
	queueMetrics     map[string]*QueueMetrics
	systemQueue      queueRateBaselines
	systemQueueRates Rates
	baselines        map[string]topicBaseline
	rates            map[string]TopicRates
	accumulators     map[string]*topicAccumulator
	systemBaseline   topicBaseline
	systemRates      TopicRates
}

type terminalKey struct {
	subjectID  string
	generation int64
}

type terminalOperation uint8

const (
	terminalEnqueue terminalOperation = iota
	terminalCancel
)

type terminalReservation struct {
	state     TerminalState
	durable   bool
	canceled  bool
	operation terminalOperation
	element   *list.Element
	inFlight  bool
}

var (
	topicBackends = []string{
		metrics.BackendSQLite,
		metrics.BackendTurso,
		metrics.BackendPostgres,
		metrics.BackendCluster,
	}
	topicOperations = []string{
		metrics.OpListTopics,
		metrics.OpCreateTopic,
		metrics.OpDeleteTopic,
		metrics.OpSubscribe,
		metrics.OpUnsubscribe,
		metrics.OpPublish,
	}
	topicResults = []string{metrics.ResultOK, metrics.ResultError}
)

// RecordTopicRequest records one decoded request without conflating it with storage work.
func (c *Collector) RecordTopicRequest(event telemetry.TopicOperationEvent) {
	c.recordTopicOperationEvent(event, false)
}

// RecordTopicOperation records one storage operation separately from its request.
func (c *Collector) RecordTopicOperation(event telemetry.TopicOperationEvent) {
	c.recordTopicOperationEvent(event, true)
}

//nolint:nestif // System and optional topic attribution must stay in one cutover critical section.
func (c *Collector) recordTopicOperationEvent(event telemetry.TopicOperationEvent, storage bool) {
	validateTopicOperationEvent(event)
	durationLabels := canonicalDurationLabels(event.Backend, event.Operation)
	key := operationResultKey{backend: event.Backend, operation: event.Operation, result: event.Result}
	metricName := MetricTopicRequestsTotal
	durationName := MetricTopicRequestDuration

	if storage {
		metricName = MetricTopicOperationsTotal
		durationName = MetricTopicOperationDuration
	}

	var dropped []string

	c.cutoverMu.Lock()
	now := c.stampedNowLocked()
	c.topicMu.Lock()

	accumulator := &c.topicSystem.topicAccumulator
	if storage {
		accumulator.operations = incrementOperationCounter(accumulator.operations, key)
	} else {
		accumulator.requests = incrementOperationCounter(accumulator.requests, key)
	}

	var topicTracked bool

	if event.TopicID != "" {
		m, ok := c.ensureTopicLocked(event.TopicID, false)

		topicTracked = ok
		if ok {
			if storage {
				m.operations = incrementOperationCounter(m.operations, key)
			} else {
				m.requests = incrementOperationCounter(m.requests, key)
			}

			m.revision++
			m.lastUpdated = now
		} else {
			c.markTopicDirtyLocked(event.TopicID, metricName, now)
			c.markTopicDirtyLocked(event.TopicID, durationName, now)
			dropped = append(dropped, metricName, durationName)
		}
	}
	c.topicMu.Unlock()

	if c.enqueueAttributedEventLocked(now, event.TopicID, topicTracked, durationName, event.Duration.Seconds(), durationLabels) {
		dropped = append(dropped, durationName)
	}
	c.cutoverMu.Unlock()
	c.recordEventDrops(dropped)
}

// RecordTopicPublish records all known publish effects and one selected-fanout event.
func (c *Collector) RecordTopicPublish(event telemetry.TopicPublishEvent) {
	var dropped []string

	c.cutoverMu.Lock()
	now := c.stampedNowLocked()
	c.topicMu.Lock()
	addPublish(&c.topicSystem.topicAccumulator, event)

	var topicTracked bool

	if event.TopicID != "" {
		m, ok := c.ensureTopicLocked(event.TopicID, false)

		topicTracked = ok
		if ok {
			addPublish(&m.topicAccumulator, event)
			m.revision++
			m.lastUpdated = now
		} else {
			for _, metricName := range []string{
				MetricTopicMessagesPublishedTotal,
				MetricTopicPublishedBytesTotal,
				MetricTopicDeliveriesTotal,
				MetricTopicDeliveryFailuresTotal,
				MetricTopicFanout,
			} {
				c.markTopicDirtyLocked(event.TopicID, metricName, now)
				dropped = append(dropped, metricName)
			}
		}
	}
	c.topicMu.Unlock()

	if c.enqueueAttributedEventLocked(now, event.TopicID, topicTracked, MetricTopicFanout, float64(event.Destinations), "") {
		dropped = append(dropped, MetricTopicFanout)
	}
	c.cutoverMu.Unlock()
	c.recordEventDrops(dropped)
}

func addPublish(accumulator *topicAccumulator, event telemetry.TopicPublishEvent) {
	accumulator.messagesPublished += event.Messages
	accumulator.publishedBytes += event.Bytes
	accumulator.deliveries += event.Delivered
	accumulator.deliveryFailures += event.Failed
}

// RecordTopicSubscriptionCreated records lifecycle only; reconciliation owns exact gauges.
func (c *Collector) RecordTopicSubscriptionCreated(topicID string) {
	c.recordTopicLifecycle(topicID, true)
}

// RecordTopicSubscriptionDeleted records lifecycle only; reconciliation owns exact gauges.
func (c *Collector) RecordTopicSubscriptionDeleted(topicID string) {
	c.recordTopicLifecycle(topicID, false)
}

func (c *Collector) recordTopicLifecycle(topicID string, created bool) {
	metricName := MetricTopicSubscriptionsDeletedTotal
	if created {
		metricName = MetricTopicSubscriptionsCreatedTotal
	}

	c.cutoverMu.Lock()
	now := c.stampedNowLocked()
	c.topicMu.Lock()
	incrementTopicLifecycle(&c.topicSystem.topicAccumulator, created)

	var dropped bool

	if topicID != "" {
		m, ok := c.ensureTopicLocked(topicID, false)
		if ok {
			incrementTopicLifecycle(&m.topicAccumulator, created)
			m.revision++
			m.lastUpdated = now
		} else {
			c.markTopicDirtyLocked(topicID, metricName, now)
		}

		dropped = !ok
	}
	c.topicMu.Unlock()
	c.cutoverMu.Unlock()

	if dropped {
		metrics.RecordTelemetryEventBufferDropped(metricName)
	}
}

func incrementTopicLifecycle(accumulator *topicAccumulator, created bool) {
	if created {
		accumulator.subscriptionsCreated++

		return
	}

	accumulator.subscriptionsDeleted++
}

// RecordTopicState installs authoritative gauge state and reserves terminal work for removals.
//
//nolint:cyclop // Exact reconciliation deliberately keeps removal, bounded admission, and exact gauges together.
func (c *Collector) RecordTopicState(event telemetry.TopicStateEvent) {
	var (
		terminalDrops uint64
		stateDrops    uint64
	)

	// State reconciliation takes the terminal lock before the callback locks so
	// terminal maintenance can never make ordinary event callbacks wait behind
	// backlog-sized work while they hold cutoverMu.
	c.terminalMu.Lock()
	c.cutoverMu.Lock()
	now := c.stampedNowLocked()
	c.topicMu.Lock()

	for topicID, current := range c.topicMetrics {
		if !current.authoritative || current.terminalPending {
			continue
		}

		if _, exists := event.Subscriptions[topicID]; !exists {
			current.authoritative = false
			current.subscriptionsKnown = false
			current.terminalPending = true

			if !c.reserveTerminalLocked(topicID, current, now) {
				c.deleteTopicLocked(topicID)

				terminalDrops++
			}
		}
	}

	var subscriptionsTotal int64

	for topicID, currentCount := range event.Subscriptions {
		if currentCount >= 0 {
			subscriptionsTotal += currentCount
		}

		generation := c.cancelTerminalLocked(topicID)

		m, ok := c.ensureTopicLocked(topicID, true)
		if !ok {
			stateDrops++

			continue
		}

		m.authoritative = true

		m.terminalPending = false
		if generation > m.terminalGeneration {
			m.terminalGeneration = generation
		}

		m.subscriptionsKnown = currentCount >= 0
		if currentCount >= 0 {
			m.subscriptionsCurrent = currentCount
		}

		m.lastUpdated = now
	}

	c.topicSystem.topicsExist = event.TopicsExist
	c.topicSystem.topicsKnown = true
	c.topicSystem.subscriptionsCurrent = subscriptionsTotal
	c.topicSystem.subscriptionsKnown = true
	c.topicMu.Unlock()
	c.cutoverMu.Unlock()
	c.terminalMu.Unlock()

	if terminalDrops > 0 {
		metrics.RecordTelemetryTerminalStateDropped(terminalDrops)
	}

	if stateDrops > 0 {
		metrics.RecordTelemetryEventBufferDrops(MetricTopicSubscriptionsCurrent, stateDrops)
	}
}

// RecordTopicStateUnavailable invalidates gauges but preserves membership and counters.
func (c *Collector) RecordTopicStateUnavailable() {
	c.cutoverMu.Lock()
	_ = c.stampedNowLocked()
	c.topicMu.Lock()
	c.topicSystem.topicsKnown = false

	c.topicSystem.subscriptionsKnown = false
	for _, current := range c.topicMetrics {
		if current.authoritative {
			current.subscriptionsKnown = false
		}
	}
	c.topicMu.Unlock()
	c.cutoverMu.Unlock()
}

//nolint:cyclop // Admission, LRU promotion, and bounded safe eviction are one cache invariant.
func (c *Collector) ensureTopicLocked(topicID string, authoritative bool) (*TopicMetrics, bool) {
	if current, exists := c.topicMetrics[topicID]; exists {
		if authoritative && !current.authoritative {
			if current.cacheElement != nil {
				c.topicCache.attributed.Remove(current.cacheElement)
			}

			current.cacheElement = nil
			current.authoritative = true
		} else if !current.authoritative && current.cacheElement != nil {
			c.topicCache.attributed.MoveToBack(current.cacheElement)
		}

		return current, true
	}

	if c.topicLimit <= 0 {
		return nil, false
	}

	if len(c.topicMetrics) >= c.topicLimit {
		oldest := c.topicCache.attributed.Front()
		if oldest == nil {
			return nil, false
		}

		oldestTopicID, ok := oldest.Value.(string)
		if !ok {
			panic("collector: non-string topic cache key")
		}

		oldestMetrics, exists := c.topicMetrics[oldestTopicID]
		if !exists {
			panic("collector: topic cache key missing from metrics map")
		}

		if oldestMetrics.revision != oldestMetrics.committedRevision {
			return nil, false
		}

		c.deleteTopicLocked(oldestTopicID)
	}

	current := &TopicMetrics{authoritative: authoritative}
	if !authoritative {
		current.cacheElement = c.topicCache.attributed.PushBack(topicID)
	}

	c.topicMetrics[topicID] = current

	return current, true
}

func (c *Collector) deleteTopicLocked(topicID string) {
	current, exists := c.topicMetrics[topicID]
	if !exists {
		return
	}

	if current.cacheElement != nil {
		c.topicCache.attributed.Remove(current.cacheElement)
	}

	delete(c.topicMetrics, topicID)
}

func incrementOperationCounter(
	target map[operationResultKey]uint64, key operationResultKey,
) map[operationResultKey]uint64 {
	if target == nil {
		target = make(map[operationResultKey]uint64)
	}

	target[key]++

	return target
}

func validateTopicOperationEvent(event telemetry.TopicOperationEvent) {
	if !stringIn(event.Backend, topicBackends) || !stringIn(event.Operation, topicOperations) ||
		!stringIn(event.Result, topicResults) {
		panic("collector: unknown topic metric vocabulary")
	}
}

func stringIn(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}

	return false
}

func canonicalResultLabels(backend, operation, result string) string {
	encoded, err := json.Marshal(operationResultLabels{Backend: backend, Operation: operation, Result: result})
	if err != nil {
		panic(err)
	}

	return string(encoded)
}

func canonicalDurationLabels(backend, operation string) string {
	encoded, err := json.Marshal(operationDurationLabels{Backend: backend, Operation: operation})
	if err != nil {
		panic(err)
	}

	return string(encoded)
}

func (c *Collector) stampedNowLocked() int64 {
	now := c.now().UnixMilli()
	if now < c.eventWatermark {
		return c.eventWatermark
	}

	return now
}

func (c *Collector) enqueueAttributedEventLocked(
	timestamp int64, topicID string, topicTracked bool, metricName string, value float64, labels string,
) bool {
	required := 1
	if topicID != "" && topicTracked {
		required++
	}

	used := len(c.eventQueue)
	if c.frozenBoundary != nil {
		used += c.frozenBoundary.eventCount
	}

	if required > c.eventBufferLimit-used {
		c.markEventDirtyLocked(metricName, timestamp)

		return true
	}

	c.eventQueue = append(c.eventQueue, MetricSample{
		Timestamp: timestamp, MetricName: metricName, Kind: MetricKindEvent, Value: value, Labels: labels,
	})
	if topicID != "" && topicTracked {
		c.eventQueue = append(c.eventQueue, MetricSample{
			Timestamp: timestamp, SubjectID: topicID, MetricName: metricName,
			Kind: MetricKindEvent, Value: value, Labels: labels,
		})
	}

	return false
}

func (c *Collector) markEventDirtyLocked(metricName string, timestamp int64) {
	extendDirtyInterval(c.eventDirty, metricName, c.topicBucket(timestamp))
}

func (c *Collector) markTopicDirtyLocked(subjectID, metricName string, timestamp int64) {
	if subjectID == "" {
		return
	}

	bucket := c.topicBucket(timestamp)

	metricsByName, exists := c.topicDirty[subjectID]
	if !exists {
		if c.topicLimit <= 0 || len(c.topicDirty) >= c.topicLimit {
			extendDirtyInterval(c.topicDirtyOverflow, metricName, bucket)

			return
		}

		metricsByName = make(map[string]dirtyInterval)
		c.topicDirty[subjectID] = metricsByName
	}

	extendDirtyInterval(metricsByName, metricName, bucket)
}

func (c *Collector) topicBucket(timestamp int64) int64 {
	intervalMS := c.collectionInterval.Milliseconds()
	if intervalMS <= 0 {
		intervalMS = rateWindowMS
	}

	return timestamp - timestamp%intervalMS
}

func extendDirtyInterval(intervals map[string]dirtyInterval, metricName string, bucket int64) {
	current, exists := intervals[metricName]
	if !exists {
		intervals[metricName] = dirtyInterval{fromBucket: bucket, toBucket: bucket}

		return
	}

	if bucket < current.fromBucket {
		current.fromBucket = bucket
	}

	if bucket > current.toBucket {
		current.toBucket = bucket
	}

	intervals[metricName] = current
}

func (c *Collector) recordEventDrops(metricNames []string) {
	counts := make(map[string]uint64, len(metricNames))
	for _, metricName := range metricNames {
		counts[metricName]++
	}

	for metricName, count := range counts {
		metrics.RecordTelemetryEventBufferDrops(metricName, count)
	}
}

// collectTopicBoundary freezes and atomically persists one closed topic boundary.
func (c *Collector) collectTopicBoundary(ctx context.Context, boundary int64) error {
	intervalMS := c.collectionInterval.Milliseconds()
	if intervalMS <= 0 || boundary <= 0 || boundary%intervalMS != 0 {
		return errors.New("collect topic boundary: boundary must align to a positive collection interval")
	}

	c.cutoverMu.Lock()
	if c.frozenBoundary == nil {
		if boundary <= c.lastTopicBoundary {
			c.cutoverMu.Unlock()

			return nil
		}

		if boundary < c.eventWatermark {
			c.cutoverMu.Unlock()

			return errors.New("collect topic boundary: boundary precedes event watermark")
		}

		c.eventWatermark = boundary
		c.queueMu.RLock()
		c.topicMu.Lock()
		c.frozenBoundary = c.freezeTopicBoundaryLocked(boundary, intervalMS)
		c.topicMu.Unlock()
		c.queueMu.RUnlock()
	}

	frozen := c.frozenBoundary
	c.cutoverMu.Unlock()

	if c.store != nil {
		err := c.store.SaveCollectionBoundary(ctx, frozen.batch)
		c.persist(metrics.TelemetryOpCollectionBoundary, err)

		if err != nil {
			return fmt.Errorf("collect topic boundary: %w", err)
		}
	}

	c.cutoverMu.Lock()
	defer c.cutoverMu.Unlock()

	if c.frozenBoundary != frozen {
		return nil
	}

	c.topicMu.Lock()
	c.finalizeTopicBoundaryLocked(frozen)
	c.topicMu.Unlock()
	c.queueMu.Lock()
	c.finalizeQueueBoundaryLocked(frozen)
	c.queueMu.Unlock()
	c.lastTopicBoundary = frozen.boundary
	c.frozenBoundary = nil
	c.advanceDirtyAfterBoundaryLocked(frozen.boundary)

	return nil
}

//nolint:cyclop // Freezing atomically enumerates events, topics, queues, and coverage in one cutover.
func (c *Collector) freezeTopicBoundaryLocked(boundary, intervalMS int64) *frozenTopicBoundary {
	bucketStart := boundary - intervalMS
	due := make([]MetricSample, 0, len(c.eventQueue))

	future := make([]MetricSample, 0, len(c.eventQueue))
	for _, sample := range c.eventQueue {
		if sample.Timestamp < boundary {
			due = append(due, sample)
		} else {
			future = append(future, sample)
		}
	}

	c.eventQueue = future

	frozen := &frozenTopicBoundary{
		boundary: boundary,
		batch: CollectionBatch{
			Boundary: boundary, SampleIntervalMS: intervalMS,
			Samples: append([]MetricSample(nil), due...),
		},
		eventCount:     len(due),
		queueBaselines: make(map[string]queueRateBaselines, len(c.queueMetrics)),
		queueRates:     make(map[string]Rates, len(c.queueMetrics)),
		queueMetrics:   make(map[string]*QueueMetrics, len(c.queueMetrics)),
		baselines:      make(map[string]topicBaseline, len(c.topicMetrics)),
		rates:          make(map[string]TopicRates, len(c.topicMetrics)),
		accumulators:   make(map[string]*topicAccumulator, len(c.topicMetrics)),
	}

	subjectComplete := make(map[string]bool, len(c.topicMetrics)+len(c.queueMetrics)+1)
	subjectSeen := make(map[string]bool, len(c.topicMetrics)+len(c.queueMetrics)+1)
	markSubject := func(subjectID string, complete bool) {
		if subjectSeen[subjectID] {
			subjectComplete[subjectID] = subjectComplete[subjectID] && complete

			return
		}

		subjectSeen[subjectID] = true
		subjectComplete[subjectID] = complete
	}

	markSubject("", c.appendSubjectBoundaryLocked(frozen, "", &c.topicSystem.topicAccumulator,
		c.topicSystem.subscriptionsCurrent, c.topicSystem.subscriptionsKnown,
		true, c.topicSystem.topicsExist, c.topicSystem.topicsKnown, bucketStart, intervalMS))

	topicIDs := make([]string, 0, len(c.topicMetrics))
	for topicID := range c.topicMetrics {
		topicIDs = append(topicIDs, topicID)
	}

	sort.Strings(topicIDs)

	for _, topicID := range topicIDs {
		current := c.topicMetrics[topicID]
		activeGauge := !current.terminalPending
		frozen.accumulators[topicID] = &current.topicAccumulator
		markSubject(topicID, c.appendSubjectBoundaryLocked(frozen, topicID, &current.topicAccumulator,
			current.subscriptionsCurrent, current.subscriptionsKnown && activeGauge,
			current.authoritative && activeGauge, 0, false, bucketStart, intervalMS))
	}

	c.appendQueueBoundaryLocked(frozen, boundary, bucketStart, intervalMS, markSubject)

	coveredSubjects := make([]string, 0, len(subjectSeen))

	for subjectID, complete := range subjectComplete {
		if complete {
			coveredSubjects = append(coveredSubjects, subjectID)
		}
	}

	sort.Strings(coveredSubjects)

	for _, subjectID := range coveredSubjects {
		frozen.batch.Coverage = append(frozen.batch.Coverage, CoverageBucket{
			Resolution: ResolutionRaw, BucketStart: bucketStart,
			SubjectID: subjectID, SampleIntervalMS: intervalMS,
		})
	}

	return frozen
}

//nolint:cyclop,gocyclo // A subject snapshot deliberately enumerates the stable fixed metric matrix in one place.
func (c *Collector) appendSubjectBoundaryLocked(
	frozen *frozenTopicBoundary,
	subjectID string,
	accumulator *topicAccumulator,
	subscriptions int64,
	subscriptionsKnown bool,
	authoritative bool,
	topicsExist int64,
	topicsKnown bool,
	bucketStart, intervalMS int64,
) bool {
	appendCounter := func(metricName, labels string, value uint64) {
		appendPeriodicSample(&frozen.batch, MetricSample{
			Timestamp: bucketStart, SubjectID: subjectID, MetricName: metricName,
			Kind: MetricKindCounter, Value: float64(value), Labels: labels,
		}, intervalMS, !c.topicDirtyAtLocked(subjectID, metricName, bucketStart))
	}

	for _, backend := range topicBackends {
		for _, operation := range topicOperations {
			for _, result := range topicResults {
				key := operationResultKey{backend: backend, operation: operation, result: result}
				labels := canonicalResultLabels(backend, operation, result)
				appendCounter(MetricTopicRequestsTotal, labels, accumulator.requests[key])
				appendCounter(MetricTopicOperationsTotal, labels, accumulator.operations[key])
			}
		}
	}

	appendCounter(MetricTopicMessagesPublishedTotal, "", accumulator.messagesPublished)
	appendCounter(MetricTopicPublishedBytesTotal, "", accumulator.publishedBytes)
	appendCounter(MetricTopicDeliveriesTotal, "", accumulator.deliveries)
	appendCounter(MetricTopicDeliveryFailuresTotal, "", accumulator.deliveryFailures)
	appendCounter(MetricTopicSubscriptionsCreatedTotal, "", accumulator.subscriptionsCreated)
	appendCounter(MetricTopicSubscriptionsDeletedTotal, "", accumulator.subscriptionsDeleted)

	if subscriptionsKnown && (subjectID == "" || authoritative) {
		appendPeriodicSample(&frozen.batch, MetricSample{
			Timestamp: bucketStart, SubjectID: subjectID, MetricName: MetricTopicSubscriptionsCurrent,
			Kind: MetricKindGauge, Value: float64(subscriptions),
		}, intervalMS, true)
	}

	if subjectID == "" && topicsKnown {
		appendPeriodicSample(&frozen.batch, MetricSample{
			Timestamp: bucketStart, MetricName: MetricTopicsExist,
			Kind: MetricKindGauge, Value: float64(topicsExist),
		}, intervalMS, true)
	}

	currentBaseline := baselineFor(accumulator, frozen.boundary)

	rates, rateSamples := calculateTopicRateSamples(
		subjectID, accumulator.baseline, currentBaseline, bucketStart,
	)
	for _, sample := range rateSamples {
		covered := accumulator.baseline.boundary == bucketStart &&
			!c.topicDirtyAtLocked(subjectID, rateSourceCounter(sample.MetricName), bucketStart)
		appendPeriodicSample(&frozen.batch, sample, intervalMS, covered)
		frozen.batch.RateSnapshots = append(frozen.batch.RateSnapshots, RateSnapshot{
			Timestamp: sample.Timestamp, SubjectID: sample.SubjectID, MetricName: sample.MetricName,
			Rate: sample.Value, WindowMS: sample.WindowMS,
		})
	}

	if subjectID == "" {
		frozen.systemBaseline = currentBaseline
		frozen.systemRates = rates
	} else {
		frozen.baselines[subjectID] = currentBaseline
		frozen.rates[subjectID] = rates
	}

	c.appendEventCoverageLocked(&frozen.batch, subjectID, bucketStart, intervalMS)

	completeSubject := subscriptionsKnown && (subjectID == "" || authoritative)
	if subjectID == "" {
		completeSubject = completeSubject && topicsKnown
	}

	completeSubject = completeSubject && accumulator.baseline.boundary == bucketStart

	return completeSubject && !c.anyEventDirtyAtLocked(bucketStart) &&
		!c.anyTopicDirtyAtLocked(subjectID, bucketStart)
}

func appendPeriodicSample(batch *CollectionBatch, sample MetricSample, intervalMS int64, covered bool) {
	batch.Samples = append(batch.Samples, sample)
	if covered {
		batch.Coverage = append(batch.Coverage, CoverageBucket{
			Resolution: ResolutionRaw, BucketStart: sample.Timestamp,
			SubjectID: sample.SubjectID, MetricName: sample.MetricName,
			Labels: sample.Labels, Kind: sample.Kind, SampleIntervalMS: intervalMS,
		})
	}
}

func baselineFor(accumulator *topicAccumulator, boundary int64) topicBaseline {
	return topicBaseline{
		boundary:          boundary,
		messagesPublished: accumulator.messagesPublished, publishedBytes: accumulator.publishedBytes,
		deliveries: accumulator.deliveries, deliveryFailures: accumulator.deliveryFailures,
		subscriptionsCreated: accumulator.subscriptionsCreated,
		subscriptionsDeleted: accumulator.subscriptionsDeleted,
		revision:             accumulator.revision,
	}
}

func rateSourceCounter(metricName string) string {
	switch metricName {
	case MetricTopicPublishRate:
		return MetricTopicMessagesPublishedTotal
	case MetricTopicDeliveryRate:
		return MetricTopicDeliveriesTotal
	case MetricTopicDeliveryFailureRate:
		return MetricTopicDeliveryFailuresTotal
	case MetricTopicPublishedBytesRate:
		return MetricTopicPublishedBytesTotal
	case MetricTopicSubscriptionsCreatedRate:
		return MetricTopicSubscriptionsCreatedTotal
	case MetricTopicSubscriptionsDeletedRate:
		return MetricTopicSubscriptionsDeletedTotal
	default:
		panic("collector: rate metric has no source counter")
	}
}

func calculateTopicRateSamples(
	subjectID string, previous, current topicBaseline, timestamp int64,
) (TopicRates, []MetricSample) {
	if previous.boundary <= 0 || current.boundary <= previous.boundary {
		return TopicRates{}, nil
	}

	windowMS := current.boundary - previous.boundary
	seconds := float64(windowMS) / float64(time.Second/time.Millisecond)

	type rateDefinition struct {
		metric   string
		current  uint64
		previous uint64
		assign   func(*TopicRates, float64)
	}

	definitions := []rateDefinition{
		{MetricTopicPublishRate, current.messagesPublished, previous.messagesPublished,
			func(r *TopicRates, value float64) { r.PublishRate = value }},
		{MetricTopicDeliveryRate, current.deliveries, previous.deliveries,
			func(r *TopicRates, value float64) { r.DeliveryRate = value }},
		{MetricTopicDeliveryFailureRate, current.deliveryFailures, previous.deliveryFailures,
			func(r *TopicRates, value float64) { r.DeliveryFailureRate = value }},
		{MetricTopicPublishedBytesRate, current.publishedBytes, previous.publishedBytes,
			func(r *TopicRates, value float64) { r.PublishedBytesRate = value }},
		{MetricTopicSubscriptionsCreatedRate, current.subscriptionsCreated, previous.subscriptionsCreated,
			func(r *TopicRates, value float64) { r.SubscriptionsCreatedRate = value }},
		{MetricTopicSubscriptionsDeletedRate, current.subscriptionsDeleted, previous.subscriptionsDeleted,
			func(r *TopicRates, value float64) { r.SubscriptionsDeletedRate = value }},
	}

	rates := TopicRates{}

	samples := make([]MetricSample, 0, len(definitions))
	for _, definition := range definitions {
		delta := resetAwareDelta(definition.previous, definition.current)
		rate := float64(delta) / seconds
		definition.assign(&rates, rate)
		samples = append(samples, MetricSample{
			Timestamp: timestamp, SubjectID: subjectID, MetricName: definition.metric,
			Kind: MetricKindRate, Value: rate, WindowMS: windowMS,
		})
	}

	return rates, samples
}

func resetAwareDelta(previous, current uint64) uint64 {
	if current < previous {
		return current
	}

	return current - previous
}

func (c *Collector) appendEventCoverageLocked(
	batch *CollectionBatch, subjectID string, bucketStart, intervalMS int64,
) {
	appendCoverage := func(metricName, labels string) {
		if c.eventDirtyAtLocked(metricName, bucketStart) ||
			c.topicDirtyAtLocked(subjectID, metricName, bucketStart) {
			return
		}

		batch.Coverage = append(batch.Coverage, CoverageBucket{
			Resolution: ResolutionRaw, BucketStart: bucketStart,
			SubjectID: subjectID, MetricName: metricName, Labels: labels,
			Kind: MetricKindEvent, SampleIntervalMS: intervalMS,
		})
	}

	for _, backend := range topicBackends {
		for _, operation := range topicOperations {
			labels := canonicalDurationLabels(backend, operation)
			appendCoverage(MetricTopicRequestDuration, labels)
			appendCoverage(MetricTopicOperationDuration, labels)
		}
	}

	appendCoverage(MetricTopicFanout, "")
}

func (c *Collector) eventDirtyAtLocked(metricName string, bucketStart int64) bool {
	interval, exists := c.eventDirty[metricName]

	return exists && interval.fromBucket <= bucketStart && bucketStart <= interval.toBucket
}

func (c *Collector) anyEventDirtyAtLocked(bucketStart int64) bool {
	for _, metricName := range []string{
		MetricTopicRequestDuration, MetricTopicOperationDuration, MetricTopicFanout,
	} {
		if c.eventDirtyAtLocked(metricName, bucketStart) {
			return true
		}
	}

	return false
}

func (c *Collector) topicDirtyAtLocked(subjectID, metricName string, bucketStart int64) bool {
	if subjectID == "" {
		return false
	}

	if interval, exists := c.topicDirtyOverflow[metricName]; exists &&
		interval.fromBucket <= bucketStart && bucketStart <= interval.toBucket {
		return true
	}

	metricsByName, exists := c.topicDirty[subjectID]
	if !exists {
		return false
	}

	interval, exists := metricsByName[metricName]

	return exists && interval.fromBucket <= bucketStart && bucketStart <= interval.toBucket
}

func (c *Collector) anyTopicDirtyAtLocked(subjectID string, bucketStart int64) bool {
	if subjectID == "" {
		return false
	}

	for _, interval := range c.topicDirtyOverflow {
		if interval.fromBucket <= bucketStart && bucketStart <= interval.toBucket {
			return true
		}
	}

	for _, interval := range c.topicDirty[subjectID] {
		if interval.fromBucket <= bucketStart && bucketStart <= interval.toBucket {
			return true
		}
	}

	return false
}

func (c *Collector) finalizeTopicBoundaryLocked(frozen *frozenTopicBoundary) {
	c.topicSystem.baseline = frozen.systemBaseline

	c.topicSystem.rates = frozen.systemRates
	for topicID, baseline := range frozen.baselines {
		if current, exists := c.topicMetrics[topicID]; exists &&
			&current.topicAccumulator == frozen.accumulators[topicID] {
			current.baseline = baseline
			current.committedRevision = baseline.revision
			current.rates = frozen.rates[topicID]
		}
	}
}

func (c *Collector) advanceDirtyAfterBoundaryLocked(boundary int64) {
	advanceDirtyIntervals(c.eventDirty, boundary)
	advanceDirtyIntervals(c.topicDirtyOverflow, boundary)

	for subjectID, metricsByName := range c.topicDirty {
		advanceDirtyIntervals(metricsByName, boundary)

		if len(metricsByName) == 0 {
			delete(c.topicDirty, subjectID)
		}
	}
}

func advanceDirtyIntervals(intervals map[string]dirtyInterval, boundary int64) {
	for metricName, interval := range intervals {
		if interval.toBucket < boundary {
			delete(intervals, metricName)

			continue
		}

		if interval.fromBucket < boundary {
			interval.fromBucket = boundary
			intervals[metricName] = interval
		}
	}
}

//nolint:cyclop // Loading reconciles a bounded durable generation inventory with live reservations.
func (c *Collector) loadDurableTerminalReservations(ctx context.Context) error {
	c.terminalMu.Lock()
	if c.terminalLoaded {
		c.terminalMu.Unlock()

		return nil
	}
	c.terminalMu.Unlock()

	if c.store == nil {
		c.terminalMu.Lock()
		c.terminalLoaded = true
		c.terminalLoadFailed = false
		c.terminalMu.Unlock()

		return nil
	}

	states, err := c.store.ListTerminalStates(ctx)
	if err != nil {
		c.terminalMu.Lock()
		c.terminalLoadFailed = true
		c.terminalMu.Unlock()
		c.persist(metrics.TelemetryOpTerminalState, err)

		return fmt.Errorf("load durable terminal states: %w", err)
	}

	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	newEntries := 0

	for _, state := range states {
		key := terminalKey{subjectID: state.SubjectID, generation: state.Generation}
		if _, exists := c.terminalEntries[key]; !exists {
			newEntries++
		}
	}

	if c.terminalLimit <= 0 || newEntries > c.terminalLimit-len(c.terminalEntries) {
		c.terminalLoadFailed = true

		return errors.New("load durable terminal states: inventory exceeds configured limit")
	}

	for _, state := range states {
		stateCopy := state
		reservation := &terminalReservation{state: stateCopy, durable: true}
		key := terminalKey{subjectID: state.SubjectID, generation: state.Generation}

		if _, exists := c.terminalEntries[key]; exists {
			continue
		}

		c.terminalEntries[key] = reservation
		if state.Generation > c.terminalNextGeneration {
			c.terminalNextGeneration = state.Generation
		}

		current, exists := c.terminalReservations[state.SubjectID]
		switch {
		case !exists:
			c.activateTerminalLocked(reservation)
		case current.state.Generation < state.Generation:
			c.deactivateTerminalLocked(current)
			c.queueTerminalCancelLocked(current)
			c.activateTerminalLocked(reservation)
		default:
			c.queueTerminalCancelLocked(reservation)
		}
	}

	c.terminalLoadFailed = false
	c.terminalLoaded = true

	return nil
}

func (c *Collector) terminalStateBefore(left, right TerminalState) bool {
	if c.terminalVisit != nil {
		c.terminalVisit()
	}

	if left.ObservedAt != right.ObservedAt {
		return left.ObservedAt < right.ObservedAt
	}

	if left.SubjectID != right.SubjectID {
		return left.SubjectID < right.SubjectID
	}

	return left.Generation < right.Generation
}

func (c *Collector) activateTerminalLocked(reservation *terminalReservation) {
	subjectID := reservation.state.SubjectID
	if _, exists := c.terminalReservations[subjectID]; exists {
		panic("collector: duplicate active terminal subject")
	}

	if _, replaced := c.terminalOrder.ReplaceOrInsert(reservation); replaced {
		panic("collector: duplicate active terminal order key")
	}

	c.terminalReservations[subjectID] = reservation
}

func (c *Collector) deactivateTerminalLocked(reservation *terminalReservation) {
	subjectID := reservation.state.SubjectID

	current, exists := c.terminalReservations[subjectID]
	if !exists || current != reservation {
		return
	}

	removed, exists := c.terminalOrder.Delete(reservation)
	if !exists || removed != reservation {
		panic("collector: active terminal missing from order")
	}

	delete(c.terminalReservations, subjectID)
}

// reserveTerminalLocked runs with terminalMu and topicMu held.
func (c *Collector) reserveTerminalLocked(subjectID string, topic *TopicMetrics, observedAt int64) bool {
	if _, exists := c.terminalReservations[subjectID]; exists {
		return true
	}

	if c.terminalLoadFailed || c.terminalLimit <= 0 || len(c.terminalEntries) >= c.terminalLimit {
		return false
	}

	generation, ok := nextTerminalGeneration(c.terminalNextGeneration)
	if !ok {
		return false
	}

	c.terminalNextGeneration = generation
	reservation := &terminalReservation{
		state: TerminalState{
			SubjectID: subjectID, Generation: generation, ObservedAt: observedAt,
		},
		operation: terminalEnqueue,
	}
	reservation.element = c.terminalQueue.PushBack(reservation)
	c.activateTerminalLocked(reservation)
	c.terminalEntries[terminalKey{subjectID: subjectID, generation: reservation.state.Generation}] = reservation
	topic.terminalGeneration = reservation.state.Generation

	return true
}

func nextTerminalGeneration(after int64) (int64, bool) {
	for {
		current := terminalGenerationSequence.Load()

		base := max(current, after)
		if base == math.MaxInt64 {
			return 0, false
		}

		if terminalGenerationSequence.CompareAndSwap(current, base+1) {
			return base + 1, true
		}
	}
}

// cancelTerminalLocked runs with terminalMu and topicMu held. It excludes the
// stale generation from due work immediately, then leaves exact durable cleanup
// on the bounded maintenance FIFO.
func (c *Collector) cancelTerminalLocked(subjectID string) int64 {
	reservation, exists := c.terminalReservations[subjectID]
	if !exists {
		return 0
	}

	c.deactivateTerminalLocked(reservation)
	c.queueTerminalCancelLocked(reservation)

	return reservation.state.Generation
}

func (c *Collector) queueTerminalCancelLocked(reservation *terminalReservation) {
	reservation.canceled = true

	reservation.operation = terminalCancel
	if reservation.element == nil {
		reservation.element = c.terminalQueue.PushBack(reservation)
	}
}

//nolint:unused // Task 9 tests pin the shared durable/pre-durable budget before Task 10 consumes it.
func (c *Collector) terminalReservationCount() int {
	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	return len(c.terminalEntries)
}

// promoteTerminalStates performs SQLite work without holding callback locks.
func (c *Collector) promoteTerminalStates(ctx context.Context) error {
	c.terminalPromoteMu.Lock()
	defer c.terminalPromoteMu.Unlock()

	for {
		reservation, operation, ok := c.nextTerminalAction()
		if !ok {
			return nil
		}

		switch operation {
		case terminalEnqueue:
			if err := c.promoteTerminalEnqueue(ctx, reservation); err != nil {
				return err
			}
		case terminalCancel:
			if err := c.promoteTerminalCancel(ctx, reservation); err != nil {
				return err
			}
		default:
			panic("collector: invalid terminal operation")
		}
	}
}

func (c *Collector) promoteTerminalEnqueue(ctx context.Context, reservation *terminalReservation) error {
	var (
		accepted bool
		err      error
	)

	if c.store != nil {
		accepted, err = c.store.EnqueueTerminalState(ctx, reservation.state, c.terminalLimit)
	}

	c.persist(metrics.TelemetryOpTerminalState, err)

	if c.finishTerminalEnqueue(reservation, accepted, err) {
		c.deleteTerminalTopic(reservation.state)
		metrics.RecordTelemetryTerminalStateDropped(1)
	}

	if err != nil {
		return fmt.Errorf("promote terminal state %q/%d: %w",
			reservation.state.SubjectID, reservation.state.Generation, err)
	}

	return nil
}

func (c *Collector) promoteTerminalCancel(ctx context.Context, reservation *terminalReservation) error {
	var err error

	if c.store != nil {
		err = c.store.CancelTerminalState(
			ctx, reservation.state.SubjectID, reservation.state.Generation,
		)
	}

	c.persist(metrics.TelemetryOpTerminalState, err)
	c.finishTerminalCancel(reservation, err)

	if err != nil {
		return fmt.Errorf("cancel terminal state %q/%d: %w",
			reservation.state.SubjectID, reservation.state.Generation, err)
	}

	return nil
}

func (c *Collector) nextTerminalAction() (*terminalReservation, terminalOperation, bool) {
	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	element := c.terminalQueue.Front()
	if element == nil {
		return nil, 0, false
	}

	reservation, ok := element.Value.(*terminalReservation)
	if !ok {
		panic("collector: invalid terminal queue entry")
	}

	if reservation.inFlight {
		panic("collector: terminal action already in flight")
	}

	if c.terminalVisit != nil {
		c.terminalVisit()
	}

	reservation.inFlight = true

	return reservation, reservation.operation, true
}

func (c *Collector) finishTerminalEnqueue(
	reservation *terminalReservation, accepted bool, enqueueErr error,
) bool {
	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	reservation.inFlight = false
	if enqueueErr != nil {
		if reservation.canceled {
			reservation.operation = terminalCancel
		}

		return false
	}

	if !accepted {
		dropTopic := !reservation.canceled
		c.removeTerminalEntryLocked(reservation)

		return dropTopic
	}

	reservation.durable = true
	if reservation.canceled {
		reservation.operation = terminalCancel

		return false
	}

	c.removeTerminalActionLocked(reservation)

	return false
}

func (c *Collector) finishTerminalCancel(reservation *terminalReservation, cancelErr error) {
	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	reservation.inFlight = false
	if cancelErr == nil {
		c.removeTerminalEntryLocked(reservation)
	}
}

func (c *Collector) removeTerminalEntryLocked(reservation *terminalReservation) {
	c.removeTerminalActionLocked(reservation)

	key := terminalKey{
		subjectID: reservation.state.SubjectID, generation: reservation.state.Generation,
	}
	if current, exists := c.terminalEntries[key]; exists && current == reservation {
		delete(c.terminalEntries, key)
	}

	c.deactivateTerminalLocked(reservation)
}

func (c *Collector) removeTerminalActionLocked(reservation *terminalReservation) {
	if reservation.element != nil {
		c.terminalQueue.Remove(reservation.element)
		reservation.element = nil
	}

	reservation.inFlight = false
}

func (c *Collector) deleteTerminalTopic(state TerminalState) {
	c.topicMu.Lock()
	defer c.topicMu.Unlock()

	if current, exists := c.topicMetrics[state.SubjectID]; exists && current.terminalPending &&
		current.terminalGeneration == state.Generation {
		c.deleteTopicLocked(state.SubjectID)
	}
}

func (c *Collector) terminalStatesDue(boundary int64) []TerminalState {
	c.terminalMu.Lock()

	states := make([]TerminalState, 0, len(c.terminalReservations))
	c.terminalOrder.Ascend(func(reservation *terminalReservation) bool {
		if c.terminalVisit != nil {
			c.terminalVisit()
		}

		if reservation.state.ObservedAt >= boundary {
			return false
		}

		if reservation.durable && !reservation.canceled && reservation.state.ObservedAt < boundary {
			states = append(states, reservation.state)
		}

		return true
	})
	c.terminalMu.Unlock()

	return states
}

// assignTerminalStates freezes the first eligible raw target without moving retries.
func (c *Collector) assignTerminalStates(ctx context.Context, boundary int64) error {
	intervalMS := c.collectionInterval.Milliseconds()
	if intervalMS <= 0 || boundary%intervalMS != 0 {
		return errors.New("assign terminal states: invalid boundary")
	}

	target := boundary - intervalMS
	if target < c.lastRollup1m {
		// Startup first catches the old raw grid up through lastRollup1m.
		// Keep an unassigned zero pending until its target belongs to a minute
		// the coordinator has not already closed, otherwise no later rollup can
		// discover it.
		return nil
	}

	for _, state := range c.terminalStatesDue(boundary) {
		if state.TargetBucket != nil {
			continue
		}

		if !c.terminalStateActive(state) {
			continue
		}

		if err := c.store.AssignTerminalBucket(
			ctx, state.SubjectID, state.Generation, target, intervalMS,
		); err != nil {
			return fmt.Errorf("assign terminal state %q/%d: %w", state.SubjectID, state.Generation, err)
		}

		c.terminalMu.Lock()
		if current, exists := c.terminalReservations[state.SubjectID]; exists &&
			current.state.Generation == state.Generation && !current.canceled {
			targetCopy, intervalCopy := target, intervalMS
			current.state.TargetBucket = &targetCopy
			current.state.SampleIntervalMS = &intervalCopy
		}
		c.terminalMu.Unlock()
	}

	return nil
}

// completeTerminalState writes the durable zero and releases its reservation once.
func (c *Collector) completeTerminalState(ctx context.Context, state TerminalState) error {
	if c.store == nil || !isAssignedTerminalState(state) {
		return errors.New("complete terminal state: assigned durable state is required")
	}

	if !c.terminalStateActive(state) {
		return nil
	}

	sample := MetricSample{
		Timestamp: *state.TargetBucket, SubjectID: state.SubjectID,
		MetricName: MetricTopicSubscriptionsCurrent, Kind: MetricKindGauge,
	}

	coverage := CoverageBucket{
		Resolution: ResolutionRaw, BucketStart: *state.TargetBucket,
		SubjectID: state.SubjectID, MetricName: MetricTopicSubscriptionsCurrent,
		Kind: MetricKindGauge, SampleIntervalMS: *state.SampleIntervalMS,
	}
	if err := c.store.CompleteTerminalState(
		ctx, state.SubjectID, state.Generation, sample, coverage,
	); err != nil {
		return fmt.Errorf("complete terminal state %q/%d: %w", state.SubjectID, state.Generation, err)
	}

	c.releaseCompletedTerminal(state)

	return nil
}

func isAssignedTerminalState(state TerminalState) bool {
	return state.Generation > 0 && state.TargetBucket != nil && state.SampleIntervalMS != nil
}

func (c *Collector) releaseCompletedTerminal(state TerminalState) bool {
	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	current, exists := c.terminalReservations[state.SubjectID]

	if !exists || current.state.Generation != state.Generation || current.canceled {
		return false
	}

	// Completion performs SQLite work before taking callback locks. Linearize
	// reservation release with the final in-memory disposition so a callback
	// either dirties the retained accumulator or recreates it after deletion.
	c.cutoverMu.Lock()
	defer c.cutoverMu.Unlock()

	c.topicMu.Lock()
	defer c.topicMu.Unlock()

	c.removeTerminalEntryLocked(current)

	topic, exists := c.topicMetrics[state.SubjectID]
	if !exists || !topic.terminalPending || topic.terminalGeneration != state.Generation {
		return true
	}

	if topic.revision == topic.committedRevision {
		c.deleteTopicLocked(state.SubjectID)

		return true
	}

	// A post-cutover callback owns data that was not part of the durable final
	// boundary. Keep it as bounded attribution-only state until collection
	// commits it; membership gauges remain suppressed without authoritative
	// reconciliation.
	topic.authoritative = false
	topic.subscriptionsKnown = false

	topic.terminalPending = false
	topic.terminalGeneration = 0

	if topic.cacheElement == nil {
		topic.cacheElement = c.topicCache.attributed.PushBack(state.SubjectID)
	} else {
		c.topicCache.attributed.MoveToBack(topic.cacheElement)
	}

	return true
}

func (c *Collector) terminalStateActive(state TerminalState) bool {
	c.terminalMu.Lock()
	defer c.terminalMu.Unlock()

	current, exists := c.terminalReservations[state.SubjectID]

	return exists && current.state.Generation == state.Generation && current.durable && !current.canceled
}

// GetTopicRates returns the latest successfully committed rates for one subject.
func (c *Collector) GetTopicRates(topicID string) TopicRates {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	if current, exists := c.topicMetrics[topicID]; exists {
		return current.rates
	}

	return TopicRates{}
}

// GetTopicSystemRates returns the latest successfully committed system rates.
func (c *Collector) GetTopicSystemRates() TopicRates {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	return c.topicSystem.rates
}

// GetTopicCounters returns current cumulative counters for one topic.
func (c *Collector) GetTopicCounters(topicID string) TopicCounters {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	current, exists := c.topicMetrics[topicID]
	if !exists {
		return TopicCounters{}
	}

	return countersFor(&current.topicAccumulator)
}

// GetTopicSystemCounters returns current cumulative counters and exact gauges.
func (c *Collector) GetTopicSystemCounters() TopicSystemCounters {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	counters := countersFor(&c.topicSystem.topicAccumulator)

	return TopicSystemCounters{
		Requests: counters.Requests, Operations: counters.Operations,
		MessagesPublished: counters.MessagesPublished, PublishedBytes: counters.PublishedBytes,
		Deliveries: counters.Deliveries, DeliveryFailures: counters.DeliveryFailures,
		SubscriptionsCreated:      counters.SubscriptionsCreated,
		SubscriptionsDeleted:      counters.SubscriptionsDeleted,
		SubscriptionsCurrent:      c.topicSystem.subscriptionsCurrent,
		SubscriptionsCurrentKnown: c.topicSystem.subscriptionsKnown,
		TopicsExist:               c.topicSystem.topicsExist, TopicsExistKnown: c.topicSystem.topicsKnown,
	}
}

func countersFor(accumulator *topicAccumulator) TopicCounters {
	return TopicCounters{
		Requests:          sumOperationCounters(accumulator.requests),
		Operations:        sumOperationCounters(accumulator.operations),
		MessagesPublished: accumulator.messagesPublished, PublishedBytes: accumulator.publishedBytes,
		Deliveries: accumulator.deliveries, DeliveryFailures: accumulator.deliveryFailures,
		SubscriptionsCreated: accumulator.subscriptionsCreated,
		SubscriptionsDeleted: accumulator.subscriptionsDeleted,
	}
}

func sumOperationCounters(values map[operationResultKey]uint64) uint64 {
	var total uint64
	for _, value := range values {
		total += value
	}

	return total
}

func (c *Collector) GetTopicSubscriptionsCurrent(topicID string) int64 {
	value, _ := c.GetTopicSubscriptionsCurrentKnown(topicID)

	return value
}

func (c *Collector) GetTopicSubscriptionsCurrentKnown(topicID string) (int64, bool) {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	current, exists := c.topicMetrics[topicID]
	if !exists || !current.authoritative || current.terminalPending || !current.subscriptionsKnown {
		return 0, false
	}

	return current.subscriptionsCurrent, true
}

func (c *Collector) GetTopicLastUpdated(topicID string) int64 {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	if current, exists := c.topicMetrics[topicID]; exists {
		return current.lastUpdated
	}

	return 0
}

// GetAllTopicIDs returns only authoritative, active inventory members.
func (c *Collector) GetAllTopicIDs() []string {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	ids := make([]string, 0, len(c.topicMetrics))
	for topicID, current := range c.topicMetrics {
		if current.authoritative && !current.terminalPending {
			ids = append(ids, topicID)
		}
	}

	sort.Strings(ids)

	return ids
}
