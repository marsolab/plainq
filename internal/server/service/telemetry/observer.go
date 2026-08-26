package telemetry

import (
	"sync"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// Recorder is the telemetry collector's side of the queue event stream.
//
// The collector keeps rates, in-flight counts and rolled-up history for
// Houston's dashboards; Prometheus keeps the counters and distributions for an
// external monitoring stack. Both want the same events, so storage emits them
// once, here, and the Observer fans them out.
//
// Distributions — batch sizes, message sizes, how long a message waited — go
// only to Prometheus. They are histograms, the telemetry store has no shape
// for one, and the collector's previous attempt at keeping them was an
// unbounded slice per queue.
type Recorder interface {
	RecordSend(queueID string, count, totalBytes uint64)
	RecordReceive(queueID string, count uint64, isEmpty bool)
	RecordDelete(queueID string, count uint64)
	RecordRedelivery(queueID string, count uint64)
	RecordDrop(queueID string, count uint64)
	RecordDLQ(queueID string, count uint64)
	IncrementQueues()
	DecrementQueues()
	SetQueuesExist(count int64)
}

// TopicRecorder is the optional pub/sub capability of a telemetry recorder.
// Queue-only recorders remain valid while the stable pub/sub collector is
// introduced incrementally.
type TopicRecorder interface {
	RecordTopicRequest(TopicOperationEvent)
	RecordTopicOperation(TopicOperationEvent)
	RecordTopicPublish(TopicPublishEvent)
	RecordTopicSubscriptionCreated(topicID string)
	RecordTopicSubscriptionDeleted(topicID string)
	RecordTopicState(TopicStateEvent)
	RecordTopicStateUnavailable()
}

// TopicOperationEvent describes one decoded request or storage operation.
type TopicOperationEvent struct {
	Backend   string
	Operation string
	Result    string
	TopicID   string
	Duration  time.Duration
}

// TopicPublishEvent describes the known business outcome of one publish.
type TopicPublishEvent struct {
	TopicID      string
	Messages     uint64
	Bytes        uint64
	Destinations uint64
	Delivered    uint64
	Failed       uint64
}

// TopicStateEvent is one exact topic and subscription inventory.
type TopicStateEvent struct {
	TopicsExist   int64
	Subscriptions map[string]int64
}

// stateSuppressingRecorder lets a logical cluster observer feed request and
// activity history into the collector without overwriting the exact local
// replica state maintained by FSM reconciliation.
type stateSuppressingRecorder struct {
	inner Recorder
}

// NewStateSuppressingRecorder forwards activity and lifecycle events while
// suppressing every exact queue/topic state mutation.
func NewStateSuppressingRecorder(inner Recorder) Recorder {
	if inner == nil {
		return nil
	}
	return &stateSuppressingRecorder{inner: inner}
}

func (r *stateSuppressingRecorder) RecordSend(queueID string, count, totalBytes uint64) {
	r.inner.RecordSend(queueID, count, totalBytes)
}
func (r *stateSuppressingRecorder) RecordReceive(queueID string, count uint64, empty bool) {
	r.inner.RecordReceive(queueID, count, empty)
}
func (r *stateSuppressingRecorder) RecordDelete(queueID string, count uint64) {
	r.inner.RecordDelete(queueID, count)
}
func (r *stateSuppressingRecorder) RecordRedelivery(queueID string, count uint64) {
	r.inner.RecordRedelivery(queueID, count)
}
func (r *stateSuppressingRecorder) RecordDrop(queueID string, count uint64) {
	r.inner.RecordDrop(queueID, count)
}
func (r *stateSuppressingRecorder) RecordDLQ(queueID string, count uint64) {
	r.inner.RecordDLQ(queueID, count)
}
func (*stateSuppressingRecorder) IncrementQueues()     {}
func (*stateSuppressingRecorder) DecrementQueues()     {}
func (*stateSuppressingRecorder) SetQueuesExist(int64) {}

func (r *stateSuppressingRecorder) topic() TopicRecorder {
	topic, _ := r.inner.(TopicRecorder)
	return topic
}

func (r *stateSuppressingRecorder) RecordTopicRequest(event TopicOperationEvent) {
	if topic := r.topic(); topic != nil {
		topic.RecordTopicRequest(event)
	}
}
func (r *stateSuppressingRecorder) RecordTopicOperation(event TopicOperationEvent) {
	if topic := r.topic(); topic != nil {
		topic.RecordTopicOperation(event)
	}
}
func (r *stateSuppressingRecorder) RecordTopicPublish(event TopicPublishEvent) {
	if topic := r.topic(); topic != nil {
		topic.RecordTopicPublish(event)
	}
}
func (r *stateSuppressingRecorder) RecordTopicSubscriptionCreated(topicID string) {
	if topic := r.topic(); topic != nil {
		topic.RecordTopicSubscriptionCreated(topicID)
	}
}
func (r *stateSuppressingRecorder) RecordTopicSubscriptionDeleted(topicID string) {
	if topic := r.topic(); topic != nil {
		topic.RecordTopicSubscriptionDeleted(topicID)
	}
}
func (*stateSuppressingRecorder) RecordTopicState(TopicStateEvent) {}
func (*stateSuppressingRecorder) RecordTopicStateUnavailable()     {}

// Observer is the seam storage and application boundaries record activity
// through. Prometheus is always updated; an attached recorder receives the same
// logical event for PlainQ's internal telemetry.
//
// Recorder callbacks run while mu is held. A recorder must not call back into
// this Observer.
type Observer struct {
	backend         string
	exactTopicState bool

	mu sync.Mutex

	queues      uint64
	queuesKnown bool

	topicsExist        int64
	topicSubscriptions map[string]int64
	topicsKnown        bool

	sink Recorder
}

// NewObserver returns an Observer for the named storage backend.
func NewObserver(backend string) *Observer {
	return &Observer{
		backend:            backend,
		exactTopicState:    true,
		topicSubscriptions: make(map[string]int64),
	}
}

// NewStateSuppressingObserver returns an activity observer that never captures
// or applies exact topic gauges. Cluster ingress uses it so only the local FSM
// observer owns Prometheus and collector topic inventory state.
func NewStateSuppressingObserver(backend string) *Observer {
	return &Observer{
		backend:            backend,
		topicSubscriptions: make(map[string]int64),
	}
}

// SetRecorder attaches the telemetry collector and replays only authoritative
// exact state. Attaching and replaying are one ordered action relative to every
// event callback.
func (o *Observer) SetRecorder(sink Recorder) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.sink = sink
	if sink == nil {
		return
	}

	if o.queuesKnown {
		//nolint:gosec // a queue count cannot reach the sign bit.
		sink.SetQueuesExist(int64(o.queues))
	}

	topicSink, ok := sink.(TopicRecorder)
	if ok && o.exactTopicState && o.topicsKnown {
		topicSink.RecordTopicState(TopicStateEvent{
			TopicsExist:   o.topicsExist,
			Subscriptions: cloneSubscriptions(o.topicSubscriptions),
		})
	}
}

// Backend returns the storage backend this Observer labels its metrics with.
func (o *Observer) Backend() string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.backend
}

// Queues returns how many queues the Observer currently holds.
func (o *Observer) Queues() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.queues
}

// QueueCreated records a new queue. An incremental mutation does not make an
// unknown queue count authoritative for later recorder replay.
func (o *Observer) QueueCreated() {
	o.mu.Lock()
	defer o.mu.Unlock()

	if !o.queuesKnown {
		return
	}

	metrics.AddQueuesExist(1)
	o.queues++

	if o.sink != nil {
		o.sink.IncrementQueues()
	}
}

// QueueDeleted records a removed queue and clears its per-queue gauges, so a
// deleted queue does not leave a permanent depth behind.
func (o *Observer) QueueDeleted(queueID string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.ResetQueue(queueID)

	if !o.queuesKnown || o.queues == 0 {
		return
	}

	metrics.AddQueuesExist(-1)
	o.queues--

	if o.sink != nil {
		o.sink.DecrementQueues()
	}
}

// SetQueues records an exact queue count, as read from the store at startup
// or after a snapshot restore.
func (o *Observer) SetQueues(count uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	//nolint:gosec // a queue count cannot reach the sign bit.
	exact := int64(count)

	metrics.SetQueuesExist(exact)
	o.queues = count
	o.queuesKnown = true

	if o.sink != nil {
		o.sink.SetQueuesExist(exact)
	}
}

// Sent records messages accepted into a queue.
func (o *Observer) Sent(queueID string, count, bytes uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordSend(queueID, count, bytes)

	if o.sink != nil {
		o.sink.RecordSend(queueID, count, bytes)
	}
}

// MessageSizes returns the recorder for a queue's message body sizes,
// resolved once for a whole batch rather than per message.
func (o *Observer) MessageSizes(queueID string) *metrics.Histogram {
	o.mu.Lock()
	defer o.mu.Unlock()

	return metrics.MessageSizes(queueID)
}

// Received records messages handed to a consumer. A zero count is an empty
// receive, which is counted as such rather than as a receive of nothing.
func (o *Observer) Received(queueID string, count, bytes uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordReceive(queueID, count, bytes)

	if o.sink != nil {
		o.sink.RecordReceive(queueID, count, count == 0)
	}
}

// Redelivered records messages handed out again after a visibility timeout
// expired.
func (o *Observer) Redelivered(queueID string, count uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordRedelivery(queueID, count)

	if o.sink != nil {
		o.sink.RecordRedelivery(queueID, count)
	}
}

// Deleted records acknowledged messages leaving a queue.
func (o *Observer) Deleted(queueID string, count uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordDelete(queueID, count)

	if o.sink != nil {
		o.sink.RecordDelete(queueID, count)
	}
}

// Dropped records messages evicted by the retention or retry policy.
func (o *Observer) Dropped(queueID string, policy v1.EvictionPolicy, count uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordDrop(queueID, policy.String(), count)

	if o.sink != nil {
		o.sink.RecordDrop(queueID, count)
	}
}

// DeadLettered records messages moved to a dead-letter queue.
func (o *Observer) DeadLettered(queueID string, count uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordDeadLetter(queueID, count)

	if o.sink != nil {
		o.sink.RecordDLQ(queueID, count)
	}
}

// TimeInQueue records how long a delivered message had been waiting.
func (o *Observer) TimeInQueue(queueID string, d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordTimeInQueue(queueID, d)
}

// QueueStats re-bases a queue's depth and in-flight count from exact
// readings taken by the backend.
func (o *Observer) QueueStats(queueID string, depth, inFlight int64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.SetQueueStats(queueID, depth, inFlight)
}

// QueuePurged records a queue emptied in one go.
func (o *Observer) QueuePurged(queueID string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.ResetQueue(queueID)
}

// Operation records one queue API operation and how long it took.
func (o *Observer) Operation(operation string, start time.Time, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordOperation(o.backend, operation, start, err)
}

// TopicRequest records one decoded public topic request.
func (o *Observer) TopicRequest(operation, topicID string, started time.Time, err error) {
	event := TopicOperationEvent{
		Backend:   o.backend,
		Operation: operation,
		Result:    metrics.Result(err),
		TopicID:   topicID,
		Duration:  time.Since(started),
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordTopicRequest(event.Backend, event.Operation, event.Result, event.Duration)
	if sink, ok := o.sink.(TopicRecorder); ok {
		sink.RecordTopicRequest(event)
	}
}

// TopicOperation records one topic storage operation.
func (o *Observer) TopicOperation(operation, topicID string, started time.Time, err error) {
	event := TopicOperationEvent{
		Backend:   o.backend,
		Operation: operation,
		Result:    metrics.Result(err),
		TopicID:   topicID,
		Duration:  time.Since(started),
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordTopicOperation(event.Backend, event.Operation, event.Result, event.Duration)
	if sink, ok := o.sink.(TopicRecorder); ok {
		sink.RecordTopicOperation(event)
	}
}

// Published records the known business outcome of one publish.
func (o *Observer) Published(event TopicPublishEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordPublish(
		event.TopicID,
		event.Messages,
		event.Bytes,
		event.Destinations,
		event.Delivered,
		event.Failed,
	)

	if sink, ok := o.sink.(TopicRecorder); ok {
		sink.RecordTopicPublish(event)
	}
}

// TopicSubscriptionCreated records one committed subscription creation.
func (o *Observer) TopicSubscriptionCreated(topicID string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordSubscriptionCreated(topicID)
	if sink, ok := o.sink.(TopicRecorder); ok {
		sink.RecordTopicSubscriptionCreated(topicID)
	}
}

// TopicSubscriptionDeleted records one committed subscription removal.
func (o *Observer) TopicSubscriptionDeleted(topicID string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordSubscriptionDeleted(topicID)
	if sink, ok := o.sink.(TopicRecorder); ok {
		sink.RecordTopicSubscriptionDeleted(topicID)
	}
}

// CaptureTopicState captures and applies an inventory as one ordered action.
// The callback runs while the Observer ordering lock is held and must not call
// back into this Observer. A state-suppressing observer skips the callback.
func (o *Observer) CaptureTopicState(capture func() (TopicStateEvent, error)) error {
	if !o.exactTopicState {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	event, err := capture()
	if err != nil {
		o.topicStateUnavailableLocked()
		return err
	}
	o.reconcileTopicStateLocked(event)

	return nil
}

// ReconcileTopicState installs one exact topic inventory. Removed topics are
// reset to zero before the new state is published.
func (o *Observer) ReconcileTopicState(event TopicStateEvent) {
	if !o.exactTopicState {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	o.reconcileTopicStateLocked(event)
}

func (o *Observer) reconcileTopicStateLocked(event TopicStateEvent) {
	next := cloneSubscriptions(event.Subscriptions)

	for topicID := range o.topicSubscriptions {
		if _, exists := next[topicID]; !exists {
			metrics.SetTopicSubscriptions(topicID, 0)
		}
	}

	for topicID, count := range next {
		metrics.SetTopicSubscriptions(topicID, count)
	}

	metrics.SetTopicsExist(event.TopicsExist)
	o.topicsExist = event.TopicsExist
	o.topicSubscriptions = next
	o.topicsKnown = true

	if sink, ok := o.sink.(TopicRecorder); ok {
		sink.RecordTopicState(TopicStateEvent{
			TopicsExist:   event.TopicsExist,
			Subscriptions: cloneSubscriptions(next),
		})
	}
}

// TopicStateUnavailable invalidates exact topic state without changing the
// last Prometheus gauges or lifecycle totals. The prior map remains retained so
// a later successful inventory can close removed-topic series with zero.
func (o *Observer) TopicStateUnavailable() {
	if !o.exactTopicState {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	o.topicStateUnavailableLocked()
}

func (o *Observer) topicStateUnavailableLocked() {
	o.topicsKnown = false
	if sink, ok := o.sink.(TopicRecorder); ok {
		sink.RecordTopicStateUnavailable()
	}
}

// StorageError records a storage failure that no single API operation owns —
// a background sweep blowing up, a statistics sample that could not be taken.
func (o *Observer) StorageError(operation string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordStorageError(o.backend, operation)
}

// GC records a retention sweep.
func (o *Observer) GC(scope string, start time.Time, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	metrics.RecordGC(o.backend, scope, start, err)
}

func cloneSubscriptions(input map[string]int64) map[string]int64 {
	copy := make(map[string]int64, len(input))
	for topicID, count := range input {
		copy[topicID] = count
	}

	return copy
}
