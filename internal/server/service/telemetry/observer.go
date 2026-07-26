package telemetry

import (
	"sync/atomic"
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

// Observer is the seam a storage backend records queue activity through.
//
// It replaced an interface that handed back a Counter per event. That shape
// allocated a closure per field per call — fourteen of them on every Send —
// to express what a method call expresses for free, and it made the two
// consumers of these events (Prometheus and the telemetry collector) look
// like unrelated systems when they want exactly the same stream.
type Observer struct {
	// backend labels every operation with the store that ran it.
	backend string

	// queues counts existing queues. The garbage collector reads it to decide
	// whether there is anything to sweep and how large a page to read, which
	// is why it is kept here rather than only in the metric.
	queues atomic.Uint64

	// sink is the telemetry collector, when one is attached. It is nil when
	// telemetry is disabled — Prometheus does not depend on it.
	sink Recorder
}

// NewObserver returns an Observer for the named storage backend.
func NewObserver(backend string) *Observer { return &Observer{backend: backend} }

// SetRecorder attaches the telemetry collector.
//
// It is set after construction because the collector needs the telemetry
// store, which is opened after the queue store it will be recording.
func (o *Observer) SetRecorder(sink Recorder) {
	o.sink = sink

	if sink != nil {
		sink.SetQueuesExist(int64(o.queues.Load())) //nolint:gosec // a queue count cannot reach the sign bit.
	}
}

// Backend returns the storage backend this Observer labels its metrics with.
func (o *Observer) Backend() string { return o.backend }

// Queues returns how many queues exist.
func (o *Observer) Queues() uint64 { return o.queues.Load() }

// QueueCreated records a new queue.
func (o *Observer) QueueCreated() {
	metrics.AddQueuesExist(1)
	o.queues.Add(1)

	if o.sink != nil {
		o.sink.IncrementQueues()
	}
}

// QueueDeleted records a removed queue and clears its per-queue gauges, so a
// deleted queue does not leave a permanent depth behind.
func (o *Observer) QueueDeleted(queueID string) {
	metrics.AddQueuesExist(-1)
	metrics.ResetQueue(queueID)
	o.queues.Add(^uint64(0)) // Subtract one; atomic.Uint64 has no Sub.

	if o.sink != nil {
		o.sink.DecrementQueues()
	}
}

// SetQueues records an exact queue count, as read from the store at startup
// or after a snapshot restore.
func (o *Observer) SetQueues(count uint64) {
	//nolint:gosec // a queue count cannot reach the sign bit.
	exact := int64(count)

	metrics.SetQueuesExist(exact)
	o.queues.Store(count)

	if o.sink != nil {
		o.sink.SetQueuesExist(exact)
	}
}

// Sent records messages accepted into a queue.
func (o *Observer) Sent(queueID string, count, bytes uint64) {
	metrics.RecordSend(queueID, count, bytes)

	if o.sink != nil {
		o.sink.RecordSend(queueID, count, bytes)
	}
}

// MessageSize records one message body size.
func (o *Observer) MessageSize(queueID string, size int) {
	metrics.RecordMessageSize(queueID, size)
}

// Received records messages handed to a consumer. A zero count is an empty
// receive, which is counted as such rather than as a receive of nothing.
func (o *Observer) Received(queueID string, count, bytes uint64) {
	metrics.RecordReceive(queueID, count, bytes)

	if o.sink != nil {
		o.sink.RecordReceive(queueID, count, count == 0)
	}
}

// Redelivered records messages handed out again after a visibility timeout
// expired.
func (o *Observer) Redelivered(queueID string, count uint64) {
	metrics.RecordRedelivery(queueID, count)

	if o.sink != nil {
		o.sink.RecordRedelivery(queueID, count)
	}
}

// Deleted records acknowledged messages leaving a queue.
func (o *Observer) Deleted(queueID string, count uint64) {
	metrics.RecordDelete(queueID, count)

	if o.sink != nil {
		o.sink.RecordDelete(queueID, count)
	}
}

// Dropped records messages evicted by the retention or retry policy.
func (o *Observer) Dropped(queueID string, policy v1.EvictionPolicy, count uint64) {
	metrics.RecordDrop(queueID, policy.String(), count)

	if o.sink != nil {
		o.sink.RecordDrop(queueID, count)
	}
}

// DeadLettered records messages moved to a dead-letter queue.
func (o *Observer) DeadLettered(queueID string, count uint64) {
	metrics.RecordDeadLetter(queueID, count)

	if o.sink != nil {
		o.sink.RecordDLQ(queueID, count)
	}
}

// TimeInQueue records how long a delivered message had been waiting.
func (o *Observer) TimeInQueue(queueID string, d time.Duration) {
	metrics.RecordTimeInQueue(queueID, d)
}

// QueueDepth re-bases a queue's depth from an exact count.
func (o *Observer) QueueDepth(queueID string, depth int64) {
	metrics.SetQueueDepth(queueID, depth)
}

// QueuePurged records a queue emptied in one go.
func (o *Observer) QueuePurged(queueID string) { metrics.ResetQueue(queueID) }

// Operation records one queue API operation and how long it took.
func (o *Observer) Operation(operation string, start time.Time, err error) {
	metrics.RecordOperation(o.backend, operation, start, err)
}

// TopicOperation records one topic API operation and how long it took.
func (o *Observer) TopicOperation(operation string, start time.Time, err error) {
	metrics.RecordTopicOperation(o.backend, operation, start, err)
}

// Published records a publish and its fan-out.
func (o *Observer) Published(topicID string, messages, bytes, delivered, failed uint64) {
	metrics.RecordPublish(topicID, messages, bytes, delivered, failed)
}

// GC records a retention sweep.
func (o *Observer) GC(scope string, start time.Time, err error) {
	metrics.RecordGC(o.backend, scope, start, err)
}
