package metrics

import "time"

// Label names shared across the queue and topic families. They are constants
// so a typo becomes a compile error rather than a second, near-identical
// series nobody notices for a month.
const (
	labelQueue     = "queue"
	labelTopic     = "topic"
	labelOperation = "operation"
	labelResult    = "result"
	labelPolicy    = "policy"
	labelBackend   = "backend"
)

// Queue operation names. These are the logical API operations, not SQL
// statements — one Send is one operation whether it wrote one message or two
// thousand.
const (
	OpCreateQueue   = "create_queue"
	OpDeleteQueue   = "delete_queue"
	OpPurgeQueue    = "purge_queue"
	OpDescribeQueue = "describe_queue"
	OpListQueues    = "list_queues"
	OpSend          = "send"
	OpReceive       = "receive"
	OpDelete        = "delete"
	OpPeek          = "peek"
	OpSweep         = "sweep"
)

// Queue and message metrics.
var (
	queueOperations = NewCounterVec(Definition{
		Name:   Namespace + "_queue_operations_total",
		Help:   "Queue operations by outcome. The error rate here is the queue API's error rate.",
		Labels: []string{labelBackend, labelOperation, labelResult},
	})

	queueOperationDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_queue_operation_duration_seconds",
		Help:   "How long a queue operation took inside the storage layer, transport excluded.",
		Labels: []string{labelBackend, labelOperation},
	}, LatencyBuckets)

	messagesSent = NewCounterVec(Definition{
		Name:   Namespace + "_messages_sent_total",
		Help:   "Messages accepted into a queue.",
		Labels: []string{labelQueue},
	})

	messagesSentBytes = NewCounterVec(Definition{
		Name:   Namespace + "_messages_sent_bytes_total",
		Help:   "Message body bytes accepted into a queue.",
		Labels: []string{labelQueue},
	})

	messagesReceived = NewCounterVec(Definition{
		Name:   Namespace + "_messages_received_total",
		Help:   "Messages handed to a consumer. Counts redeliveries, so it exceeds messages_sent when consumers fail.",
		Labels: []string{labelQueue},
	})

	messagesReceivedBytes = NewCounterVec(Definition{
		Name:   Namespace + "_messages_received_bytes_total",
		Help:   "Message body bytes handed to consumers.",
		Labels: []string{labelQueue},
	})

	messagesDeleted = NewCounterVec(Definition{
		Name:   Namespace + "_messages_deleted_total",
		Help:   "Messages acknowledged and removed. Persistently below the receive rate means consumers are failing.",
		Labels: []string{labelQueue},
	})

	messagesDropped = NewCounterVec(Definition{
		Name:   Namespace + "_messages_dropped_total",
		Help:   "Messages evicted by retention or retry exhaustion, by eviction policy.",
		Labels: []string{labelQueue, labelPolicy},
	})

	messagesDeadLettered = NewCounterVec(Definition{
		Name:   Namespace + "_messages_dead_lettered_total",
		Help:   "Messages moved to a dead-letter queue. Anything above zero wants a human.",
		Labels: []string{labelQueue},
	})

	messagesRedelivered = NewCounterVec(Definition{
		Name:   Namespace + "_messages_redelivered_total",
		Help:   "Messages handed out again after a visibility timeout expired.",
		Labels: []string{labelQueue},
	})

	emptyReceives = NewCounterVec(Definition{
		Name:   Namespace + "_empty_receives_total",
		Help:   "Receive calls that found nothing. A high ratio means consumers are polling an idle queue.",
		Labels: []string{labelQueue},
	})

	messagesInFlight = NewGaugeVec(Definition{
		Name:   Namespace + "_messages_in_flight",
		Help:   "Messages claimed by a consumer and not yet acknowledged. Rising and not falling means consumers are stalled.",
		Labels: []string{labelQueue},
	})

	queueDepth = NewGaugeVec(Definition{
		Name:   Namespace + "_queue_depth",
		Help:   "Messages held by a queue. Derived from observed operations and re-based whenever an exact count is taken.",
		Labels: []string{labelQueue},
	})

	messageSize = NewHistogramVec(Definition{
		Name:   Namespace + "_message_size_bytes",
		Help:   "Distribution of message body sizes on send.",
		Labels: []string{labelQueue},
	}, SizeBuckets)

	batchSize = NewHistogramVec(Definition{
		Name:   Namespace + "_batch_size",
		Help:   "Distribution of how many messages a single batched operation carried.",
		Labels: []string{labelQueue, labelOperation},
	}, CountBuckets)

	messageInQueueDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_message_in_queue_duration_seconds",
		Help:   "How long a message sat in a queue before it was delivered.",
		Labels: []string{labelQueue},
	}, SlowBuckets)

	queuesExist = NewGaugeVec(Definition{
		Name:   Namespace + "_queues_exist",
		Help:   "Queues that currently exist.",
		Labels: []string{},
	})
)

// RecordOperation records one queue operation: its outcome and how long it
// took. err is the operation's error, or nil.
func RecordOperation(backend, operation string, start time.Time, err error) {
	queueOperations.With(backend, operation, resultOf(err)).Inc()
	queueOperationDuration.ObserveSince(start, backend, operation)
}

// resultOf maps an error to the shared result label.
func resultOf(err error) string {
	if err != nil {
		return ResultError
	}

	return ResultOK
}

// Result maps an error to the label value the `result` dimension uses, for
// call sites that record it directly.
func Result(err error) string { return resultOf(err) }

// RecordSend records messages accepted into a queue.
func RecordSend(queueID string, count, bytes uint64) {
	if count == 0 {
		return
	}

	messagesSent.Add(count, queueID)
	messagesSentBytes.Add(bytes, queueID)
	messagesInFlight.Add(0, queueID) // Materialize the series so an idle queue still reports zero.
	queueDepth.Add(float64(count), queueID)
	batchSize.Observe(float64(count), queueID, OpSend)
}

// RecordMessageSize records one message body size.
func RecordMessageSize(queueID string, size int) {
	if size < 0 {
		return
	}

	messageSize.Observe(float64(size), queueID)
}

// MessageSizes returns a queue's body-size histogram.
//
// A Send carrying two thousand messages measures two thousand bodies, and
// resolving the histogram by label on each one would put a map lookup on the
// hot path per message to reach a handle that never changes. Batched writers
// take it once and update it directly.
func MessageSizes(queueID string) *Histogram { return messageSize.With(queueID) }

// RecordReceive records a receive. An empty receive is counted separately
// rather than as a zero-count receive: the two mean different things, and
// conflating them hides idle-polling consumers.
func RecordReceive(queueID string, count, bytes uint64) {
	if count == 0 {
		emptyReceives.With(queueID).Inc()

		return
	}

	messagesReceived.Add(count, queueID)
	messagesReceivedBytes.Add(bytes, queueID)
	messagesInFlight.Add(float64(count), queueID)
	batchSize.Observe(float64(count), queueID, OpReceive)
}

// RecordRedelivery records messages that were handed out again after their
// visibility timeout expired.
func RecordRedelivery(queueID string, count uint64) {
	messagesRedelivered.Add(count, queueID)
}

// RecordDelete records acknowledged messages leaving a queue.
func RecordDelete(queueID string, count uint64) {
	if count == 0 {
		return
	}

	messagesDeleted.Add(count, queueID)
	messagesInFlight.Add(-float64(count), queueID)
	queueDepth.Add(-float64(count), queueID)
	batchSize.Observe(float64(count), queueID, OpDelete)
}

// RecordTimeInQueue records how long a delivered message had been waiting.
func RecordTimeInQueue(queueID string, d time.Duration) {
	if d < 0 {
		return
	}

	messageInQueueDuration.ObserveDuration(d, queueID)
}

// RecordDrop records messages evicted by the retention or retry policy.
func RecordDrop(queueID, policy string, count uint64) {
	if count == 0 {
		return
	}

	messagesDropped.Add(count, queueID, policy)
	queueDepth.Add(-float64(count), queueID)
}

// RecordDeadLetter records messages moved to a dead-letter queue. The count
// is attributed to the queue they came from; the arrival is separately
// visible as a send on the dead-letter queue itself.
func RecordDeadLetter(queueID string, count uint64) {
	messagesDeadLettered.Add(count, queueID)
}

// SetQueueDepth re-bases a queue's depth from an exact count.
//
// Depth is tracked by delta on the write path, which is free but drifts if
// anything mutates the store behind its back — a snapshot restore, most
// obviously. Every exact count the server already computes is fed back
// through here, so the gauge self-corrects rather than slowly lying.
func SetQueueDepth(queueID string, depth int64) { queueDepth.Set(float64(depth), queueID) }

// ResetQueue clears the per-queue gauges after a purge or a queue deletion,
// so a deleted queue does not leave a permanent non-zero depth behind.
func ResetQueue(queueID string) {
	queueDepth.Set(0, queueID)
	messagesInFlight.Set(0, queueID)
}

// SetQueuesExist records how many queues exist.
func SetQueuesExist(count int64) { queuesExist.Set(float64(count)) }

// AddQueuesExist moves the queue count by delta.
func AddQueuesExist(delta int64) { queuesExist.Add(float64(delta)) }
