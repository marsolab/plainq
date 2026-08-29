package metrics

import "time"

// Topic operation names.
const (
	OpCreateTopic = "create_topic"
	OpDeleteTopic = "delete_topic"
	OpListTopics  = "list_topics"
	OpPublish     = "publish"
	OpSubscribe   = "subscribe"
	OpUnsubscribe = "unsubscribe"
)

// Pub/sub metrics.
var (
	topicRequests = NewCounterVec(Definition{
		Name:   Namespace + "_topic_requests_total",
		Help:   "Decoded topic requests by outcome.",
		Labels: []string{labelBackend, labelOperation, labelResult},
	})

	topicRequestDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_topic_request_duration_seconds",
		Help:   "How long a decoded topic request took at the application boundary.",
		Labels: []string{labelBackend, labelOperation},
	}, LatencyBuckets)

	topicOperations = NewCounterVec(Definition{
		Name:   Namespace + "_topic_operations_total",
		Help:   "Topic operations by outcome.",
		Labels: []string{labelBackend, labelOperation, labelResult},
	})

	topicOperationDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_topic_operation_duration_seconds",
		Help:   "How long a topic operation took inside the storage layer.",
		Labels: []string{labelBackend, labelOperation},
	}, LatencyBuckets)

	topicMessagesPublished = NewCounterVec(Definition{
		Name:   Namespace + "_topic_messages_published_total",
		Help:   "Messages published to a topic, counted once per publish regardless of fan-out.",
		Labels: []string{labelTopic},
	})

	topicPublishBytes = NewCounterVec(Definition{
		Name:   Namespace + "_topic_published_bytes_total",
		Help:   "Message body bytes published to a topic.",
		Labels: []string{labelTopic},
	})

	topicDeliveries = NewCounterVec(Definition{
		Name:   Namespace + "_topic_deliveries_total",
		Help:   "Individual deliveries to subscriber queues. One publish to three subscribers is three deliveries.",
		Labels: []string{labelTopic},
	})

	topicDeliveryFailures = NewCounterVec(Definition{
		Name:   Namespace + "_topic_delivery_failures_total",
		Help:   "Deliveries that failed to reach a subscriber queue. Publishing is best-effort per subscriber, so this is the only place a lost fan-out shows up.",
		Labels: []string{labelTopic},
	})

	topicFanout = NewHistogramVec(Definition{
		Name:   Namespace + "_topic_fanout",
		Help:   "Distribution of how many subscriber destinations a single publish selected.",
		Labels: []string{labelTopic},
	}, CountBuckets)

	topicSubscriptions = NewGaugeVec(Definition{
		Name:   Namespace + "_topic_subscriptions",
		Help:   "Subscriptions currently attached to a topic.",
		Labels: []string{labelTopic},
	})

	topicSubscriptionsCreated = NewCounterVec(Definition{
		Name:   Namespace + "_topic_subscriptions_created_total",
		Help:   "Subscriptions created on a topic.",
		Labels: []string{labelTopic},
	})

	topicSubscriptionsDeleted = NewCounterVec(Definition{
		Name:   Namespace + "_topic_subscriptions_deleted_total",
		Help:   "Subscriptions removed from a topic.",
		Labels: []string{labelTopic},
	})

	topicsExist = NewGaugeVec(Definition{
		Name:   Namespace + "_topics_exist",
		Help:   "Topics that currently exist.",
		Labels: []string{},
	})
)

// RecordTopicRequest records one decoded public topic request and its elapsed
// application-boundary duration.
func RecordTopicRequest(backend, operation, result string, elapsed time.Duration) {
	validateTopicMetricVocabulary(backend, operation, result)
	topicRequests.With(backend, operation, result).Inc()
	topicRequestDuration.ObserveDuration(elapsed, backend, operation)
}

// RecordTopicOperation records one topic storage operation and its elapsed
// duration.
func RecordTopicOperation(backend, operation, result string, elapsed time.Duration) {
	validateTopicMetricVocabulary(backend, operation, result)
	topicOperations.With(backend, operation, result).Inc()
	topicOperationDuration.ObserveDuration(elapsed, backend, operation)
}

// RecordPublish records a publish and its fan-out.
//
// delivered and failed are counted separately because a publish reports
// success once it has been accepted, and a subscriber that could not be
// written to would otherwise vanish without trace.
func RecordPublish(topicID string, messages, bytes, destinations, delivered, failed uint64) {
	topicMessagesPublished.Add(messages, topicID)
	topicPublishBytes.Add(bytes, topicID)
	topicDeliveries.Add(delivered, topicID)
	topicDeliveryFailures.Add(failed, topicID)
	topicFanout.Observe(float64(destinations), topicID)
}

// RecordSubscriptionCreated records a new subscription lifecycle event.
func RecordSubscriptionCreated(topicID string) {
	topicSubscriptionsCreated.With(topicID).Inc()
}

// RecordSubscriptionDeleted records a removed subscription lifecycle event.
func RecordSubscriptionDeleted(topicID string) {
	topicSubscriptionsDeleted.With(topicID).Inc()
}

// SetTopicSubscriptions records a topic's subscription count from an exact
// reading, which is how the count is re-based after a restart or a restore.
func SetTopicSubscriptions(topicID string, current int64) {
	topicSubscriptions.Set(float64(current), topicID)
}

// SetTopicsExist records how many topics exist.
func SetTopicsExist(count int64) { topicsExist.Set(float64(count)) }

// ResetTopic clears a topic's gauges when it is deleted.
func ResetTopic(topicID string) { topicSubscriptions.Set(0, topicID) }

func validateTopicMetricVocabulary(backend, operation, result string) {
	if !validTopicBackend(backend) {
		panic("metrics: unknown topic backend: " + backend)
	}

	if !validTopicOperation(operation) {
		panic("metrics: unknown topic operation: " + operation)
	}

	if result != ResultOK && result != ResultError {
		panic("metrics: unknown topic result: " + result)
	}
}

func validTopicBackend(backend string) bool {
	switch backend {
	case BackendSQLite, BackendTurso, BackendPostgres, BackendCluster:
		return true
	default:
		return false
	}
}

func validTopicOperation(operation string) bool {
	switch operation {
	case OpCreateTopic, OpDeleteTopic, OpListTopics, OpPublish, OpSubscribe, OpUnsubscribe:
		return true
	default:
		return false
	}
}
