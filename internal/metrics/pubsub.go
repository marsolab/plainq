package metrics

import "time"

// Topic operation names.
const (
	OpCreateTopic  = "create_topic"
	OpDeleteTopic  = "delete_topic"
	OpListTopics   = "list_topics"
	OpPublish      = "publish"
	OpSubscribe    = "subscribe"
	OpUnsubscribe  = "unsubscribe"
	OpListMessages = "list_messages"
)

// Pub/sub metrics.
var (
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
		Help:   "Distribution of how many subscribers a single publish reached.",
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

// RecordTopicOperation records one topic operation and how long it took.
func RecordTopicOperation(backend, operation string, start time.Time, err error) {
	topicOperations.With(backend, operation, resultOf(err)).Inc()
	topicOperationDuration.ObserveSince(start, backend, operation)
}

// RecordPublish records a publish and its fan-out.
//
// delivered and failed are counted separately because a publish reports
// success once it has been accepted, and a subscriber that could not be
// written to would otherwise vanish without trace.
func RecordPublish(topicID string, messages, bytes, delivered, failed uint64) {
	topicMessagesPublished.Add(messages, topicID)
	topicPublishBytes.Add(bytes, topicID)
	topicDeliveries.Add(delivered, topicID)
	topicDeliveryFailures.Add(failed, topicID)

	if messages > 0 {
		topicFanout.Observe(float64(delivered+failed)/float64(messages), topicID)
	}
}

// RecordSubscriptionCreated records a new subscription and the resulting
// subscription count for the topic.
func RecordSubscriptionCreated(topicID string, current int64) {
	topicSubscriptionsCreated.With(topicID).Inc()
	topicSubscriptions.Set(float64(current), topicID)
}

// RecordSubscriptionDeleted records a removed subscription and the resulting
// subscription count for the topic.
func RecordSubscriptionDeleted(topicID string, current int64) {
	topicSubscriptionsDeleted.With(topicID).Inc()
	topicSubscriptions.Set(float64(current), topicID)
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
