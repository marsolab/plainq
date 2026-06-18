package queue

import "time"

// Topic represents a pub/sub topic and its queue subscriptions.
type Topic struct {
	TopicID       string         `json:"topicId"`
	TopicName     string         `json:"topicName"`
	CreatedAt     time.Time      `json:"createdAt"`
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
}

// Subscription represents a queue subscribed to a pub/sub topic.
type Subscription struct {
	SubscriptionID string    `json:"subscriptionId"`
	TopicID        string    `json:"topicId"`
	QueueID        string    `json:"queueId"`
	QueueName      string    `json:"queueName,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// ListTopicsResponse represents a response containing all pub/sub topics.
type ListTopicsResponse struct {
	Topics []Topic `json:"topics"`
}

// CreateTopicRequest represents the request to create a pub/sub topic.
type CreateTopicRequest struct {
	TopicName string `json:"topicName"`
}

// CreateTopicResponse represents the response to a create-topic request.
type CreateTopicResponse struct {
	TopicID string `json:"topicId"`
}

// SubscribeRequest represents the request to subscribe a queue to a topic.
type SubscribeRequest struct {
	QueueID string `json:"queueId"`
}

// SubscribeResponse represents the response to a topic-subscription request.
type SubscribeResponse struct {
	SubscriptionID string `json:"subscriptionId"`
}

// PublishRequest represents the request to publish messages to a topic.
type PublishRequest struct {
	Messages []PublishMessage `json:"messages"`
}

// PublishMessage represents a message published to a topic.
type PublishMessage struct {
	Body []byte `json:"body"`
}

// PublishResponse represents the fan-out result of publishing to a topic.
type PublishResponse struct {
	TopicID        string   `json:"topicId"`
	QueueIDs       []string `json:"queueIds"`
	MessageIDs     []string `json:"messageIds"`
	DeliveredCount int      `json:"deliveredCount"`
}
