package queue

import "time"

type Topic struct {
	TopicID       string         `json:"topicId"`
	TopicName     string         `json:"topicName"`
	CreatedAt     time.Time      `json:"createdAt"`
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
}

type Subscription struct {
	SubscriptionID string    `json:"subscriptionId"`
	TopicID        string    `json:"topicId"`
	QueueID        string    `json:"queueId"`
	QueueName      string    `json:"queueName,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

type ListTopicsRequest struct{}

type ListTopicsResponse struct {
	Topics []Topic `json:"topics"`
}

type CreateTopicRequest struct {
	TopicName string `json:"topicName"`
}

type CreateTopicResponse struct {
	TopicID string `json:"topicId"`
}

type SubscribeRequest struct {
	QueueID string `json:"queueId"`
}

type SubscribeResponse struct {
	SubscriptionID string `json:"subscriptionId"`
}

type PublishRequest struct {
	Messages []PublishMessage `json:"messages"`
}

type PublishMessage struct {
	Body []byte `json:"body"`
}

type PublishResponse struct {
	TopicID        string   `json:"topicId"`
	QueueIDs       []string `json:"queueIds"`
	MessageIDs     []string `json:"messageIds"`
	DeliveredCount int      `json:"deliveredCount"`
}
