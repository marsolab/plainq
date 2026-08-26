package queue

import (
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/shared/pqerr"
)

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

type TopicInventory struct {
	TopicsExist        int64
	SubscriptionCounts map[string]int64
}

type DeleteTopicResult struct {
	RemovedSubscriptions []Subscription `json:"removedSubscriptions"`
}

type DeleteQueueResult struct {
	RemovedSubscriptions []Subscription `json:"removedSubscriptions"`
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

type PublishDeliveryFailure struct {
	QueueID  string `json:"queueId"`
	Messages uint64 `json:"messages"`
	Cause    string `json:"cause"`
}

type PublishOutcome struct {
	Response         *PublishResponse         `json:"response"`
	Partial          bool                     `json:"partial"`
	SelectedQueues   uint64                   `json:"selectedQueues"`
	FailedDeliveries uint64                   `json:"failedDeliveries"`
	DeliveryFailures []PublishDeliveryFailure `json:"deliveryFailures"`
}

type PartialPublishError struct {
	Outcome PublishOutcome
	Causes  []error
}

func (e *PartialPublishError) Error() string {
	return fmt.Sprintf(
		"%s: %d queue messages failed across %d destinations",
		pqerr.ErrPartialFanout,
		e.Outcome.FailedDeliveries,
		len(e.Outcome.DeliveryFailures),
	)
}

func (e *PartialPublishError) Unwrap() []error {
	errs := make([]error, 0, len(e.Causes)+1)
	errs = append(errs, pqerr.ErrPartialFanout)
	errs = append(errs, e.Causes...)

	return errs
}
