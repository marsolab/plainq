package queue

import (
	"context"
	"fmt"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// BatchSender sends one complete publish batch to a destination queue.
type BatchSender func(context.Context, *v1.SendRequest) (*v1.SendResponse, error)

// FanOut attempts a publish batch against every selected subscription queue.
func FanOut(
	ctx context.Context,
	topicID string,
	subscriptions []Subscription,
	messages []PublishMessage,
	send BatchSender,
) (*PublishResponse, error) {
	response := &PublishResponse{
		TopicID:    topicID,
		QueueIDs:   make([]string, 0, len(subscriptions)),
		MessageIDs: []string{},
	}
	for _, subscription := range subscriptions {
		response.QueueIDs = append(response.QueueIDs, subscription.QueueID)
	}

	failures := make([]PublishDeliveryFailure, 0)
	causes := make([]error, 0)
	for _, subscription := range subscriptions {
		batch := make([]*v1.SendMessage, 0, len(messages))
		for _, message := range messages {
			batch = append(batch, &v1.SendMessage{Body: message.Body})
		}

		sent, err := send(ctx, &v1.SendRequest{QueueId: subscription.QueueID, Messages: batch})
		if err != nil {
			failures = append(failures, PublishDeliveryFailure{
				QueueID:  subscription.QueueID,
				Messages: uint64(len(messages)),
				Cause:    err.Error(),
			})
			causes = append(causes, fmt.Errorf("publish to queue %q: %w", subscription.QueueID, err))

			continue
		}

		response.MessageIDs = append(response.MessageIDs, sent.GetMessageIds()...)
		response.DeliveredCount += len(sent.GetMessageIds())
	}

	if len(failures) == 0 {
		return response, nil
	}

	return response, &PartialPublishError{
		Outcome: PublishOutcome{
			Response:           response,
			SelectedQueues:     uint64(len(subscriptions)),
			FailedDeliveries:   uint64(len(failures) * len(messages)),
			FailedDestinations: uint64(len(failures)),
			DeliveryFailures:   failures,
		},
		Causes: causes,
	}
}
