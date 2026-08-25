package queue

import (
	"fmt"
	"strings"

	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/idkit"
)

// validateQueueIDFromRequest performs validation of the queue identifier.
func validateQueueIDFromRequest(r interface{ GetQueueId() string }) error {
	if r == nil {
		return errkit.ErrInvalidID
	}

	return validateQueueID(r.GetQueueId())
}

// validateDescribeQueueRequest accepts either documented lookup key. Queue IDs
// take precedence when both are set, matching the protobuf contract.
func validateDescribeQueueRequest(r interface {
	GetQueueId() string
	GetQueueName() string
}) error {
	if r == nil {
		return errkit.ErrInvalidArgument
	}

	if r.GetQueueId() != "" {
		return validateQueueID(r.GetQueueId())
	}

	if r.GetQueueName() == "" {
		return errkit.ErrInvalidArgument
	}

	return nil
}

// validateQueueID validates given queue identifier.
func validateQueueID(queueID string) error {
	if queueID == "" {
		return errkit.ErrInvalidID
	}

	if err := idkit.ValidateXID(strings.ToLower(queueID)); err != nil {
		return errkit.ErrInvalidID
	}

	return nil
}

func validateTopicID(id string) error {
	if err := idkit.ValidateXID(strings.ToLower(id)); err != nil {
		return fmt.Errorf("%w: invalid topic id %q", pqerr.ErrInvalidID, id)
	}

	return nil
}

func validateSubscriptionID(id string) error {
	if err := idkit.ValidateXID(strings.ToLower(id)); err != nil {
		return fmt.Errorf("%w: invalid subscription id %q", pqerr.ErrInvalidID, id)
	}

	return nil
}

func validateListTopicsRequest(input *ListTopicsRequest) error {
	if input == nil {
		return fmt.Errorf("%w: list topics request is required", pqerr.ErrInvalidInput)
	}

	return nil
}

func validateCreateTopicRequest(input *CreateTopicRequest) error {
	if input == nil || strings.TrimSpace(input.TopicName) == "" {
		return fmt.Errorf("%w: topic name is required", pqerr.ErrInvalidInput)
	}

	return nil
}

func validateDeleteTopicRequest(topicID string) error {
	return validateTopicID(topicID)
}

func validateSubscribeRequest(topicID string, input *SubscribeRequest) error {
	if err := validateTopicID(topicID); err != nil {
		return err
	}
	if input == nil {
		return fmt.Errorf("%w: subscribe request is required", pqerr.ErrInvalidInput)
	}

	return validateQueueID(input.QueueID)
}

func validateUnsubscribeRequest(topicID, subscriptionID string) error {
	if err := validateTopicID(topicID); err != nil {
		return err
	}

	return validateSubscriptionID(subscriptionID)
}

func validatePublishRequest(topicID string, input *PublishRequest) error {
	if err := validateTopicID(topicID); err != nil {
		return err
	}
	if input == nil || len(input.Messages) == 0 {
		return fmt.Errorf("%w: at least one publish message is required", pqerr.ErrInvalidInput)
	}

	return nil
}
