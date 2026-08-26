//nolint:wrapcheck // The application boundary preserves transport-neutral storage and domain errors unchanged.
package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

type pubSubApplication struct {
	storage  Storage
	observer *telemetry.Observer
	logger   *slog.Logger
}

func newPubSubApplication(storage Storage, observer *telemetry.Observer, logger *slog.Logger) *pubSubApplication {
	return &pubSubApplication{storage: storage, observer: observer, logger: logger}
}

func (a *pubSubApplication) listTopics(ctx context.Context, input *ListTopicsRequest) (_ *ListTopicsResponse, err error) {
	started := time.Now()
	defer func() { a.observer.TopicRequest(metrics.OpListTopics, "", started, err) }()

	validationErr := validateListTopicsRequest(input)
	if validationErr != nil {
		err = validationErr

		return nil, validationErr
	}

	output, storageErr := a.storage.ListTopics(ctx)
	err = storageErr

	return output, storageErr
}

func (a *pubSubApplication) createTopic(ctx context.Context, input *CreateTopicRequest) (_ *CreateTopicResponse, err error) {
	started := time.Now()
	attributedTopicID := ""

	defer func() { a.observer.TopicRequest(metrics.OpCreateTopic, attributedTopicID, started, err) }()

	validationErr := validateCreateTopicRequest(input)
	if validationErr != nil {
		err = validationErr

		return nil, validationErr
	}

	output, storageErr := a.storage.CreateTopic(ctx, input)
	err = storageErr
	if storageErr != nil {
		return output, storageErr
	}

	if output != nil {
		attributedTopicID = output.TopicID
	}

	a.reconcileTopicState(ctx)

	return output, nil
}

func (a *pubSubApplication) deleteTopic(ctx context.Context, topicID string) (err error) {
	started := time.Now()
	attributedTopicID := ""

	defer func() { a.observer.TopicRequest(metrics.OpDeleteTopic, attributedTopicID, started, err) }()

	validationErr := validateTopicID(topicID)
	if validationErr != nil {
		err = validationErr

		return validationErr
	}

	attributedTopicID = topicID

	output, storageErr := a.storage.DeleteTopic(ctx, topicID)
	err = storageErr
	if storageErr != nil {
		return storageErr
	}

	if output != nil {
		for _, subscription := range output.RemovedSubscriptions {
			a.observer.TopicSubscriptionDeleted(subscription.TopicID)
		}
	}

	a.reconcileTopicState(ctx)

	return nil
}

func (a *pubSubApplication) subscribe(
	ctx context.Context,
	topicID string,
	input *SubscribeRequest,
) (_ *SubscribeResponse, err error) {
	started := time.Now()
	attributedTopicID := ""

	defer func() { a.observer.TopicRequest(metrics.OpSubscribe, attributedTopicID, started, err) }()

	validationErr := validateTopicID(topicID)
	if validationErr != nil {
		err = validationErr

		return nil, validationErr
	}

	attributedTopicID = topicID

	if input == nil {
		err = fmt.Errorf("%w: subscribe request is required", pqerr.ErrInvalidInput)

		return nil, err
	}

	validationErr = validatePubSubQueueID(input.QueueID)
	if validationErr != nil {
		err = validationErr

		return nil, validationErr
	}

	output, storageErr := a.storage.Subscribe(ctx, topicID, input)
	err = storageErr
	if storageErr != nil {
		return output, storageErr
	}

	a.observer.TopicSubscriptionCreated(topicID)
	a.reconcileTopicState(ctx)

	return output, nil
}

func (a *pubSubApplication) unsubscribe(ctx context.Context, topicID, subscriptionID string) (err error) {
	started := time.Now()
	attributedTopicID := ""

	defer func() { a.observer.TopicRequest(metrics.OpUnsubscribe, attributedTopicID, started, err) }()

	validationErr := validateTopicID(topicID)
	if validationErr != nil {
		err = validationErr

		return validationErr
	}

	attributedTopicID = topicID

	validationErr = validateSubscriptionID(subscriptionID)
	if validationErr != nil {
		err = validationErr

		return validationErr
	}

	storageErr := a.storage.Unsubscribe(ctx, topicID, subscriptionID)
	err = storageErr
	if storageErr != nil {
		return storageErr
	}

	a.observer.TopicSubscriptionDeleted(topicID)
	a.reconcileTopicState(ctx)

	return nil
}

func (a *pubSubApplication) publish(
	ctx context.Context,
	topicID string,
	input *PublishRequest,
) (_ *PublishResponse, err error) {
	started := time.Now()
	attributedTopicID := ""

	defer func() { a.observer.TopicRequest(metrics.OpPublish, attributedTopicID, started, err) }()

	validationErr := validateTopicID(topicID)
	if validationErr != nil {
		err = validationErr

		return nil, validationErr
	}

	attributedTopicID = topicID

	if input == nil || len(input.Messages) == 0 {
		err = fmt.Errorf("%w: at least one publish message is required", pqerr.ErrInvalidInput)

		return nil, err
	}

	output, storageErr := a.storage.Publish(ctx, topicID, input)
	err = storageErr
	if errors.Is(storageErr, consensus.ErrCommitUnknown) {
		return output, storageErr
	}

	knownOutput := output
	knownOutcome := storageErr == nil && output != nil

	var partial *PartialPublishError
	if errors.As(storageErr, &partial) {
		knownOutcome = true

		if knownOutput == nil {
			knownOutput = partial.Outcome.Response
		}
	}
	if knownOutcome {
		a.observer.Published(telemetry.TopicPublishEvent{
			TopicID:      topicID,
			Messages:     uint64(len(input.Messages)),
			Bytes:        publishedBodyBytes(input.Messages),
			Destinations: selectedDestinations(knownOutput, storageErr),
			Delivered:    deliveredCount(knownOutput),
			Failed:       failedDeliveries(storageErr),
		})
	}

	return output, storageErr
}

//nolint:unparam // The internal result carries exact cascade effects even though public transports intentionally discard it.
func (a *pubSubApplication) deleteQueue(
	ctx context.Context,
	input *v1.DeleteQueueRequest,
) (*DeleteQueueResult, error) {
	if input == nil {
		return nil, fmt.Errorf("%w: delete queue request is required", pqerr.ErrInvalidID)
	}
	if err := validatePubSubQueueID(input.GetQueueId()); err != nil {
		return nil, err
	}

	output, err := a.storage.DeleteQueue(ctx, input)
	if err != nil {
		return output, err
	}
	if output != nil {
		for _, subscription := range output.RemovedSubscriptions {
			a.observer.TopicSubscriptionDeleted(subscription.TopicID)
		}
	}

	a.reconcileTopicState(ctx)

	return output, nil
}

func (a *pubSubApplication) reconcileTopicState(ctx context.Context) {
	state, err := a.storage.TopicInventory(ctx)
	if err != nil {
		a.observer.TopicStateUnavailable()
		a.observer.StorageError("topic_inventory")
		a.logger.WarnContext(ctx, "reconcile topic telemetry", slog.String("error", err.Error()))

		return
	}

	a.observer.ReconcileTopicState(telemetry.TopicStateEvent{
		TopicsExist:   state.TopicsExist,
		Subscriptions: state.SubscriptionCounts,
	})
}

func selectedDestinations(output *PublishResponse, err error) uint64 {
	var partial *PartialPublishError
	if errors.As(err, &partial) {
		return partial.Outcome.SelectedQueues
	}
	if output == nil {
		return 0
	}

	return uint64(len(output.QueueIDs))
}

func deliveredCount(output *PublishResponse) uint64 {
	if output == nil || output.DeliveredCount <= 0 {
		return 0
	}

	return uint64(output.DeliveredCount)
}

func failedDeliveries(err error) uint64 {
	var partial *PartialPublishError
	if errors.As(err, &partial) {
		return partial.Outcome.FailedDeliveries
	}

	return 0
}

func publishedBodyBytes(messages []PublishMessage) uint64 {
	var total uint64
	for _, message := range messages {
		total += uint64(len(message.Body))
	}

	return total
}
