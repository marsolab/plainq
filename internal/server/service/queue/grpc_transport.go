package queue

import (
	"context"
	"errors"
	"fmt"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/ctxkit"
	"github.com/marsolab/servekit/grpckit"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) ListQueues(ctx context.Context, r *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
	output, listErr := s.policyOperations().ListQueues(ctx, r)
	if listErr != nil {
		return queueGRPCError[*v1.ListQueuesResponse](ctx, listErr)
	}

	return output, nil
}

func (s *Service) DescribeQueue(ctx context.Context, r *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
	if err := validateDescribeQueueRequest(r); err != nil {
		return queueGRPCError[*v1.DescribeQueueResponse](ctx, err)
	}

	output, describeErr := s.policyOperations().DescribeQueue(ctx, r)
	if describeErr != nil {
		return queueGRPCError[*v1.DescribeQueueResponse](ctx, pqerr.AsTransport(describeErr))
	}

	return output, nil
}

func (s *Service) CreateQueue(ctx context.Context, r *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error) {
	output, createErr := s.policyOperations().CreateQueue(ctx, r)
	if createErr != nil {
		return queueGRPCError[*v1.CreateQueueResponse](ctx, createErr)
	}

	return output, nil
}

func (s *Service) DeleteQueue(ctx context.Context, r *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
	if _, err := s.pubsub.deleteQueue(ctx, r); err != nil {
		if errors.Is(err, pqerr.ErrFailedPrecondition) {
			return failedPreconditionGRPC(ctx, err)
		}

		return queueGRPCError[*v1.DeleteQueueResponse](ctx, err)
	}

	return &v1.DeleteQueueResponse{}, nil
}

//nolint:wrapcheck // Wrapping would hide the exact gRPC status required by the public delete contract.
func failedPreconditionGRPC(ctx context.Context, err error) (*v1.DeleteQueueResponse, error) {
	if hook := ctxkit.GetLogErrHook(ctx); hook != nil {
		hook(err)
	}

	return nil, status.Error(codes.FailedPrecondition, codes.FailedPrecondition.String())
}

func (s *Service) PurgeQueue(ctx context.Context, r *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return queueGRPCError[*v1.PurgeQueueResponse](ctx, err)
	}

	output, purgeErr := s.policyOperations().PurgeQueue(ctx, r)
	if purgeErr != nil {
		return queueGRPCError[*v1.PurgeQueueResponse](ctx, purgeErr)
	}

	return output, nil
}

func (s *Service) Send(ctx context.Context, r *v1.SendRequest) (*v1.SendResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return queueGRPCError[*v1.SendResponse](ctx, err)
	}

	output, sendErr := s.policyOperations().Send(ctx, r)
	if sendErr != nil {
		return queueGRPCError[*v1.SendResponse](ctx, sendErr)
	}

	return output, nil
}

func (s *Service) Receive(ctx context.Context, r *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return queueGRPCError[*v1.ReceiveResponse](ctx, err)
	}

	output, receiveErr := s.policyOperations().Receive(ctx, r)
	if receiveErr != nil {
		return queueGRPCError[*v1.ReceiveResponse](ctx, receiveErr)
	}

	return output, nil
}

func (s *Service) Delete(ctx context.Context, r *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return queueGRPCError[*v1.DeleteResponse](ctx, err)
	}

	output, deleteErr := s.policyOperations().Delete(ctx, r)
	if deleteErr != nil {
		return queueGRPCError[*v1.DeleteResponse](ctx, deleteErr)
	}

	return output, nil
}

func (s *Service) ListTopics(ctx context.Context, r *v1.ListTopicsRequest) (*v1.ListTopicsResponse, error) {
	var input *ListTopicsRequest
	if r != nil {
		input = &ListTopicsRequest{}
	}

	output, err := s.pubsub.listTopics(ctx, input)
	if err != nil {
		return queueGRPCError[*v1.ListTopicsResponse](ctx, pqerr.AsTransport(err))
	}

	topics := make([]*v1.Topic, 0, len(output.Topics))
	for _, topic := range output.Topics {
		topics = append(topics, topicToProto(topic))
	}

	return &v1.ListTopicsResponse{Topics: topics}, nil
}

func (s *Service) CreateTopic(ctx context.Context, r *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error) {
	var input *CreateTopicRequest
	if r != nil {
		input = &CreateTopicRequest{TopicName: r.GetTopicName()}
	}

	output, err := s.pubsub.createTopic(ctx, input)
	if err != nil {
		return queueGRPCError[*v1.CreateTopicResponse](ctx, pqerr.AsTransport(err))
	}

	return &v1.CreateTopicResponse{TopicId: output.TopicID}, nil
}

func (s *Service) DeleteTopic(ctx context.Context, r *v1.DeleteTopicRequest) (*v1.DeleteTopicResponse, error) {
	if err := s.pubsub.deleteTopic(ctx, r.GetTopicId()); err != nil {
		return queueGRPCError[*v1.DeleteTopicResponse](ctx, pqerr.AsTransport(err))
	}

	return &v1.DeleteTopicResponse{}, nil
}

func (s *Service) Subscribe(ctx context.Context, r *v1.SubscribeRequest) (*v1.SubscribeResponse, error) {
	var input *SubscribeRequest
	if r != nil {
		input = &SubscribeRequest{QueueID: r.GetQueueId()}
	}

	output, err := s.pubsub.subscribe(ctx, r.GetTopicId(), input)
	if err != nil {
		return queueGRPCError[*v1.SubscribeResponse](ctx, pqerr.AsTransport(err))
	}

	return &v1.SubscribeResponse{SubscriptionId: output.SubscriptionID}, nil
}

func (s *Service) Unsubscribe(ctx context.Context, r *v1.UnsubscribeRequest) (*v1.UnsubscribeResponse, error) {
	if err := s.pubsub.unsubscribe(ctx, r.GetTopicId(), r.GetSubscriptionId()); err != nil {
		return queueGRPCError[*v1.UnsubscribeResponse](ctx, pqerr.AsTransport(err))
	}

	return &v1.UnsubscribeResponse{}, nil
}

func (s *Service) Publish(ctx context.Context, r *v1.PublishRequest) (*v1.PublishResponse, error) {
	var input *PublishRequest

	if r != nil {
		messages := make([]PublishMessage, 0, len(r.GetMessages()))
		for _, message := range r.GetMessages() {
			if message != nil {
				messages = append(messages, PublishMessage{Body: message.GetBody()})
			}
		}

		input = &PublishRequest{Messages: messages}
	}

	output, err := s.pubsub.publish(ctx, r.GetTopicId(), input)
	if err != nil {
		if errors.Is(err, pqerr.ErrCapacityExceeded) {
			return nil, fmt.Errorf("publish capacity exceeded: %w", status.Error(codes.ResourceExhausted, err.Error()))
		}

		return queueGRPCError[*v1.PublishResponse](ctx, pqerr.AsTransport(err))
	}

	return &v1.PublishResponse{
		TopicId:        output.TopicID,
		QueueIds:       output.QueueIDs,
		MessageIds:     output.MessageIDs,
		DeliveredCount: deliveredCountToUint64(output.DeliveredCount),
	}, nil
}

func deliveredCountToUint64(count int) uint64 {
	if count <= 0 {
		return 0
	}

	return uint64(count)
}

func topicToProto(topic Topic) *v1.Topic {
	subscriptions := make([]*v1.Subscription, 0, len(topic.Subscriptions))
	for _, subscription := range topic.Subscriptions {
		subscriptions = append(subscriptions, &v1.Subscription{
			SubscriptionId: subscription.SubscriptionID,
			TopicId:        subscription.TopicID,
			QueueId:        subscription.QueueID,
			QueueName:      subscription.QueueName,
			CreatedAt:      timestamppb.New(subscription.CreatedAt),
		})
	}

	return &v1.Topic{
		TopicId:       topic.TopicID,
		TopicName:     topic.TopicName,
		CreatedAt:     timestamppb.New(topic.CreatedAt),
		Subscriptions: subscriptions,
	}
}

//nolint:wrapcheck // gRPC status values are finalized at the transport boundary.
func queueGRPCError[T any](ctx context.Context, err error) (T, error) {
	if retryDelay, exhausted := quota.RetryDelay(err); exhausted {
		var zero T

		value := status.New(codes.ResourceExhausted, codes.ResourceExhausted.String())

		withDetails, detailsErr := value.WithDetails(&errdetails.RetryInfo{
			RetryDelay: durationpb.New(retryDelay),
		})
		if detailsErr != nil {
			return zero, value.Err()
		}

		return zero, withDetails.Err()
	}

	return grpckit.ErrorGRPC[T](ctx, pqerr.AsTransport(err))
}
