package queue

import (
	"context"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/grpckit"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) ListQueues(ctx context.Context, r *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
	output, listErr := s.storage.ListQueues(ctx, r)
	if listErr != nil {
		return grpckit.ErrorGRPC[*v1.ListQueuesResponse](ctx, listErr)
	}

	return output, nil
}

func (s *Service) DescribeQueue(ctx context.Context, r *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
	if err := validateDescribeQueueRequest(r); err != nil {
		return grpckit.ErrorGRPC[*v1.DescribeQueueResponse](ctx, err)
	}

	output, describeErr := s.storage.DescribeQueue(ctx, r)
	if describeErr != nil {
		return grpckit.ErrorGRPC[*v1.DescribeQueueResponse](ctx, pqerr.AsTransport(describeErr))
	}

	return output, nil
}

func (s *Service) CreateQueue(ctx context.Context, r *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error) {
	output, createErr := s.storage.CreateQueue(ctx, r)
	if createErr != nil {
		return grpckit.ErrorGRPC[*v1.CreateQueueResponse](ctx, createErr)
	}

	return output, nil
}

func (s *Service) DeleteQueue(ctx context.Context, r *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteQueueResponse](ctx, err)
	}

	if _, err := s.storage.DeleteQueue(ctx, r); err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteQueueResponse](ctx, err)
	}

	s.reconcileTopicSubscriptionCounts(ctx)

	return &v1.DeleteQueueResponse{}, nil
}

func (s *Service) PurgeQueue(ctx context.Context, r *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return grpckit.ErrorGRPC[*v1.PurgeQueueResponse](ctx, err)
	}

	output, purgeErr := s.storage.PurgeQueue(ctx, r)
	if purgeErr != nil {
		return grpckit.ErrorGRPC[*v1.PurgeQueueResponse](ctx, purgeErr)
	}

	return output, nil
}

func (s *Service) Send(ctx context.Context, r *v1.SendRequest) (*v1.SendResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return grpckit.ErrorGRPC[*v1.SendResponse](ctx, err)
	}

	output, sendErr := s.storage.Send(ctx, r)
	if sendErr != nil {
		return grpckit.ErrorGRPC[*v1.SendResponse](ctx, sendErr)
	}

	return output, nil
}

func (s *Service) Receive(ctx context.Context, r *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return grpckit.ErrorGRPC[*v1.ReceiveResponse](ctx, err)
	}

	output, receiveErr := s.storage.Receive(ctx, r)
	if receiveErr != nil {
		return grpckit.ErrorGRPC[*v1.ReceiveResponse](ctx, receiveErr)
	}

	return output, nil
}

func (s *Service) Delete(ctx context.Context, r *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteResponse](ctx, err)
	}

	output, deleteErr := s.storage.Delete(ctx, r)
	if deleteErr != nil {
		return grpckit.ErrorGRPC[*v1.DeleteResponse](ctx, deleteErr)
	}

	return output, nil
}

func (s *Service) ListTopics(ctx context.Context, _ *v1.ListTopicsRequest) (*v1.ListTopicsResponse, error) {
	output, err := s.storage.ListTopics(ctx)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.ListTopicsResponse](ctx, pqerr.AsTransport(err))
	}

	topics := make([]*v1.Topic, 0, len(output.Topics))
	for _, topic := range output.Topics {
		topics = append(topics, topicToProto(topic))
	}

	return &v1.ListTopicsResponse{Topics: topics}, nil
}

func (s *Service) CreateTopic(ctx context.Context, r *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error) {
	if r == nil {
		return grpckit.ErrorGRPC[*v1.CreateTopicResponse](ctx, pqerr.AsTransport(pqerr.ErrInvalidInput))
	}

	output, err := s.storage.CreateTopic(ctx, &CreateTopicRequest{TopicName: r.GetTopicName()})
	if err != nil {
		return grpckit.ErrorGRPC[*v1.CreateTopicResponse](ctx, pqerr.AsTransport(err))
	}

	return &v1.CreateTopicResponse{TopicId: output.TopicID}, nil
}

func (s *Service) DeleteTopic(ctx context.Context, r *v1.DeleteTopicRequest) (*v1.DeleteTopicResponse, error) {
	if r == nil {
		return grpckit.ErrorGRPC[*v1.DeleteTopicResponse](ctx, pqerr.AsTransport(pqerr.ErrInvalidInput))
	}

	if err := s.storage.DeleteTopic(ctx, r.GetTopicId()); err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteTopicResponse](ctx, pqerr.AsTransport(err))
	}

	s.reconcileTopicSubscriptionCounts(ctx)

	return &v1.DeleteTopicResponse{}, nil
}

func (s *Service) Subscribe(ctx context.Context, r *v1.SubscribeRequest) (*v1.SubscribeResponse, error) {
	if r == nil {
		return grpckit.ErrorGRPC[*v1.SubscribeResponse](ctx, pqerr.AsTransport(pqerr.ErrInvalidInput))
	}

	if err := validateQueueID(r.GetQueueId()); err != nil {
		return grpckit.ErrorGRPC[*v1.SubscribeResponse](ctx, err)
	}

	output, err := s.storage.Subscribe(ctx, r.GetTopicId(), &SubscribeRequest{QueueID: r.GetQueueId()})
	if err != nil {
		return grpckit.ErrorGRPC[*v1.SubscribeResponse](ctx, pqerr.AsTransport(err))
	}

	s.recordTopicSubscriptionCreated(ctx, r.GetTopicId())

	return &v1.SubscribeResponse{SubscriptionId: output.SubscriptionID}, nil
}

func (s *Service) Unsubscribe(ctx context.Context, r *v1.UnsubscribeRequest) (*v1.UnsubscribeResponse, error) {
	if r == nil {
		return grpckit.ErrorGRPC[*v1.UnsubscribeResponse](ctx, pqerr.AsTransport(pqerr.ErrInvalidInput))
	}

	if err := s.storage.Unsubscribe(ctx, r.GetTopicId(), r.GetSubscriptionId()); err != nil {
		return grpckit.ErrorGRPC[*v1.UnsubscribeResponse](ctx, pqerr.AsTransport(err))
	}

	s.recordTopicSubscriptionDeleted(ctx, r.GetTopicId())

	return &v1.UnsubscribeResponse{}, nil
}

func (s *Service) Publish(ctx context.Context, r *v1.PublishRequest) (*v1.PublishResponse, error) {
	if r == nil {
		return grpckit.ErrorGRPC[*v1.PublishResponse](ctx, pqerr.AsTransport(pqerr.ErrInvalidInput))
	}

	messages := make([]PublishMessage, 0, len(r.GetMessages()))
	for _, message := range r.GetMessages() {
		if message != nil {
			messages = append(messages, PublishMessage{Body: message.GetBody()})
		}
	}

	output, err := s.storage.Publish(ctx, r.GetTopicId(), &PublishRequest{Messages: messages})
	if err != nil {
		return grpckit.ErrorGRPC[*v1.PublishResponse](ctx, pqerr.AsTransport(err))
	}

	if s.topicMetrics != nil {
		s.topicMetrics.RecordTopicPublish(r.GetTopicId(), uint64(len(messages)), deliveredCountToUint64(output.DeliveredCount))
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
