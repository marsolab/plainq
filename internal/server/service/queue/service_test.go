package queue

import (
	"context"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

type mockStorage struct {
	createQueueFunc   func(ctx context.Context, input *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error)
	describeQueueFunc func(ctx context.Context, input *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error)
	listQueuesFunc    func(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error)
	purgeQueueFunc    func(ctx context.Context, input *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error)
	deleteQueueFunc   func(ctx context.Context, input *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error)
	sendFunc          func(ctx context.Context, input *v1.SendRequest) (*v1.SendResponse, error)
	receiveFunc       func(ctx context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error)
	deleteFunc        func(ctx context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error)
	peekFunc          func(ctx context.Context, input *PeekRequest) (*PeekResponse, error)
	listTopicsFunc    func(ctx context.Context) (*ListTopicsResponse, error)
	createTopicFunc   func(ctx context.Context, input *CreateTopicRequest) (*CreateTopicResponse, error)
	deleteTopicFunc   func(ctx context.Context, topicID string) error
	subscribeFunc     func(ctx context.Context, topicID string, input *SubscribeRequest) (*SubscribeResponse, error)
	unsubscribeFunc   func(ctx context.Context, topicID, subscriptionID string) error
	publishFunc       func(ctx context.Context, topicID string, input *PublishRequest) (*PublishResponse, error)
}

func (m *mockStorage) CreateQueue(ctx context.Context, input *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error) {
	return m.createQueueFunc(ctx, input)
}

func (m *mockStorage) DescribeQueue(ctx context.Context, input *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
	return m.describeQueueFunc(ctx, input)
}

func (m *mockStorage) ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
	return m.listQueuesFunc(ctx, input)
}

func (m *mockStorage) PurgeQueue(ctx context.Context, input *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
	return m.purgeQueueFunc(ctx, input)
}

func (m *mockStorage) DeleteQueue(ctx context.Context, input *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
	return m.deleteQueueFunc(ctx, input)
}

func (m *mockStorage) Send(ctx context.Context, input *v1.SendRequest) (*v1.SendResponse, error) {
	return m.sendFunc(ctx, input)
}

func (m *mockStorage) Receive(ctx context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	return m.receiveFunc(ctx, input)
}

func (m *mockStorage) Delete(ctx context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	return m.deleteFunc(ctx, input)
}

func (m *mockStorage) Peek(ctx context.Context, input *PeekRequest) (*PeekResponse, error) {
	return m.peekFunc(ctx, input)
}

func (m *mockStorage) ListTopics(ctx context.Context) (*ListTopicsResponse, error) {
	if m.listTopicsFunc != nil {
		return m.listTopicsFunc(ctx)
	}
	return &ListTopicsResponse{}, nil
}

func (m *mockStorage) CreateTopic(ctx context.Context, input *CreateTopicRequest) (*CreateTopicResponse, error) {
	if m.createTopicFunc != nil {
		return m.createTopicFunc(ctx, input)
	}
	return &CreateTopicResponse{}, nil
}

func (m *mockStorage) DeleteTopic(ctx context.Context, topicID string) error {
	if m.deleteTopicFunc != nil {
		return m.deleteTopicFunc(ctx, topicID)
	}
	return nil
}

func (m *mockStorage) Subscribe(ctx context.Context, topicID string, input *SubscribeRequest) (*SubscribeResponse, error) {
	if m.subscribeFunc != nil {
		return m.subscribeFunc(ctx, topicID, input)
	}
	return &SubscribeResponse{}, nil
}

func (m *mockStorage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	if m.unsubscribeFunc != nil {
		return m.unsubscribeFunc(ctx, topicID, subscriptionID)
	}
	return nil
}

func (m *mockStorage) Publish(ctx context.Context, topicID string, input *PublishRequest) (*PublishResponse, error) {
	if m.publishFunc != nil {
		return m.publishFunc(ctx, topicID, input)
	}
	return &PublishResponse{}, nil
}
