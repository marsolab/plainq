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
