package client

import (
	"context"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestTopicMethodsForwardRequestOptionsAndStatus(t *testing.T) {
	type testCase struct {
		operation string
		request   any
		call      func(context.Context, *Client, any, grpc.CallOption) error
	}

	tests := map[string]testCase{
		"list topics": {
			operation: "list topics",
			request:   &v1.ListTopicsRequest{},
			call: func(ctx context.Context, client *Client, request any, option grpc.CallOption) error {
				_, err := client.ListTopics(ctx, request.(*v1.ListTopicsRequest), option)

				return err
			},
		},
		"create topic": {
			operation: "create topic",
			request:   &v1.CreateTopicRequest{TopicName: "orders"},
			call: func(ctx context.Context, client *Client, request any, option grpc.CallOption) error {
				_, err := client.CreateTopic(ctx, request.(*v1.CreateTopicRequest), option)

				return err
			},
		},
		"delete topic": {
			operation: "delete topic",
			request:   &v1.DeleteTopicRequest{TopicId: "D8VEKIMGOO6F7O6LNLN0"},
			call: func(ctx context.Context, client *Client, request any, option grpc.CallOption) error {
				_, err := client.DeleteTopic(ctx, request.(*v1.DeleteTopicRequest), option)

				return err
			},
		},
		"subscribe": {
			operation: "subscribe",
			request: &v1.SubscribeRequest{
				TopicId: "D8VEKIMGOO6F7O6LNLN0",
				QueueId: "D8VEKIMGOO6F7O6LNLN1",
			},
			call: func(ctx context.Context, client *Client, request any, option grpc.CallOption) error {
				_, err := client.Subscribe(ctx, request.(*v1.SubscribeRequest), option)

				return err
			},
		},
		"unsubscribe": {
			operation: "unsubscribe",
			request: &v1.UnsubscribeRequest{
				TopicId:        "D8VEKIMGOO6F7O6LNLN0",
				SubscriptionId: "D8VEKIMGOO6F7O6LNLN2",
			},
			call: func(ctx context.Context, client *Client, request any, option grpc.CallOption) error {
				_, err := client.Unsubscribe(ctx, request.(*v1.UnsubscribeRequest), option)

				return err
			},
		},
		"publish": {
			operation: "publish",
			request: &v1.PublishRequest{
				TopicId: "D8VEKIMGOO6F7O6LNLN0",
				Messages: []*v1.PublishMessage{
					{Body: []byte("hello")},
				},
			},
			call: func(ctx context.Context, client *Client, request any, option grpc.CallOption) error {
				_, err := client.Publish(ctx, request.(*v1.PublishRequest), option)

				return err
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := &topicServiceClientFake{
				err: status.Error(codes.Unavailable, "storage unavailable"),
			}
			client := &Client{client: fake}
			option := grpc.WaitForReady(true)

			err := tc.call(context.Background(), client, tc.request, option)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("status code = %v, want %v (%v)", status.Code(err), codes.Unavailable, err)
			}
			if !strings.Contains(err.Error(), tc.operation) {
				t.Errorf("error %q does not include operation %q", err, tc.operation)
			}
			if fake.operation != tc.operation {
				t.Errorf("generated client operation = %q, want %q", fake.operation, tc.operation)
			}
			if fake.request != tc.request {
				t.Errorf("request pointer = %p, want exact pointer %p", fake.request, tc.request)
			}
			if len(fake.options) != 1 || !reflect.DeepEqual(fake.options[0], option) {
				t.Errorf("call options = %#v, want [%#v]", fake.options, option)
			}
		})
	}
}

func TestCloseDelegatesToOwnedConnection(t *testing.T) {
	conn, err := grpc.NewClient(
		"passthrough:///unused",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	client := &Client{conn: conn}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	if got := conn.GetState(); got != connectivity.Shutdown {
		t.Errorf("connection state = %v, want %v", got, connectivity.Shutdown)
	}
}

type topicServiceClientFake struct {
	v1.PlainQServiceClient

	operation string
	request   any
	options   []grpc.CallOption
	err       error
}

func (f *topicServiceClientFake) record(operation string, request any, options []grpc.CallOption) {
	f.operation = operation
	f.request = request
	f.options = options
}

func (f *topicServiceClientFake) ListTopics(
	_ context.Context,
	request *v1.ListTopicsRequest,
	options ...grpc.CallOption,
) (*v1.ListTopicsResponse, error) {
	f.record("list topics", request, options)

	return nil, f.err
}

func (f *topicServiceClientFake) CreateTopic(
	_ context.Context,
	request *v1.CreateTopicRequest,
	options ...grpc.CallOption,
) (*v1.CreateTopicResponse, error) {
	f.record("create topic", request, options)

	return nil, f.err
}

func (f *topicServiceClientFake) DeleteTopic(
	_ context.Context,
	request *v1.DeleteTopicRequest,
	options ...grpc.CallOption,
) (*v1.DeleteTopicResponse, error) {
	f.record("delete topic", request, options)

	return nil, f.err
}

func (f *topicServiceClientFake) Subscribe(
	_ context.Context,
	request *v1.SubscribeRequest,
	options ...grpc.CallOption,
) (*v1.SubscribeResponse, error) {
	f.record("subscribe", request, options)

	return nil, f.err
}

func (f *topicServiceClientFake) Unsubscribe(
	_ context.Context,
	request *v1.UnsubscribeRequest,
	options ...grpc.CallOption,
) (*v1.UnsubscribeResponse, error) {
	f.record("unsubscribe", request, options)

	return nil, f.err
}

func (f *topicServiceClientFake) Publish(
	_ context.Context,
	request *v1.PublishRequest,
	options ...grpc.CallOption,
) (*v1.PublishResponse, error) {
	f.record("publish", request, options)

	return nil, f.err
}
