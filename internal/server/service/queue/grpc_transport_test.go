package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/maxatome/go-testdeep/td"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_1(t *testing.T) {
	r := &v1.DescribeQueueResponse{
		QueueId:                  "UD",
		QueueName:                "Nme",
		CreatedAt:                timestamppb.New(time.Now()),
		RetentionPeriodSeconds:   60,
		VisibilityTimeoutSeconds: 30,
		MaxReceiveAttempts:       5,
		EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DROP,
		DeadLetterQueueId:        "ID",
	}

	jsonout, err := json.Marshal(r)
	td.CmpNoError(t, err)

	t.Log("jsonoutgfh", string(jsonout))
}

func TestServer_ListQueues(t *testing.T) {
	type tcase struct {
		storage *mockStorage
		req     *v1.ListQueuesRequest

		want    *v1.ListQueuesResponse
		wantErr error
	}

	tests := map[string]tcase{
		"OK": {
			storage: &mockStorage{
				listQueuesFunc: func(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
					output := v1.ListQueuesResponse{
						Queues: []*v1.DescribeQueueResponse{
							{
								QueueId:                  "test-id",
								QueueName:                "test-name",
								CreatedAt:                timestamppb.New(time.Unix(100500, 100500)),
								RetentionPeriodSeconds:   60,
								VisibilityTimeoutSeconds: 30,
								MaxReceiveAttempts:       5,
								EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DROP,
							},
						},
					}

					return &output, nil
				},
			},

			req: &v1.ListQueuesRequest{},

			want: &v1.ListQueuesResponse{
				Queues: []*v1.DescribeQueueResponse{
					{
						QueueId:                  "test-id",
						QueueName:                "test-name",
						CreatedAt:                timestamppb.New(time.Unix(100500, 100500)),
						RetentionPeriodSeconds:   60,
						VisibilityTimeoutSeconds: 30,
						MaxReceiveAttempts:       5,
						EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DROP,
					},
				},
			},

			wantErr: nil,
		},
		"Err": {
			storage: &mockStorage{
				listQueuesFunc: func(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
					return nil, errors.New("test error")
				},
			},
			req:     &v1.ListQueuesRequest{},
			want:    nil,
			wantErr: status.Error(codes.Internal, codes.Internal.String()),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := &Service{
				storage: tc.storage,
			}

			res, err := server.ListQueues(context.Background(), tc.req)
			td.CmpErrorIs(t, err, tc.wantErr)
			if tc.wantErr == nil {
				td.Cmp(t, res, tc.want)
			}
		})
	}

}

func TestServer_DescribeQueue(t *testing.T) {
	queueID := "c5s8b4p9e8rg5u5fgq10"
	queue := &v1.DescribeQueueResponse{QueueId: queueID, QueueName: "platform.events"}

	tests := map[string]struct {
		request  *v1.DescribeQueueRequest
		storage  *mockStorage
		wantCode codes.Code
		want     *v1.DescribeQueueResponse
	}{
		"looks up by name": {
			request: &v1.DescribeQueueRequest{QueueName: "platform.events"},
			storage: &mockStorage{
				describeQueueFunc: func(_ context.Context, input *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
					td.Cmp(t, input.GetQueueId(), "")
					td.Cmp(t, input.GetQueueName(), "platform.events")

					return queue, nil
				},
			},
			want: queue,
		},
		"queue ID takes precedence when both lookup keys are present": {
			request: &v1.DescribeQueueRequest{QueueId: queueID, QueueName: "ignored-by-storage"},
			storage: &mockStorage{
				describeQueueFunc: func(_ context.Context, input *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
					td.Cmp(t, input.GetQueueId(), queueID)

					return queue, nil
				},
			},
			want: queue,
		},
		"missing queue returns NotFound": {
			request: &v1.DescribeQueueRequest{QueueName: "not-created"},
			storage: &mockStorage{
				describeQueueFunc: func(context.Context, *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
					return nil, pqerr.ErrNotFound
				},
			},
			wantCode: codes.NotFound,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTestGRPCClient(t, &Service{storage: tc.storage})

			got, err := client.DescribeQueue(context.Background(), tc.request)
			if tc.wantCode != codes.OK {
				td.Cmp(t, status.Code(err), tc.wantCode)

				return
			}

			td.CmpNoError(t, err)
			if !proto.Equal(got, tc.want) {
				t.Errorf("DescribeQueue() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServer_DeleteQueueFailedPrecondition(t *testing.T) {
	server := &Service{storage: &mockStorage{
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
			return nil, pqerr.ErrFailedPrecondition
		},
	}}

	_, err := server.DeleteQueue(context.Background(), &v1.DeleteQueueRequest{QueueId: validXID})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("DeleteQueue status = %s, want %s", got, codes.FailedPrecondition)
	}
}

func TestProtectedLegacyGRPCQueueOperationsUseTenantRBAC(t *testing.T) {
	const queueID = "c5s8b4p9e8rg5u5fgq10"
	ctx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "human-a", TenantID: "tenant-a",
	})

	tests := []struct {
		name       string
		permission middleware.PermissionType
		invoke     func(*Service) error
	}{
		{
			name: "delete queue", permission: middleware.PermissionDelete,
			invoke: func(service *Service) error {
				_, err := service.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID})

				return err
			},
		},
		{
			name: "purge queue", permission: middleware.PermissionPurge,
			invoke: func(service *Service) error {
				_, err := service.PurgeQueue(ctx, &v1.PurgeQueueRequest{QueueId: queueID})

				return err
			},
		},
		{
			name: "send", permission: middleware.PermissionSend,
			invoke: func(service *Service) error {
				_, err := service.Send(ctx, &v1.SendRequest{QueueId: queueID})

				return err
			},
		},
		{
			name: "receive", permission: middleware.PermissionReceive,
			invoke: func(service *Service) error {
				_, err := service.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID})

				return err
			},
		},
		{
			name: "acknowledge", permission: middleware.PermissionDelete,
			invoke: func(service *Service) error {
				_, err := service.Delete(ctx, &v1.DeleteRequest{QueueId: queueID})

				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{
				cfg: &config.Config{GRPCProtectLegacy: true}, storage: authorizedLegacyStorage(queueID, "topic-a"),
			}
			service.SetPermissionChecker(testPermissionCheckerFunc(func(
				_ context.Context,
				userID, gotQueueID string,
				permission middleware.PermissionType,
			) (bool, error) {
				if userID != "human-a" || gotQueueID != queueID || permission != test.permission {
					t.Fatalf("permission check = user %q queue %q permission %q", userID, gotQueueID, permission)
				}

				return false, nil
			}))

			err := test.invoke(service)
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("operation code = %s, want %s (error %v)", got, codes.PermissionDenied, err)
			}
		})
	}
}

func TestEveryGeneratedProtectedLegacyRPCIsAuthorized(t *testing.T) {
	const (
		queueID = "c5s8b4p9e8rg5u5fgq10"
		topicID = "topic-a"
	)
	ctx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "human-a", TenantID: "tenant-a", Roles: []string{"member"},
	})

	invocations := map[string]func(*Service) error{
		v1.PlainQService_ListQueues_FullMethodName: func(service *Service) error {
			_, err := service.ListQueues(ctx, &v1.ListQueuesRequest{})

			return err
		},
		v1.PlainQService_DescribeQueue_FullMethodName: func(service *Service) error {
			_, err := service.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID})

			return err
		},
		v1.PlainQService_CreateQueue_FullMethodName: func(service *Service) error {
			_, err := service.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "orders"})

			return err
		},
		v1.PlainQService_PurgeQueue_FullMethodName: func(service *Service) error {
			_, err := service.PurgeQueue(ctx, &v1.PurgeQueueRequest{QueueId: queueID})

			return err
		},
		v1.PlainQService_DeleteQueue_FullMethodName: func(service *Service) error {
			_, err := service.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID})

			return err
		},
		v1.PlainQService_Send_FullMethodName: func(service *Service) error {
			_, err := service.Send(ctx, &v1.SendRequest{QueueId: queueID})

			return err
		},
		v1.PlainQService_Receive_FullMethodName: func(service *Service) error {
			_, err := service.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID})

			return err
		},
		v1.PlainQService_Delete_FullMethodName: func(service *Service) error {
			_, err := service.Delete(ctx, &v1.DeleteRequest{QueueId: queueID})

			return err
		},
		v1.PlainQService_ListTopics_FullMethodName: func(service *Service) error {
			_, err := service.ListTopics(ctx, &v1.ListTopicsRequest{})

			return err
		},
		v1.PlainQService_CreateTopic_FullMethodName: func(service *Service) error {
			_, err := service.CreateTopic(ctx, &v1.CreateTopicRequest{TopicName: "events"})

			return err
		},
		v1.PlainQService_DeleteTopic_FullMethodName: func(service *Service) error {
			_, err := service.DeleteTopic(ctx, &v1.DeleteTopicRequest{TopicId: topicID})

			return err
		},
		v1.PlainQService_Subscribe_FullMethodName: func(service *Service) error {
			_, err := service.Subscribe(ctx, &v1.SubscribeRequest{TopicId: topicID, QueueId: queueID})

			return err
		},
		v1.PlainQService_Unsubscribe_FullMethodName: func(service *Service) error {
			_, err := service.Unsubscribe(ctx, &v1.UnsubscribeRequest{TopicId: topicID, SubscriptionId: "sub-a"})

			return err
		},
		v1.PlainQService_Publish_FullMethodName: func(service *Service) error {
			_, err := service.Publish(ctx, &v1.PublishRequest{TopicId: topicID})

			return err
		},
	}

	generated := make(map[string]struct{}, len(v1.PlainQService_ServiceDesc.Methods))
	for _, method := range v1.PlainQService_ServiceDesc.Methods {
		fullMethod := fmt.Sprintf("/%s/%s", v1.PlainQService_ServiceDesc.ServiceName, method.MethodName)
		generated[fullMethod] = struct{}{}
		if _, ok := invocations[fullMethod]; !ok {
			t.Errorf("generated legacy method %q lacks a denial regression", fullMethod)
		}
		if policy, ok := legacyV1Policies[fullMethod]; !ok || policy.authorization == 0 {
			t.Errorf("generated legacy method %q lacks an explicit authorization policy", fullMethod)
		}
	}
	if len(invocations) != len(generated) || len(legacyV1Policies) != len(generated) {
		t.Fatalf(
			"legacy inventories = %d denial regressions / %d policies, generated service has %d methods",
			len(invocations), len(legacyV1Policies), len(generated),
		)
	}

	for method, invoke := range invocations {
		t.Run(method, func(t *testing.T) {
			storage := authorizedLegacyStorage(queueID, topicID)
			service := &Service{cfg: &config.Config{GRPCProtectLegacy: true}, storage: storage}
			service.SetPermissionChecker(testPermissionCheckerFunc(func(
				context.Context, string, string, middleware.PermissionType,
			) (bool, error) {
				return false, nil
			}))

			if err := invoke(service); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("protected legacy method code = %s, want %s (error %v)",
					status.Code(err), codes.PermissionDenied, err)
			}
		})
	}
}

func TestProtectedLegacyCrossTenantResourcesAreHidden(t *testing.T) {
	const queueID = "c5s8b4p9e8rg5u5fgq10"
	ctx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "admin-a", TenantID: "tenant-a", Roles: []string{"admin"},
	})
	service := &Service{
		cfg: &config.Config{GRPCProtectLegacy: true},
		storage: &mockStorage{
			describeQueueFunc: func(context.Context, *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
				return nil, pqerr.ErrNotFound
			},
			sendFunc: func(context.Context, *v1.SendRequest) (*v1.SendResponse, error) {
				return &v1.SendResponse{}, nil
			},
			listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
				return &ListTopicsResponse{}, nil
			},
		},
	}
	service.SetPermissionChecker(testPermissionCheckerFunc(func(
		context.Context, string, string, middleware.PermissionType,
	) (bool, error) {
		return false, nil
	}))

	invocations := map[string]func() error{
		"describe queue": func() error {
			_, err := service.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID})

			return err
		},
		"purge queue": func() error {
			_, err := service.PurgeQueue(ctx, &v1.PurgeQueueRequest{QueueId: queueID})

			return err
		},
		"delete queue": func() error {
			_, err := service.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID})

			return err
		},
		"send": func() error {
			_, err := service.Send(ctx, &v1.SendRequest{QueueId: queueID})

			return err
		},
		"receive": func() error {
			_, err := service.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID})

			return err
		},
		"acknowledge": func() error {
			_, err := service.Delete(ctx, &v1.DeleteRequest{QueueId: queueID})

			return err
		},
		"delete topic": func() error {
			_, err := service.DeleteTopic(ctx, &v1.DeleteTopicRequest{TopicId: "topic-b"})

			return err
		},
		"subscribe": func() error {
			_, err := service.Subscribe(ctx, &v1.SubscribeRequest{TopicId: "topic-b", QueueId: queueID})

			return err
		},
		"unsubscribe": func() error {
			_, err := service.Unsubscribe(ctx, &v1.UnsubscribeRequest{TopicId: "topic-b", SubscriptionId: "sub-b"})

			return err
		},
		"publish": func() error {
			_, err := service.Publish(ctx, &v1.PublishRequest{TopicId: "topic-b"})

			return err
		},
	}

	for name, invoke := range invocations {
		t.Run(name, func(t *testing.T) {
			if err := invoke(); status.Code(err) != codes.NotFound {
				t.Fatalf("cross-tenant resource code = %s, want %s (error %v)",
					status.Code(err), codes.NotFound, err)
			}
		})
	}
}

func TestProtectedLegacySameTenantPoliciesAllowGrantedOperations(t *testing.T) {
	const (
		queueID = "c5s8b4p9e8rg5u5fgq10"
		topicID = "topic-a"
	)
	storage := authorizedLegacyStorage(queueID, topicID)
	memberContext := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "human-a", TenantID: "tenant-a", Roles: []string{"member"},
	})
	service := &Service{cfg: &config.Config{GRPCProtectLegacy: true}, storage: storage}
	service.SetPermissionChecker(testPermissionCheckerFunc(func(
		_ context.Context, userID, gotQueueID string, permission middleware.PermissionType,
	) (bool, error) {
		return userID == "human-a" && gotQueueID == queueID && permission == middleware.PermissionSend, nil
	}))

	if _, err := service.Send(memberContext, &v1.SendRequest{QueueId: queueID}); err != nil {
		t.Fatalf("same-tenant granted queue send: %v", err)
	}

	adminContext := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "admin-a", TenantID: "tenant-a", Roles: []string{"admin"},
	})
	if _, err := service.Publish(adminContext, &v1.PublishRequest{TopicId: topicID}); err != nil {
		t.Fatalf("same-tenant admin topic publish: %v", err)
	}
}

func authorizedLegacyStorage(queueID, topicID string) *mockStorage {
	return &mockStorage{
		listQueuesFunc: func(context.Context, *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
			return &v1.ListQueuesResponse{}, nil
		},
		describeQueueFunc: func(context.Context, *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
			return &v1.DescribeQueueResponse{QueueId: queueID}, nil
		},
		createQueueFunc: func(context.Context, *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error) {
			return &v1.CreateQueueResponse{QueueId: queueID}, nil
		},
		purgeQueueFunc: func(context.Context, *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
			return &v1.PurgeQueueResponse{}, nil
		},
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
			return &v1.DeleteQueueResponse{}, nil
		},
		sendFunc: func(context.Context, *v1.SendRequest) (*v1.SendResponse, error) {
			return &v1.SendResponse{}, nil
		},
		receiveFunc: func(context.Context, *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
			return &v1.ReceiveResponse{}, nil
		},
		deleteFunc: func(context.Context, *v1.DeleteRequest) (*v1.DeleteResponse, error) {
			return &v1.DeleteResponse{}, nil
		},
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{TopicID: topicID}}}, nil
		},
	}
}

func TestServer_TopicRPCs(t *testing.T) {
	createdAt := time.Unix(1_709_000_000, 0).UTC()
	topic := Topic{
		TopicID:   "topic-1",
		TopicName: "platform.events",
		CreatedAt: createdAt,
		Subscriptions: []Subscription{{
			SubscriptionID: "subscription-1",
			TopicID:        "topic-1",
			QueueID:        "c5s8b4p9e8rg5u5fgq10",
			QueueName:      "platform.events",
			CreatedAt:      createdAt,
		}},
	}
	queueID := topic.Subscriptions[0].QueueID

	storage := &mockStorage{
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{topic}}, nil
		},
		createTopicFunc: func(_ context.Context, input *CreateTopicRequest) (*CreateTopicResponse, error) {
			td.Cmp(t, input, &CreateTopicRequest{TopicName: "platform.events"})

			return &CreateTopicResponse{TopicID: topic.TopicID}, nil
		},
		deleteTopicFunc: func(_ context.Context, topicID string) error {
			td.Cmp(t, topicID, topic.TopicID)

			return nil
		},
		subscribeFunc: func(_ context.Context, topicID string, input *SubscribeRequest) (*SubscribeResponse, error) {
			td.Cmp(t, topicID, topic.TopicID)
			td.Cmp(t, input, &SubscribeRequest{QueueID: queueID})

			return &SubscribeResponse{SubscriptionID: topic.Subscriptions[0].SubscriptionID}, nil
		},
		unsubscribeFunc: func(_ context.Context, topicID, subscriptionID string) error {
			td.Cmp(t, topicID, topic.TopicID)
			td.Cmp(t, subscriptionID, topic.Subscriptions[0].SubscriptionID)

			return nil
		},
		publishFunc: func(_ context.Context, topicID string, input *PublishRequest) (*PublishResponse, error) {
			td.Cmp(t, topicID, topic.TopicID)
			td.Cmp(t, input, &PublishRequest{Messages: []PublishMessage{{Body: []byte("hello")}}})

			return &PublishResponse{
				TopicID:        topicID,
				QueueIDs:       []string{queueID},
				MessageIDs:     []string{"message-1"},
				DeliveredCount: 1,
			}, nil
		},
	}
	server := &Service{storage: storage}
	ctx := context.Background()

	listed, err := server.ListTopics(ctx, &v1.ListTopicsRequest{})
	td.CmpNoError(t, err)
	td.Cmp(t, listed, &v1.ListTopicsResponse{Topics: []*v1.Topic{{
		TopicId:   topic.TopicID,
		TopicName: topic.TopicName,
		CreatedAt: timestamppb.New(createdAt),
		Subscriptions: []*v1.Subscription{{
			SubscriptionId: topic.Subscriptions[0].SubscriptionID,
			TopicId:        topic.TopicID,
			QueueId:        queueID,
			QueueName:      topic.Subscriptions[0].QueueName,
			CreatedAt:      timestamppb.New(createdAt),
		}},
	}}})

	created, err := server.CreateTopic(ctx, &v1.CreateTopicRequest{TopicName: topic.TopicName})
	td.CmpNoError(t, err)
	td.Cmp(t, created, &v1.CreateTopicResponse{TopicId: topic.TopicID})

	deleted, err := server.DeleteTopic(ctx, &v1.DeleteTopicRequest{TopicId: topic.TopicID})
	td.CmpNoError(t, err)
	td.Cmp(t, deleted, &v1.DeleteTopicResponse{})

	subscribed, err := server.Subscribe(ctx, &v1.SubscribeRequest{TopicId: topic.TopicID, QueueId: queueID})
	td.CmpNoError(t, err)
	td.Cmp(t, subscribed, &v1.SubscribeResponse{SubscriptionId: topic.Subscriptions[0].SubscriptionID})

	unsubscribed, err := server.Unsubscribe(ctx, &v1.UnsubscribeRequest{
		TopicId:        topic.TopicID,
		SubscriptionId: topic.Subscriptions[0].SubscriptionID,
	})
	td.CmpNoError(t, err)
	td.Cmp(t, unsubscribed, &v1.UnsubscribeResponse{})

	published, err := server.Publish(ctx, &v1.PublishRequest{
		TopicId:  topic.TopicID,
		Messages: []*v1.PublishMessage{{Body: []byte("hello")}},
	})
	td.CmpNoError(t, err)
	td.Cmp(t, published, &v1.PublishResponse{
		TopicId:        topic.TopicID,
		QueueIds:       []string{queueID},
		MessageIds:     []string{"message-1"},
		DeliveredCount: 1,
	})
}

func newTestGRPCClient(t *testing.T, service v1.PlainQServiceServer) v1.PlainQServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	v1.RegisterPlainQServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	td.Require(t).CmpNoError(err, "dial in-memory gRPC server")
	t.Cleanup(func() { td.CmpNoError(t, conn.Close(), "close gRPC connection") })

	return v1.NewPlainQServiceClient(conn)
}
