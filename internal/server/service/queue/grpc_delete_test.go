package queue

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/ctxkit"
	"github.com/marsolab/servekit/idkit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCDeleteTopicMapsCommitUnknownToInternal(t *testing.T) {
	topicID := idkit.XID()
	storage := &mockStorage{
		deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
			return nil, consensus.ErrCommitUnknown
		},
	}
	service := newTestService(storage)

	response, err := service.DeleteTopic(context.Background(), &v1.DeleteTopicRequest{TopicId: topicID})
	if response != nil || status.Code(err) != codes.Internal {
		t.Fatalf("DeleteTopic() = %#v, %v; want nil gRPC %v", response, err, codes.Internal)
	}
}

func TestDeleteQueueForceFalseMapsToHTTP409AndGRPCFailedPrecondition(t *testing.T) {
	storage := &mockStorage{
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*DeleteQueueResult, error) {
			return nil, pqerr.ErrFailedPrecondition
		},
	}
	httpResponse := doRequest(t, newTestService(storage), http.MethodDelete, "/"+validXID, "")
	if httpResponse.Code != http.StatusConflict {
		t.Fatalf("HTTP DeleteQueue status = %d, want %d", httpResponse.Code, http.StatusConflict)
	}

	service := newTestService(storage)
	var logged error
	ctx := ctxkit.SetLogErrHook(context.Background(), func(err error) { logged = err })

	response, err := service.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: "c5s8b4p9e8rg5u5fgq10"})
	if response != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteQueue() = %#v, %v; want nil gRPC %v", response, err, codes.FailedPrecondition)
	}
	if !errors.Is(logged, pqerr.ErrFailedPrecondition) {
		t.Fatalf("access-log error = %v, want %v", logged, pqerr.ErrFailedPrecondition)
	}
}

func TestGRPCDeleteQueueDoesNotExposeInternalEffects(t *testing.T) {
	storage := &mockStorage{
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*DeleteQueueResult, error) {
			return &DeleteQueueResult{RemovedSubscriptions: []Subscription{{SubscriptionID: "internal-only"}}}, nil
		},
	}
	service := newTestService(storage)

	response, err := service.DeleteQueue(context.Background(), &v1.DeleteQueueRequest{
		QueueId: "c5s8b4p9e8rg5u5fgq10",
		Force:   true,
	})
	if err != nil {
		t.Fatalf("DeleteQueue() error = %v", err)
	}
	encoded, err := response.MarshalVT()
	if err != nil {
		t.Fatalf("marshal DeleteQueue response: %v", err)
	}
	if len(encoded) != 0 {
		t.Fatalf("DeleteQueue response encoded %d bytes, want empty public protobuf", len(encoded))
	}
}

func TestGRPCDeleteTopicDoesNotExposeInternalEffects(t *testing.T) {
	topicID := idkit.XID()
	storage := &mockStorage{
		deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
			return &DeleteTopicResult{RemovedSubscriptions: []Subscription{{SubscriptionID: "internal-only"}}}, nil
		},
	}
	service := newTestService(storage)

	response, err := service.DeleteTopic(context.Background(), &v1.DeleteTopicRequest{TopicId: topicID})
	if err != nil {
		t.Fatalf("DeleteTopic() error = %v", err)
	}
	encoded, err := response.MarshalVT()
	if err != nil {
		t.Fatalf("marshal DeleteTopic response: %v", err)
	}
	if len(encoded) != 0 {
		t.Fatalf("DeleteTopic response encoded %d bytes, want empty public protobuf", len(encoded))
	}
}
