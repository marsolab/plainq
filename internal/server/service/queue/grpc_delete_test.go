package queue

import (
	"context"
	"errors"
	"testing"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/server/config"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/ctxkit"
	"github.com/marsolab/servekit/logkit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCDeleteTopicMapsCommitUnknownToInternal(t *testing.T) {
	storage := &mockStorage{
		deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
			return nil, consensus.ErrCommitUnknown
		},
	}
	service := NewService(&config.Config{}, logkit.NewNop(), storage)

	response, err := service.DeleteTopic(context.Background(), &v1.DeleteTopicRequest{TopicId: "topic-1"})
	if response != nil || status.Code(err) != codes.Internal {
		t.Fatalf("DeleteTopic() = %#v, %v; want nil gRPC %v", response, err, codes.Internal)
	}
}

func TestGRPCDeleteQueueMapsFailedPreconditionAndRecordsAccessError(t *testing.T) {
	storage := &mockStorage{
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*DeleteQueueResult, error) {
			return nil, pqerr.ErrFailedPrecondition
		},
	}
	service := NewService(&config.Config{}, logkit.NewNop(), storage)
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
	service := NewService(&config.Config{}, logkit.NewNop(), storage)

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
	storage := &mockStorage{
		deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
			return &DeleteTopicResult{RemovedSubscriptions: []Subscription{{SubscriptionID: "internal-only"}}}, nil
		},
	}
	service := NewService(&config.Config{}, logkit.NewNop(), storage)

	response, err := service.DeleteTopic(context.Background(), &v1.DeleteTopicRequest{TopicId: "topic-1"})
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
