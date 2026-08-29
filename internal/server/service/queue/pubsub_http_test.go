package queue

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
	"github.com/marsolab/servekit/logkit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPubSubHTTPMapsDomainErrors(t *testing.T) {
	topicID := idkit.XID()
	tests := map[string]struct {
		storage *mockStorage
		method  string
		target  string
		body    string
		want    int
	}{
		"duplicate topic": {
			storage: &mockStorage{createTopicFunc: func(context.Context, *CreateTopicRequest) (*CreateTopicResponse, error) {
				return nil, pqerr.ErrAlreadyExists
			}},
			method: http.MethodPost, target: "/topics/", body: `{"topicName":"events"}`, want: http.StatusConflict,
		},
		"missing topic": {
			storage: &mockStorage{deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
				return nil, pqerr.ErrNotFound
			}},
			method: http.MethodDelete, target: "/topics/" + topicID, want: http.StatusNotFound,
		},
		"temporarily unavailable": {
			storage: &mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
				return nil, pqerr.ErrUnavailable
			}},
			method: http.MethodPost, target: "/topics/" + topicID + "/publish", body: `{"messages":[{"body":"eA=="}]}`, want: http.StatusServiceUnavailable,
		},
		"non-empty queue needs force": {
			storage: &mockStorage{deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*DeleteQueueResult, error) {
				return nil, pqerr.ErrFailedPrecondition
			}},
			method: http.MethodDelete, target: "/" + validXID, want: http.StatusConflict,
		},
		"commit outcome unknown": {
			storage: &mockStorage{deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
				return nil, consensus.ErrCommitUnknown
			}},
			method: http.MethodDelete, target: "/topics/" + topicID, want: http.StatusInternalServerError,
		},
		"partial fanout": {
			storage: &mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
				return nil, &PartialPublishError{Causes: []error{pqerr.ErrUnavailable}}
			}},
			method: http.MethodPost, target: "/topics/" + topicID + "/publish", body: `{"messages":[{"body":"eA=="}]}`, want: http.StatusInternalServerError,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := doRequest(t, newTestService(tc.storage), tc.method, tc.target, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestPubSubHTTPPreservesSuccessStatusesAndShapes(t *testing.T) {
	topicID := idkit.XID()
	subscriptionID := idkit.XID()
	storage := &mockStorage{
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{}}, nil
		},
		createTopicFunc: func(context.Context, *CreateTopicRequest) (*CreateTopicResponse, error) {
			return &CreateTopicResponse{TopicID: topicID}, nil
		},
		deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
			return &DeleteTopicResult{}, nil
		},
		subscribeFunc: func(context.Context, string, *SubscribeRequest) (*SubscribeResponse, error) {
			return &SubscribeResponse{SubscriptionID: subscriptionID}, nil
		},
		unsubscribeFunc: func(context.Context, string, string) error { return nil },
		publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
			return &PublishResponse{TopicID: topicID, QueueIDs: []string{}, MessageIDs: []string{}, DeliveredCount: 0}, nil
		},
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*DeleteQueueResult, error) {
			return &DeleteQueueResult{}, nil
		},
		topicInventoryFunc: func(context.Context) (TopicInventory, error) {
			return TopicInventory{TopicsExist: 1, SubscriptionCounts: map[string]int64{topicID: 0}}, nil
		},
	}
	service := newTestService(storage)
	tests := []struct {
		name, method, target, body string
		status                     int
		wantBody                   string
	}{
		{name: "list", method: http.MethodGet, target: "/topics/", status: http.StatusOK, wantBody: `{"topics":[]}`},
		{name: "create", method: http.MethodPost, target: "/topics/", body: `{"topicName":"events"}`, status: http.StatusCreated, wantBody: `{"topicId":"` + topicID + `"}`},
		{name: "delete", method: http.MethodDelete, target: "/topics/" + topicID, status: http.StatusOK, wantBody: `{}`},
		{name: "subscribe", method: http.MethodPost, target: "/topics/" + topicID + "/subscriptions", body: `{"queueId":"` + validXID + `"}`, status: http.StatusCreated, wantBody: `{"subscriptionId":"` + subscriptionID + `"}`},
		{name: "unsubscribe", method: http.MethodDelete, target: "/topics/" + topicID + "/subscriptions/" + subscriptionID, status: http.StatusOK, wantBody: `{}`},
		{name: "publish", method: http.MethodPost, target: "/topics/" + topicID + "/publish", body: `{"messages":[{"body":"eA=="}]}`, status: http.StatusAccepted, wantBody: `{"topicId":"` + topicID + `","queueIds":[],"messageIds":[],"deliveredCount":0}`},
		{name: "delete queue", method: http.MethodDelete, target: "/" + validXID + "?force=true", status: http.StatusOK, wantBody: `{}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, service, tc.method, tc.target, tc.body)
			if rec.Code != tc.status || strings.TrimSpace(rec.Body.String()) != tc.wantBody {
				t.Fatalf("response = %d %s, want %d %s", rec.Code, strings.TrimSpace(rec.Body.String()), tc.status, tc.wantBody)
			}
		})
	}
}

func TestUndecodableHTTPBodyDoesNotRecordBusinessRequest(t *testing.T) {
	recorder := &applicationRecorder{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(recorder)
	storage := &mockStorage{}
	service := NewService(nil, logkit.NewNop(), NewObservedStorage(storage, observer), observer)
	body := &trackedBody{Reader: strings.NewReader(`{"topicName":`)}
	request := httptest.NewRequest(http.MethodPost, "/topics/", nil)
	request.Body = body
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if len(recorder.requests) != 0 || len(recorder.operations) != 0 {
		t.Fatalf("events = requests %#v operations %#v, want none", recorder.requests, recorder.operations)
	}
	if !body.closed {
		t.Fatal("malformed request body was not closed")
	}
}

func TestPubSubHTTPAndGRPCHaveStatusParity(t *testing.T) {
	topicID := idkit.XID()

	t.Run("invalid subscribe queue", func(t *testing.T) {
		storage := &mockStorage{}
		httpResponse := doRequest(t, newTestService(storage), http.MethodPost, "/topics/"+topicID+"/subscriptions", `{"queueId":"bad"}`)
		_, grpcErr := newTestService(storage).Subscribe(context.Background(), &v1.SubscribeRequest{TopicId: topicID, QueueId: "bad"})
		if httpResponse.Code != http.StatusBadRequest || status.Code(grpcErr) != codes.InvalidArgument {
			t.Fatalf("HTTP/gRPC = %d/%v, want %d/%v", httpResponse.Code, status.Code(grpcErr), http.StatusBadRequest, codes.InvalidArgument)
		}
	})

	t.Run("missing topic", func(t *testing.T) {
		storage := &mockStorage{deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
			return nil, pqerr.ErrNotFound
		}}
		httpResponse := doRequest(t, newTestService(storage), http.MethodDelete, "/topics/"+topicID, "")
		_, grpcErr := newTestService(storage).DeleteTopic(context.Background(), &v1.DeleteTopicRequest{TopicId: topicID})
		if httpResponse.Code != http.StatusNotFound || status.Code(grpcErr) != codes.NotFound {
			t.Fatalf("HTTP/gRPC = %d/%v, want %d/%v", httpResponse.Code, status.Code(grpcErr), http.StatusNotFound, codes.NotFound)
		}
	})

	t.Run("partial publish remains conservative", func(t *testing.T) {
		partial := &PartialPublishError{Outcome: PublishOutcome{Response: &PublishResponse{TopicID: topicID}}, Causes: []error{pqerr.ErrUnavailable}}
		storage := &mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
			return partial.Outcome.Response, partial
		}}
		httpResponse := doRequest(t, newTestService(storage), http.MethodPost, "/topics/"+topicID+"/publish", `{"messages":[{"body":"eA=="}]}`)
		grpcResponse, grpcErr := newTestService(storage).Publish(context.Background(), &v1.PublishRequest{TopicId: topicID, Messages: []*v1.PublishMessage{{Body: []byte("x")}}})
		if httpResponse.Code != http.StatusInternalServerError || status.Code(grpcErr) != codes.Internal || grpcResponse != nil {
			t.Fatalf("HTTP/gRPC = %d/%v response=%#v, want %d/%v nil", httpResponse.Code, status.Code(grpcErr), grpcResponse, http.StatusInternalServerError, codes.Internal)
		}
	})

	t.Run("oversized publish is non-retryable capacity", func(t *testing.T) {
		storage := &mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
			return nil, fmt.Errorf("encoded publish command: %w", pqerr.ErrCapacityExceeded)
		}}
		httpResponse := doRequest(t, newTestService(storage), http.MethodPost, "/topics/"+topicID+"/publish", `{"messages":[{"body":"eA=="}]}`)
		grpcResponse, grpcErr := newTestService(storage).Publish(context.Background(), &v1.PublishRequest{
			TopicId: topicID, Messages: []*v1.PublishMessage{{Body: []byte("x")}},
		})
		if httpResponse.Code != http.StatusRequestEntityTooLarge || status.Code(grpcErr) != codes.ResourceExhausted || grpcResponse != nil {
			t.Fatalf("HTTP/gRPC = %d/%v response=%#v, want %d/%v nil",
				httpResponse.Code, status.Code(grpcErr), grpcResponse,
				http.StatusRequestEntityTooLarge, codes.ResourceExhausted)
		}
	})

	t.Run("zero-count legacy partial never dereferences nil response", func(t *testing.T) {
		storage := &mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
			return nil, &PartialPublishError{Outcome: PublishOutcome{Partial: true}}
		}}
		grpcResponse, grpcErr := newTestService(storage).Publish(context.Background(), &v1.PublishRequest{
			TopicId: topicID, Messages: []*v1.PublishMessage{{Body: []byte("x")}},
		})
		if status.Code(grpcErr) != codes.Internal || grpcResponse != nil {
			t.Fatalf("gRPC = %v response=%#v, want Internal/nil", status.Code(grpcErr), grpcResponse)
		}
	})
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error {
	b.closed = true

	return nil
}

var _ io.ReadCloser = (*trackedBody)(nil)
