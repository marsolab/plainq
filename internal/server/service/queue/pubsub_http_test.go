package queue

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/server/config"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/logkit"
)

func TestPublishTopicRecordsTopicMetricsAfterSuccess(t *testing.T) {
	storage := &mockStorage{
		publishFunc: func(_ context.Context, topicID string, input *PublishRequest) (*PublishResponse, error) {
			if topicID != "topic-1" {
				t.Fatalf("topicID = %q, want topic-1", topicID)
			}
			return &PublishResponse{TopicID: topicID, DeliveredCount: 5}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodPost, "/topics/topic-1/publish", strings.NewReader(`{"messages":[{"body":"aGVsbG8="},{"body":"d29ybGQ="}]}`))
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	if recorder.publishTopicID != "topic-1" {
		t.Fatalf("publishTopicID = %q, want topic-1", recorder.publishTopicID)
	}
	if recorder.messagesPublished != 2 {
		t.Fatalf("messagesPublished = %d, want 2", recorder.messagesPublished)
	}
	if recorder.deliveries != 5 {
		t.Fatalf("deliveries = %d, want 5", recorder.deliveries)
	}
}

func TestPublishTopicDoesNotRecordTopicMetricsOnFailure(t *testing.T) {
	storage := &mockStorage{
		publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
			return nil, errors.New("publish failed")
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodPost, "/topics/topic-1/publish", strings.NewReader(`{"messages":[{"body":"aGVsbG8="}]}`))
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code == http.StatusAccepted {
		t.Fatalf("status = %d, want non-success publish status", rec.Code)
	}
	if recorder.publishTopicID != "" {
		t.Fatalf("publishTopicID = %q, want empty", recorder.publishTopicID)
	}
	if recorder.messagesPublished != 0 {
		t.Fatalf("messagesPublished = %d, want 0", recorder.messagesPublished)
	}
	if recorder.deliveries != 0 {
		t.Fatalf("deliveries = %d, want 0", recorder.deliveries)
	}
}

func TestSubscribeTopicRecordsCurrentSubscriptionCount(t *testing.T) {
	storage := &mockStorage{
		subscribeFunc: func(context.Context, string, *SubscribeRequest) (*SubscribeResponse, error) {
			return &SubscribeResponse{SubscriptionID: "sub-1"}, nil
		},
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{
				TopicID: "topic-1",
				Subscriptions: []Subscription{
					{SubscriptionID: "sub-1"},
					{SubscriptionID: "sub-2"},
				},
			}}}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodPost, "/topics/topic-1/subscriptions", strings.NewReader(`{"queueId":"c5s8b4p9e8rg5u5fgq10"}`))
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if recorder.createdTopicID != "topic-1" {
		t.Fatalf("createdTopicID = %q, want topic-1", recorder.createdTopicID)
	}
	if recorder.createdCurrentCount != 2 {
		t.Fatalf("createdCurrentCount = %d, want 2", recorder.createdCurrentCount)
	}
}

func TestSubscribeTopicDoesNotRecordTopicMetricsOnFailure(t *testing.T) {
	storage := &mockStorage{
		subscribeFunc: func(context.Context, string, *SubscribeRequest) (*SubscribeResponse, error) {
			return nil, errors.New("subscribe failed")
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodPost, "/topics/topic-1/subscriptions", strings.NewReader(`{"queueId":"c5s8b4p9e8rg5u5fgq10"}`))
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code == http.StatusCreated {
		t.Fatalf("status = %d, want non-success subscribe status", rec.Code)
	}
	if recorder.createdTopicID != "" {
		t.Fatalf("createdTopicID = %q, want empty", recorder.createdTopicID)
	}
	if recorder.createdCurrentCount != 0 {
		t.Fatalf("createdCurrentCount = %d, want 0", recorder.createdCurrentCount)
	}
}

func TestSetTopicMetricsRecorderReconcilesExistingTopicSubscriptions(t *testing.T) {
	storage := &mockStorage{
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{
				TopicID: "topic-1",
				Subscriptions: []Subscription{
					{SubscriptionID: "sub-1"},
					{SubscriptionID: "sub-2"},
				},
			}}}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)

	svc.SetTopicMetricsRecorder(recorder)

	if got := recorder.reconciledCounts["topic-1"]; got != 2 {
		t.Fatalf("reconciled topic-1 count = %d, want 2", got)
	}
}

func TestDeleteTopicReconcilesTopicSubscriptionMetrics(t *testing.T) {
	storage := &mockStorage{
		deleteTopicFunc: func(_ context.Context, topicID string) error {
			if topicID != "topic-1" {
				t.Fatalf("topicID = %q, want topic-1", topicID)
			}
			return nil
		},
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{
				TopicID: "topic-2",
				Subscriptions: []Subscription{
					{SubscriptionID: "sub-2"},
				},
			}}}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodDelete, "/topics/topic-1", nil)
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := recorder.reconciledCounts["topic-2"]; got != 1 {
		t.Fatalf("reconciled topic-2 count = %d, want 1", got)
	}
	if _, ok := recorder.reconciledCounts["topic-1"]; ok {
		t.Fatalf("reconciled counts = %v, want deleted topic absent", recorder.reconciledCounts)
	}
}

func TestDeleteQueueReconcilesTopicSubscriptionMetrics(t *testing.T) {
	storage := &mockStorage{
		deleteQueueFunc: func(_ context.Context, input *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
			if input.QueueId != "c5s8b4p9e8rg5u5fgq10" {
				t.Fatalf("QueueId = %q, want c5s8b4p9e8rg5u5fgq10", input.QueueId)
			}
			return &v1.DeleteQueueResponse{}, nil
		},
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{
				TopicID: "topic-1",
				Subscriptions: []Subscription{
					{SubscriptionID: "sub-remaining", QueueID: "c5s8b4p9e8rg5u5fgq11"},
				},
			}}}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodDelete, "/c5s8b4p9e8rg5u5fgq10?force=true", nil)
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := recorder.reconciledCounts["topic-1"]; got != 1 {
		t.Fatalf("reconciled topic-1 count = %d, want 1", got)
	}
}

func TestUnsubscribeTopicRecordsCurrentSubscriptionCount(t *testing.T) {
	storage := &mockStorage{
		unsubscribeFunc: func(context.Context, string, string) error {
			return nil
		},
		listTopicsFunc: func(context.Context) (*ListTopicsResponse, error) {
			return &ListTopicsResponse{Topics: []Topic{{
				TopicID: "topic-1",
				Subscriptions: []Subscription{
					{SubscriptionID: "sub-remaining"},
				},
			}}}, nil
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodDelete, "/topics/topic-1/subscriptions/sub-1", nil)
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if recorder.deletedTopicID != "topic-1" {
		t.Fatalf("deletedTopicID = %q, want topic-1", recorder.deletedTopicID)
	}
	if recorder.deletedCurrentCount != 1 {
		t.Fatalf("deletedCurrentCount = %d, want 1", recorder.deletedCurrentCount)
	}
}

func TestUnsubscribeTopicDoesNotRecordTopicMetricsOnFailure(t *testing.T) {
	storage := &mockStorage{
		unsubscribeFunc: func(context.Context, string, string) error {
			return errors.New("unsubscribe failed")
		},
	}
	recorder := &fakeTopicMetricsRecorder{}
	svc := NewService(&config.Config{}, logkit.NewNop(), storage)
	svc.SetTopicMetricsRecorder(recorder)

	req := httptest.NewRequest(http.MethodDelete, "/topics/topic-1/subscriptions/sub-1", nil)
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("status = %d, want non-success unsubscribe status", rec.Code)
	}
	if recorder.deletedTopicID != "" {
		t.Fatalf("deletedTopicID = %q, want empty", recorder.deletedTopicID)
	}
	if recorder.deletedCurrentCount != 0 {
		t.Fatalf("deletedCurrentCount = %d, want 0", recorder.deletedCurrentCount)
	}
}

var _ TopicMetricsRecorder = (*fakeTopicMetricsRecorder)(nil)

type fakeTopicMetricsRecorder struct {
	publishTopicID    string
	messagesPublished uint64
	deliveries        uint64

	createdTopicID      string
	createdCurrentCount int64
	deletedTopicID      string
	deletedCurrentCount int64
	reconciledCounts    map[string]int64
}

func (f *fakeTopicMetricsRecorder) RecordTopicPublish(topicID string, messagesPublished, deliveries uint64) {
	f.publishTopicID = topicID
	f.messagesPublished = messagesPublished
	f.deliveries = deliveries
}

func (f *fakeTopicMetricsRecorder) RecordTopicSubscriptionCreated(topicID string, currentCount int64) {
	f.createdTopicID = topicID
	f.createdCurrentCount = currentCount
}

func (f *fakeTopicMetricsRecorder) RecordTopicSubscriptionDeleted(topicID string, currentCount int64) {
	f.deletedTopicID = topicID
	f.deletedCurrentCount = currentCount
}

func (f *fakeTopicMetricsRecorder) ReconcileTopicSubscriptionCounts(countsByTopic map[string]int64) {
	f.reconciledCounts = make(map[string]int64, len(countsByTopic))
	for topicID, count := range countsByTopic {
		f.reconciledCounts[topicID] = count
	}
}
