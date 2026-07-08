package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
)

func TestGetTopicDashboardOverview(t *testing.T) {
	c := collector.New(nil)
	c.RecordTopicPublish("topic-1", 4, 8)
	c.RecordTopicSubscriptionCreated("topic-1", 2)
	c.RecordTopicPublish("topic-2", 1, 1)
	c.RecordTopicSubscriptionCreated("topic-2", 1)
	time.Sleep(2 * time.Millisecond)

	h := NewMetricsHandler(c, &fakeMetricsStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topics/overview", nil)
	rec := httptest.NewRecorder()

	h.GetTopicDashboardOverview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got TopicDashboardOverviewResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got.SystemMetrics.MessagesPublished != 5 {
		t.Fatalf("MessagesPublished = %d, want 5", got.SystemMetrics.MessagesPublished)
	}
	if got.SystemMetrics.Deliveries != 9 {
		t.Fatalf("Deliveries = %d, want 9", got.SystemMetrics.Deliveries)
	}
	if got.SystemMetrics.SubscriptionsCurrent == nil || *got.SystemMetrics.SubscriptionsCurrent != 3 {
		t.Fatalf("SubscriptionsCurrent = %v, want 3", got.SystemMetrics.SubscriptionsCurrent)
	}
	if len(got.TopicMetrics) != 2 {
		t.Fatalf("len(TopicMetrics) = %d, want 2", len(got.TopicMetrics))
	}
	if got.UpdatedAt == 0 {
		t.Fatal("UpdatedAt = 0, want non-zero timestamp")
	}
	for _, row := range got.TopicMetrics {
		if row.UpdatedAt == 0 {
			t.Fatalf("row %q UpdatedAt = 0, want topic activity timestamp", row.TopicID)
		}
		if row.UpdatedAt >= got.UpdatedAt {
			t.Fatalf("row %q UpdatedAt = %d, want before response timestamp %d", row.TopicID, row.UpdatedAt, got.UpdatedAt)
		}
	}
}

func TestGetTopicDashboardOverviewReturnsNullForUnknownSubscriptions(t *testing.T) {
	c := collector.New(nil)
	c.RecordTopicSubscriptionCreated("topic-1", -1)

	h := NewMetricsHandler(c, &fakeMetricsStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topics/overview", nil)
	rec := httptest.NewRecorder()

	h.GetTopicDashboardOverview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got TopicDashboardOverviewResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got.SystemMetrics.SubscriptionsCurrent != nil {
		t.Fatalf("system SubscriptionsCurrent = %v, want nil", got.SystemMetrics.SubscriptionsCurrent)
	}
	if len(got.TopicMetrics) != 1 {
		t.Fatalf("len(TopicMetrics) = %d, want 1", len(got.TopicMetrics))
	}
	if got.TopicMetrics[0].SubscriptionsCurrent != nil {
		t.Fatalf("topic SubscriptionsCurrent = %v, want nil", got.TopicMetrics[0].SubscriptionsCurrent)
	}
}

func TestGetTopicMetrics(t *testing.T) {
	c := collector.New(nil)
	c.RecordTopicPublish("topic-1", 4, 8)
	c.RecordTopicSubscriptionCreated("topic-1", 2)
	subscriptions := int64(2)

	h := NewMetricsHandler(c, &fakeMetricsStore{
		topicSummary: &collector.TopicMetricsSummary{
			TopicID:         "topic-1",
			TotalPublished:  4,
			TotalDeliveries: 8,
			AvgPublishRate:  1.5,
			AvgDeliveryRate: 3,
			MaxPublishRate:  4,
			MaxDeliveryRate: 8,
			Subscriptions:   &subscriptions,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topic/topic-1?range=1h", nil)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}", h.GetTopicMetrics)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got struct {
		*collector.TopicMetricsSummary
		CurrentPublishRate  float64 `json:"currentPublishRate"`
		CurrentDeliveryRate float64 `json:"currentDeliveryRate"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.TopicID != "topic-1" {
		t.Fatalf("TopicID = %q, want topic-1", got.TopicID)
	}
	if got.CurrentPublishRate != 0 {
		t.Fatalf("CurrentPublishRate = %v, want 0 before rate worker tick", got.CurrentPublishRate)
	}
}

func TestGetTopicMetricsReturnsNullForUnknownSubscriptions(t *testing.T) {
	c := collector.New(nil)
	h := NewMetricsHandler(c, &fakeMetricsStore{
		topicSummary: &collector.TopicMetricsSummary{
			TopicID:         "topic-1",
			TotalPublished:  4,
			TotalDeliveries: 8,
			Subscriptions:   nil,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topic/topic-1?range=1h", nil)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}", h.GetTopicMetrics)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got struct {
		Subscriptions *int64 `json:"subscriptions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Subscriptions != nil {
		t.Fatalf("Subscriptions = %v, want nil", got.Subscriptions)
	}
}

func TestGetTopicMetricsUsesKnownCollectorSubscriptions(t *testing.T) {
	c := collector.New(nil)
	c.ReconcileTopicSubscriptionCounts(map[string]int64{"topic-1": 0})
	h := NewMetricsHandler(c, &fakeMetricsStore{
		topicSummary: &collector.TopicMetricsSummary{
			TopicID:         "topic-1",
			TotalPublished:  4,
			TotalDeliveries: 8,
			Subscriptions:   nil,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topic/topic-1?range=1h", nil)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}", h.GetTopicMetrics)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got struct {
		Subscriptions *int64 `json:"subscriptions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Subscriptions == nil || *got.Subscriptions != 0 {
		t.Fatalf("Subscriptions = %v, want known zero", got.Subscriptions)
	}
}

func TestGetTopicRatesChart(t *testing.T) {
	c := collector.New(nil)
	h := NewMetricsHandler(c, &fakeMetricsStore{
		rateHistory: map[string][]collector.DataPoint{
			collector.MetricTopicPublishRate:  {{Timestamp: 1000, Value: 2}},
			collector.MetricTopicDeliveryRate: {{Timestamp: 1000, Value: 4}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topic/topic-1/rates?range=1h", nil)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}/rates", h.GetTopicRatesChart)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got MultiMetricsChartResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Metrics) != 2 {
		t.Fatalf("len(Metrics) = %d, want 2", len(got.Metrics))
	}
}

func TestGetTopicRatesChartReturnsErrorOnStoreFailure(t *testing.T) {
	c := collector.New(nil)
	h := NewMetricsHandler(c, &fakeMetricsStore{
		rateHistoryErr: errors.New("metrics store offline"),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/topic/topic-1/rates?range=1h", nil)
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}/rates", h.GetTopicRatesChart)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

type fakeMetricsStore struct {
	topicSummary   *collector.TopicMetricsSummary
	rateHistory    map[string][]collector.DataPoint
	rateHistoryErr error
}

func (*fakeMetricsStore) GetMetrics(context.Context, string, string, int64, int64, string) ([]collector.DataPoint, error) {
	return nil, nil
}

func (s *fakeMetricsStore) GetRateHistory(_ context.Context, metricName, _ string, _, _ int64) ([]collector.DataPoint, error) {
	if s.rateHistoryErr != nil {
		return nil, s.rateHistoryErr
	}

	return s.rateHistory[metricName], nil
}

func (*fakeMetricsStore) GetMetricsSummary(context.Context, string, int64, int64) (*collector.MetricsSummary, error) {
	return &collector.MetricsSummary{}, nil
}

func (s *fakeMetricsStore) GetTopicMetricsSummary(context.Context, string, int64, int64) (*collector.TopicMetricsSummary, error) {
	return s.topicSummary, nil
}
