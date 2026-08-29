package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
	"github.com/maxatome/go-testdeep/td"
)

func TestMetricsContractTopicRatesExactEnvelopeAndOrder(t *testing.T) {
	store := &fakeMetricsStore{seriesFn: func(query collector.SeriesQuery) (collector.SeriesResult, error) {
		result := completeRawResult(query, []float64{1, 2, 3})
		if query.MetricName == collector.MetricTopicDeliveryRate {
			result = completeRawResult(query, []float64{4, 5, 6})
		}
		if query.MetricName == collector.MetricTopicDeliveryFailureRate {
			result = completeRawResult(query, []float64{0, 1, 0})
		}
		return result, nil
	}}
	h := NewMetricsHandler(collector.New(nil), store, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicRatesChart,
		"/api/v1/metrics/topic/topic-1/rates?from=1700006370000&to=1700006400000")

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicSeriesResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.TopicID, "topic-1")
	td.Cmp(t, got.TimeRange, TimeRange{From: 1_700_006_370_000, To: contractNowMS})
	td.Cmp(t, got.EffectiveTimeRange, got.TimeRange)
	td.Cmp(t, got.Resolution, "raw")
	td.Cmp(t, got.SampleIntervalMS, int64(10_000))
	td.Cmp(t, got.GeneratedAt, contractNowMS)
	td.Cmp(t, metricNames(got.Metrics), []string{
		collector.MetricTopicPublishRate,
		collector.MetricTopicDeliveryRate,
		collector.MetricTopicDeliveryFailureRate,
	})
	for _, series := range got.Metrics {
		td.Cmp(t, series.Samples.Complete, true)
		td.Cmp(t, series.Samples.ExpectedPointCount, int64(3))
		td.Cmp(t, series.Samples.ReturnedPointCount, int64(3))
	}
	for _, query := range store.seriesQueries {
		td.Cmp(t, query.Resolution, collector.ResolutionRaw)
		td.Cmp(t, query.From, int64(1_700_006_370_000))
		td.Cmp(t, query.To, contractNowMS)
	}
}

func TestMetricsContractUnalignedRatesJSONKeepsBothRanges(t *testing.T) {
	h := NewMetricsHandler(collector.New(nil), &fakeMetricsStore{}, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicRatesChart,
		"/api/v1/metrics/topic/topic-1/rates?from=1700006370001&to=1700006399999")

	td.Cmp(t, recorder.Code, http.StatusOK)
	want := `{"topicId":"topic-1","metrics":[{"metricName":"plainq_topic_publish_rate","topicId":"topic-1","kind":"rate","unit":"messages_per_second","interpolation":"linear","timeRange":{"from":1700006370001,"to":1700006399999},"resolution":"raw","samples":{"expectedPointCount":1,"returnedPointCount":0,"firstSampleAt":null,"lastSampleAt":null,"complete":false,"missingRanges":[{"from":1700006380000,"to":1700006390000,"reason":"notRecorded"}]},"dataPoints":[]},{"metricName":"plainq_topic_delivery_rate","topicId":"topic-1","kind":"rate","unit":"messages_per_second","interpolation":"linear","timeRange":{"from":1700006370001,"to":1700006399999},"resolution":"raw","samples":{"expectedPointCount":1,"returnedPointCount":0,"firstSampleAt":null,"lastSampleAt":null,"complete":false,"missingRanges":[{"from":1700006380000,"to":1700006390000,"reason":"notRecorded"}]},"dataPoints":[]},{"metricName":"plainq_topic_delivery_failure_rate","topicId":"topic-1","kind":"rate","unit":"messages_per_second","interpolation":"linear","timeRange":{"from":1700006370001,"to":1700006399999},"resolution":"raw","samples":{"expectedPointCount":1,"returnedPointCount":0,"firstSampleAt":null,"lastSampleAt":null,"complete":false,"missingRanges":[{"from":1700006380000,"to":1700006390000,"reason":"notRecorded"}]},"dataPoints":[]}],"timeRange":{"from":1700006370001,"to":1700006399999},"effectiveTimeRange":{"from":1700006380000,"to":1700006390000},"resolution":"raw","sampleIntervalMs":10000,"generatedAt":1700006400000}`
	td.Cmp(t, recorder.Body.String(), want+"\n")
}

func TestMetricsContractCanonicalEmptyRatesSkipTheStore(t *testing.T) {
	store := &fakeMetricsStore{seriesErr: errors.New("must not be queried")}
	h := NewMetricsHandler(collector.New(nil), store, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicRatesChart,
		"/api/v1/metrics/topic/topic-1/rates?from=1700006410000&to=1700006420000")

	td.Cmp(t, recorder.Code, http.StatusOK)
	td.Cmp(t, len(store.seriesQueries), 0)
	var got TopicSeriesResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.EffectiveTimeRange, TimeRange{From: 1_700_006_410_000, To: 1_700_006_410_000})
	for _, series := range got.Metrics {
		td.Cmp(t, series.Samples, SampleMetadata{MissingRanges: []MissingRange{}})
		td.Cmp(t, series.DataPoints, []MetricDataPoint{})
	}
}

func TestMetricsContractTopicSubscriptionsSummaryAndOrder(t *testing.T) {
	store := &fakeMetricsStore{seriesFn: func(query collector.SeriesQuery) (collector.SeriesResult, error) {
		switch query.MetricName {
		case collector.MetricTopicSubscriptionsCurrent:
			return completeRawResult(query, []float64{2, 3, 4}), nil
		case collector.MetricTopicSubscriptionsCreatedRate:
			return completeRawResult(query, []float64{1, 3, 2}), nil
		case collector.MetricTopicSubscriptionsDeletedRate:
			return completeRawResult(query, []float64{0, 1, 2}), nil
		case collector.MetricTopicSubscriptionsCreatedTotal:
			return completeRawCounterResult(query, 2, []float64{3, 5, 5}), nil
		case collector.MetricTopicSubscriptionsDeletedTotal:
			return completeRawCounterResult(query, 1, []float64{1, 2, 4}), nil
		default:
			return collector.SeriesResult{}, nil
		}
	}}
	h := NewMetricsHandler(collector.New(nil), store, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicSubscriptions,
		"/api/v1/metrics/topic/topic-1/subscriptions?from=1700006370000&to=1700006400000")

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicSubscriptionsResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, metricNames(got.Metrics), []string{
		collector.MetricTopicSubscriptionsCurrent,
		collector.MetricTopicSubscriptionsCreatedRate,
		collector.MetricTopicSubscriptionsDeletedRate,
	})
	td.Cmp(t, got.Summary, TopicSubscriptionSummary{
		SubscriptionsCurrent: int64Pointer(4),
		CreatedDuringWindow:  int64Pointer(3),
		RemovedDuringWindow:  int64Pointer(3),
		AvgCreateRate:        float64Pointer(2),
		AvgRemoveRate:        float64Pointer(1),
		MaxCreateRate:        float64Pointer(3),
		MaxRemoveRate:        float64Pointer(2),
		UpdatedAt:            int64Pointer(1_700_006_390_000),
	})
}

func TestMetricsContractTopicSubscriptionsIncompleteSummaryUsesNull(t *testing.T) {
	h := NewMetricsHandler(collector.New(nil), &fakeMetricsStore{}, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicSubscriptions,
		"/api/v1/metrics/topic/topic-1/subscriptions?from=1700006370000&to=1700006400000")

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicSubscriptionsResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.Summary, TopicSubscriptionSummary{})
	if got.Metrics == nil {
		t.Fatal("metrics = nil, want [] or fixed series")
	}
}

func TestMetricsContractTopicSummaryLegacyFallbackAndExactRanges(t *testing.T) {
	h := NewMetricsHandler(collector.New(nil), &fakeMetricsStore{}, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicMetrics,
		"/api/v1/metrics/topic/topic-1?from=1700006370001&to=1700006399999")

	td.Cmp(t, recorder.Code, http.StatusOK)
	want := `{"topicId":"topic-1","from":1700006370001,"to":1700006399999,"totalPublished":0,"totalDeliveries":0,"avgPublishRate":0,"avgDeliveryRate":0,"maxPublishRate":0,"maxDeliveryRate":0,"subscriptions":null,"currentPublishRate":0,"currentDeliveryRate":0,"timeRange":{"from":1700006370001,"to":1700006399999},"totalPublishedBytes":null,"totalDeliveryFailures":null,"averageFanout":null,"maxFanout":null,"subscriptionsCreatedDuringWindow":null,"subscriptionsRemovedDuringWindow":null,"effectiveTimeRange":{"from":1700006380000,"to":1700006390000},"resolution":"raw","generatedAt":1700006400000,"operationSummaries":null,"storageOperationSummaries":null}`
	td.Cmp(t, recorder.Body.String(), want+"\n")
}

func TestMetricsContractTopicSummaryUsesTypedRangeData(t *testing.T) {
	store := &fakeMetricsStore{seriesFn: func(query collector.SeriesQuery) (collector.SeriesResult, error) {
		switch query.MetricName {
		case collector.MetricTopicMessagesPublishedTotal:
			return completeRawCounterResult(query, 10, []float64{12, 3, 8}), nil
		case collector.MetricTopicDeliveriesTotal:
			return completeRawCounterResult(query, 20, []float64{25, 30, 40}), nil
		case collector.MetricTopicPublishedBytesTotal:
			return completeRawCounterResult(query, 100, []float64{150, 160, 10}), nil
		case collector.MetricTopicDeliveryFailuresTotal:
			return completeRawCounterResult(query, 2, []float64{2, 3, 1}), nil
		case collector.MetricTopicSubscriptionsCreatedTotal:
			return completeRawCounterResult(query, 0, []float64{1, 2, 4}), nil
		case collector.MetricTopicSubscriptionsDeletedTotal:
			return completeRawCounterResult(query, 0, []float64{0, 1, 1}), nil
		case collector.MetricTopicPublishRate:
			return completeRawResult(query, []float64{1, 2, 3}), nil
		case collector.MetricTopicDeliveryRate:
			return completeRawResult(query, []float64{4, 5, 6}), nil
		case collector.MetricTopicSubscriptionsCurrent:
			return completeRawResult(query, []float64{5, 6, 7}), nil
		case collector.MetricTopicFanout:
			return completeRawResult(query, []float64{2, 4, 6}), nil
		default:
			return collector.SeriesResult{}, nil
		}
	}}
	h := NewMetricsHandler(collector.New(nil), store, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicMetrics,
		"/api/v1/metrics/topic/topic-1?from=1700006370000&to=1700006400000")

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicMetricsResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.TopicMetricsSummary, &collector.TopicMetricsSummary{
		TopicID: "topic-1", From: 1_700_006_370_000, To: contractNowMS,
		TotalPublished: 10, TotalDeliveries: 20,
		AvgPublishRate: 2, AvgDeliveryRate: 5,
		MaxPublishRate: 3, MaxDeliveryRate: 6,
		Subscriptions: int64Pointer(7),
	})
	td.Cmp(t, got.TotalPublishedBytes, uint64Pointer(70))
	td.Cmp(t, got.TotalDeliveryFailures, uint64Pointer(2))
	td.Cmp(t, got.AverageFanout, float64Pointer(4))
	td.Cmp(t, got.MaxFanout, float64Pointer(6))
	td.Cmp(t, got.SubscriptionsCreatedDuringWindow, int64Pointer(4))
	td.Cmp(t, got.SubscriptionsRemovedDuringWindow, int64Pointer(1))
	td.Cmp(t, got.OperationSummaries, (*[]OperationSummary)(nil))
	td.Cmp(t, got.StorageOperationSummaries, (*[]OperationSummary)(nil))
}

func TestMetricsContractOperationSummariesStaySeparateAndOrdered(t *testing.T) {
	store := &fakeMetricsStore{seriesFn: func(query collector.SeriesQuery) (collector.SeriesResult, error) {
		if query.MetricName != collector.MetricTopicRequestsTotal &&
			query.MetricName != collector.MetricTopicOperationsTotal &&
			query.MetricName != collector.MetricTopicRequestDuration &&
			query.MetricName != collector.MetricTopicOperationDuration {
			return collector.SeriesResult{}, nil
		}

		labels := decodeOperationLabels(query.Labels)
		count := float64(0)
		durations := []float64(nil)
		switch {
		case query.MetricName == collector.MetricTopicRequestsTotal &&
			labels["backend"] == metrics.BackendSQLite && labels["operation"] == metrics.OpSubscribe &&
			labels["result"] == metrics.ResultOK:
			count = 1
		case query.MetricName == collector.MetricTopicRequestDuration &&
			labels["backend"] == metrics.BackendSQLite && labels["operation"] == metrics.OpSubscribe:
			durations = []float64{0.1}
		case query.MetricName == collector.MetricTopicRequestsTotal &&
			labels["backend"] == metrics.BackendCluster && labels["operation"] == metrics.OpPublish &&
			labels["result"] == metrics.ResultError:
			count = 1
		case query.MetricName == collector.MetricTopicRequestDuration &&
			labels["backend"] == metrics.BackendCluster && labels["operation"] == metrics.OpPublish:
			durations = []float64{0.3}
		case query.MetricName == collector.MetricTopicOperationsTotal &&
			labels["backend"] == metrics.BackendPostgres && labels["operation"] == metrics.OpPublish &&
			labels["result"] == metrics.ResultOK:
			count = 2
		case query.MetricName == collector.MetricTopicOperationDuration &&
			labels["backend"] == metrics.BackendPostgres && labels["operation"] == metrics.OpPublish:
			durations = []float64{0.25, 0.5}
		}

		if query.Kind == collector.MetricKindCounter {
			return completeRawCounterResult(query, 0, []float64{0, count}), nil
		}
		return completeRawEventResult(query, durations), nil
	}}
	h := NewMetricsHandler(collector.New(nil), store, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicMetrics,
		"/api/v1/metrics/topic/topic-1?from=1700006380000&to=1700006400000")

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicMetricsResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.OperationSummaries, td.Ptr([]OperationSummary{
		{
			Backend: metrics.BackendSQLite, Operation: metrics.OpSubscribe, OK: 1,
			DurationSeconds: DurationSummary{Min: 0.1, Max: 0.1, Avg: 0.1, Sum: 0.1, Count: 1},
		},
		{
			Backend: metrics.BackendCluster, Operation: metrics.OpPublish, Error: 1,
			DurationSeconds: DurationSummary{Min: 0.3, Max: 0.3, Avg: 0.3, Sum: 0.3, Count: 1},
		},
	}))
	td.Cmp(t, got.StorageOperationSummaries, td.Ptr([]OperationSummary{
		{
			Backend: metrics.BackendPostgres, Operation: metrics.OpPublish, OK: 2,
			DurationSeconds: DurationSummary{Min: 0.25, Max: 0.5, Avg: 0.375, Sum: 0.75, Count: 2},
		},
	}))
}

func TestMetricsContractOperationSummaryCoverageIsIndependent(t *testing.T) {
	store := &fakeMetricsStore{seriesFn: func(query collector.SeriesQuery) (collector.SeriesResult, error) {
		if query.MetricName == collector.MetricTopicRequestsTotal ||
			query.MetricName == collector.MetricTopicRequestDuration {
			return collector.SeriesResult{}, nil
		}
		if query.MetricName == collector.MetricTopicOperationsTotal {
			return completeRawCounterResult(query, 0, []float64{0, 0}), nil
		}
		if query.MetricName == collector.MetricTopicOperationDuration {
			return completeRawEventResult(query, nil), nil
		}
		return collector.SeriesResult{}, nil
	}}
	h := NewMetricsHandler(collector.New(nil), store, testMetricsHandlerConfig())
	recorder := requestTopicHandler(t, h.GetTopicMetrics,
		"/api/v1/metrics/topic/topic-1?from=1700006380000&to=1700006400000")

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicMetricsResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.OperationSummaries, (*[]OperationSummary)(nil))
	td.Cmp(t, got.StorageOperationSummaries, td.Ptr([]OperationSummary{}))
}

func TestMetricsContractTopicOverviewUsesRequestedRangeAndCurrentProcessValues(t *testing.T) {
	c := collector.New(nil)
	c.RecordTopicPublish(telemetry.TopicPublishEvent{
		TopicID: "topic-1", Messages: 4, Bytes: 120, Delivered: 7, Failed: 2,
	})
	c.RecordTopicState(telemetry.TopicStateEvent{
		TopicsExist: 1, Subscriptions: map[string]int64{"topic-1": 3},
	})
	h := NewMetricsHandler(c, &fakeMetricsStore{}, testMetricsHandlerConfig())
	recorder := httptest.NewRecorder()
	h.GetTopicDashboardOverview(recorder, httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/topics/overview?from=1700006380001&to=1700006399999", nil))

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicDashboardOverviewResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.TimeRange, TimeRange{From: 1_700_006_380_001, To: 1_700_006_399_999})
	td.Cmp(t, got.EffectiveTimeRange, TimeRange{From: 1_700_006_399_999, To: 1_700_006_399_999})
	td.Cmp(t, got.Resolution, "raw")
	td.Cmp(t, got.UpdatedAt, contractNowMS)
	td.Cmp(t, got.SystemMetrics.MessagesPublished, uint64(4))
	td.Cmp(t, got.SystemMetrics.PublishedBytes, uint64(120))
	td.Cmp(t, got.SystemMetrics.Deliveries, uint64(7))
	td.Cmp(t, got.SystemMetrics.DeliveryFailures, uint64(2))
	td.Cmp(t, got.SystemMetrics.TopicsExist, int64(1))
	td.Cmp(t, got.SystemMetrics.OperationSummaries, (*[]OperationSummary)(nil))
	td.Cmp(t, got.SystemMetrics.StorageOperationSummaries, (*[]OperationSummary)(nil))
}

func TestMetricsContractTopicOverviewIncludesSystemListAndCreateOperations(t *testing.T) {
	store := &fakeMetricsStore{seriesFn: func(query collector.SeriesQuery) (collector.SeriesResult, error) {
		if query.SubjectID != "" {
			t.Fatalf("operation summary subject = %q, want system subject", query.SubjectID)
		}
		labels := decodeOperationLabels(query.Labels)
		count := float64(0)
		durations := []float64(nil)
		switch {
		case query.MetricName == collector.MetricTopicRequestsTotal &&
			labels["backend"] == metrics.BackendSQLite && labels["operation"] == metrics.OpListTopics &&
			labels["result"] == metrics.ResultOK:
			count = 1
		case query.MetricName == collector.MetricTopicRequestDuration &&
			labels["backend"] == metrics.BackendSQLite && labels["operation"] == metrics.OpListTopics:
			durations = []float64{0.125}
		case query.MetricName == collector.MetricTopicRequestsTotal &&
			labels["backend"] == metrics.BackendTurso && labels["operation"] == metrics.OpCreateTopic &&
			labels["result"] == metrics.ResultError:
			count = 1
		case query.MetricName == collector.MetricTopicRequestDuration &&
			labels["backend"] == metrics.BackendTurso && labels["operation"] == metrics.OpCreateTopic:
			durations = []float64{0.25}
		}
		if query.Kind == collector.MetricKindCounter {
			return completeRawCounterResult(query, 0, []float64{0, count}), nil
		}
		return completeRawEventResult(query, durations), nil
	}}
	h := NewMetricsHandler(collector.New(nil), store, testMetricsHandlerConfig())
	recorder := httptest.NewRecorder()
	h.GetTopicDashboardOverview(recorder, httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/topics/overview?from=1700006380000&to=1700006400000", nil))

	td.Cmp(t, recorder.Code, http.StatusOK)
	var got TopicDashboardOverviewResponse
	td.Require(t).CmpNoError(json.NewDecoder(recorder.Body).Decode(&got))
	td.Cmp(t, got.SystemMetrics.OperationSummaries, td.Ptr([]OperationSummary{
		{
			Backend: metrics.BackendSQLite, Operation: metrics.OpListTopics, OK: 1,
			DurationSeconds: DurationSummary{Min: 0.125, Max: 0.125, Avg: 0.125, Sum: 0.125, Count: 1},
		},
		{
			Backend: metrics.BackendTurso, Operation: metrics.OpCreateTopic, Error: 1,
			DurationSeconds: DurationSummary{Min: 0.25, Max: 0.25, Avg: 0.25, Sum: 0.25, Count: 1},
		},
	}))
	td.Cmp(t, got.SystemMetrics.StorageOperationSummaries, td.Ptr([]OperationSummary{}))
}

func completeRawResult(query collector.SeriesQuery, values []float64) collector.SeriesResult {
	result := collector.SeriesResult{
		Coverage:   make([]collector.CoverageBucket, 0, len(values)),
		DataPoints: make([]collector.DataPoint, 0, len(values)),
	}
	interval := int64(10_000)
	for index, value := range values {
		timestamp := query.From + int64(index)*interval
		result.Coverage = append(result.Coverage, collector.CoverageBucket{
			Resolution: collector.ResolutionRaw, BucketStart: timestamp, SubjectID: query.SubjectID,
			MetricName: query.MetricName, Labels: query.Labels, Kind: query.Kind, SampleIntervalMS: interval,
		})
		result.DataPoints = append(result.DataPoints, collector.DataPoint{
			Timestamp: timestamp, Value: value, Source: "observed", Count: 1, WindowMS: interval,
		})
	}
	return result
}

func completeRawCounterResult(query collector.SeriesQuery, prior float64, values []float64) collector.SeriesResult {
	result := completeRawResult(query, values)
	result.Prior = &collector.DataPoint{
		Timestamp: query.From - 10_000, Value: prior, Source: "observed", Count: 1,
	}
	result.PriorCoverage = []collector.CoverageBucket{{
		Resolution: collector.ResolutionRaw, BucketStart: query.From - 10_000, SubjectID: query.SubjectID,
		MetricName: query.MetricName, Labels: query.Labels, Kind: query.Kind, SampleIntervalMS: 10_000,
	}}
	return result
}

func completeRawEventResult(query collector.SeriesQuery, values []float64) collector.SeriesResult {
	interval := int64(10_000)
	result := collector.SeriesResult{
		Coverage:   make([]collector.CoverageBucket, 0, (query.To-query.From)/interval),
		DataPoints: make([]collector.DataPoint, 0, len(values)),
	}
	for timestamp := query.From; timestamp < query.To; timestamp += interval {
		result.Coverage = append(result.Coverage, collector.CoverageBucket{
			Resolution: collector.ResolutionRaw, BucketStart: timestamp, SubjectID: query.SubjectID,
			MetricName: query.MetricName, Labels: query.Labels, Kind: query.Kind, SampleIntervalMS: interval,
		})
	}
	for index, value := range values {
		result.DataPoints = append(result.DataPoints, collector.DataPoint{
			Timestamp: query.From + int64(index)*interval + 1, Value: value, Source: "observed", Count: 1,
		})
	}
	return result
}

func requestTopicHandler(t *testing.T, handler http.HandlerFunc, target string) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	router.Get("/api/v1/metrics/topic/{id}/rates", handler)
	router.Get("/api/v1/metrics/topic/{id}/subscriptions", handler)
	router.Get("/api/v1/metrics/topic/{id}", handler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

func metricNames(series []MetricSeriesResponse) []string {
	result := make([]string, 0, len(series))
	for _, item := range series {
		result = append(result, item.MetricName)
	}
	return result
}

func uint64Pointer(value uint64) *uint64 { return &value }

func decodeOperationLabels(encoded string) map[string]string {
	result := make(map[string]string)
	_ = json.Unmarshal([]byte(encoded), &result)
	return result
}
