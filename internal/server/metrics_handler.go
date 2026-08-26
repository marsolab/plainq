package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
	"github.com/marsolab/servekit/httpkit"
)

const (
	// durationMinutes15 is the number of minutes for the 15m time range preset.
	durationMinutes15 = 15

	// durationHours12 is the number of hours for the 12h time range preset.
	durationHours12 = 12

	// durationDays90 is the number of days for the 90d time range preset.
	durationDays90 = 90

	// durationDays365 is the number of days for the 1y time range preset.
	durationDays365 = 365

	// metricTypeGauge is the metric type label for gauge metrics.
	metricTypeGauge = "gauge"

	// metricTypeCounter is the metric type label for counter metrics.
	metricTypeCounter = "counter"

	// metricTypeHistogram is the metric type label for histogram metrics.
	metricTypeHistogram = "histogram"

	// csvSeparator is the comma separator used in CSV export.
	csvSeparator = ","
)

type MetricsStore interface {
	GetMetrics(ctx context.Context, metricName, queueID string, from, to int64, resolution string) ([]collector.DataPoint, error)
	GetRateHistory(ctx context.Context, metricName, queueID string, from, to int64) ([]collector.DataPoint, error)
	GetMetricsSummary(ctx context.Context, queueID string, from, to int64) (*collector.MetricsSummary, error)
	QuerySeries(ctx context.Context, query collector.SeriesQuery) (collector.SeriesResult, error)
	QuerySubjectCoverage(ctx context.Context, query collector.SubjectCoverageQuery) ([]collector.CoverageBucket, error)
}

// MetricsHandler handles metrics API requests.
type MetricsHandler struct {
	collector *collector.Collector
	store     MetricsStore
	cfg       MetricsHandlerConfig
}

// NewMetricsHandler creates a new MetricsHandler.
func NewMetricsHandler(c *collector.Collector, s MetricsStore, cfg MetricsHandlerConfig) *MetricsHandler {
	return &MetricsHandler{
		collector: c,
		store:     s,
		cfg:       normalizeMetricsHandlerConfig(cfg),
	}
}

// TimeRange represents a time range for queries.
type TimeRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// TimeRangePreset represents preset time ranges like Grafana.
type TimeRangePreset string

const (
	TimeRangeLast5m     TimeRangePreset = "5m"
	TimeRangeLast15m    TimeRangePreset = "15m"
	TimeRangeLast30m    TimeRangePreset = "30m"
	TimeRangeLast1h     TimeRangePreset = "1h"
	TimeRangeLast3h     TimeRangePreset = "3h"
	TimeRangeLast6h     TimeRangePreset = "6h"
	TimeRangeLast12h    TimeRangePreset = "12h"
	TimeRangeLast24h    TimeRangePreset = "24h"
	TimeRangeLast2d     TimeRangePreset = "2d"
	TimeRangeLastSevenD TimeRangePreset = "7d"
	TimeRangeLast30d    TimeRangePreset = "30d"
	TimeRangeLast90d    TimeRangePreset = "90d"
	TimeRangeLast1y     TimeRangePreset = "1y"
)

//nolint:revive,gocyclo,cyclop // cyclomatic: this function is a simple range selector.
func ParseTimeRange(preset string, customFrom, customTo int64) TimeRange {
	now := time.Now().UnixMilli()

	if customFrom > 0 && customTo > 0 {
		return TimeRange{From: customFrom, To: customTo}
	}

	var duration time.Duration

	switch TimeRangePreset(preset) {
	case TimeRangeLast5m:
		duration = 5 * time.Minute
	case TimeRangeLast15m:
		duration = durationMinutes15 * time.Minute
	case TimeRangeLast30m:
		duration = 30 * time.Minute
	case TimeRangeLast1h:
		duration = 1 * time.Hour
	case TimeRangeLast3h:
		duration = 3 * time.Hour
	case TimeRangeLast6h:
		duration = 6 * time.Hour
	case TimeRangeLast12h:
		duration = durationHours12 * time.Hour
	case TimeRangeLast24h:
		duration = 24 * time.Hour
	case TimeRangeLast2d:
		duration = 2 * 24 * time.Hour
	case TimeRangeLastSevenD:
		duration = 7 * 24 * time.Hour
	case TimeRangeLast30d:
		duration = 30 * 24 * time.Hour
	case TimeRangeLast90d:
		duration = durationDays90 * 24 * time.Hour
	case TimeRangeLast1y:
		duration = durationDays365 * 24 * time.Hour
	default:
		duration = 1 * time.Hour // Default to last hour.
	}

	return TimeRange{
		From: now - duration.Milliseconds(),
		To:   now,
	}
}

// SelectResolution automatically selects appropriate resolution based on time range.
func SelectResolution(tr TimeRange) string {
	duration := time.Duration(tr.To-tr.From) * time.Millisecond

	switch {
	case duration <= 1*time.Hour:
		return "raw"
	case duration <= 6*time.Hour:
		return "1m"
	case duration <= 24*time.Hour:
		return "5m"
	case duration <= 7*24*time.Hour:
		return "1h"
	default:
		return "1d"
	}
}

// DashboardOverviewResponse represents the overview dashboard data.
type DashboardOverviewResponse struct {
	SystemMetrics SystemMetricsData  `json:"systemMetrics"`
	QueueMetrics  []QueueMetricsData `json:"queueMetrics"`
	TimeRange     TimeRange          `json:"timeRange"`
	UpdatedAt     int64              `json:"updatedAt"`
}

// SystemMetricsData represents system-wide metrics.
type SystemMetricsData struct {
	QueuesExist   int64   `json:"queuesExist"`
	TotalInFlight int64   `json:"totalInFlight"`
	SendRate      float64 `json:"sendRate"`
	ReceiveRate   float64 `json:"receiveRate"`
	DeleteRate    float64 `json:"deleteRate"`
	TotalSent     uint64  `json:"totalSent"`
	TotalReceived uint64  `json:"totalReceived"`
	TotalDeleted  uint64  `json:"totalDeleted"`
}

// QueueMetricsData represents metrics for a single queue.
type QueueMetricsData struct {
	QueueID          string  `json:"queueId"`
	QueueName        string  `json:"queueName,omitempty"`
	InFlight         int64   `json:"inFlight"`
	SendRate         float64 `json:"sendRate"`
	ReceiveRate      float64 `json:"receiveRate"`
	DeleteRate       float64 `json:"deleteRate"`
	MessagesSent     uint64  `json:"messagesSent"`
	MessagesReceived uint64  `json:"messagesReceived"`
	MessagesDeleted  uint64  `json:"messagesDeleted"`
	EmptyReceives    uint64  `json:"emptyReceives"`
}

// TopicDashboardOverviewResponse represents the topic overview dashboard data.
type TopicDashboardOverviewResponse struct {
	SystemMetrics      TopicSystemMetricsData `json:"systemMetrics"`
	TopicMetrics       []TopicMetricsData     `json:"topicMetrics"`
	TimeRange          TimeRange              `json:"timeRange"`
	EffectiveTimeRange TimeRange              `json:"effectiveTimeRange"`
	Resolution         string                 `json:"resolution"`
	UpdatedAt          int64                  `json:"updatedAt"`
}

// TopicSystemMetricsData represents system-wide topic metrics.
type TopicSystemMetricsData struct {
	PublishRate               float64             `json:"publishRate"`
	DeliveryRate              float64             `json:"deliveryRate"`
	MessagesPublished         uint64              `json:"messagesPublished"`
	PublishedBytes            uint64              `json:"publishedBytes"`
	Deliveries                uint64              `json:"deliveries"`
	DeliveryFailures          uint64              `json:"deliveryFailures"`
	SubscriptionsCurrent      *int64              `json:"subscriptionsCurrent"`
	SubscriptionsCreated      uint64              `json:"subscriptionsCreated"`
	SubscriptionsDeleted      uint64              `json:"subscriptionsDeleted"`
	TopicsExist               int64               `json:"topicsExist"`
	OperationSummaries        *[]OperationSummary `json:"operationSummaries"`
	StorageOperationSummaries *[]OperationSummary `json:"storageOperationSummaries"`
}

// TopicMetricsData represents metrics for a single topic.
type TopicMetricsData struct {
	TopicID              string  `json:"topicId"`
	PublishRate          float64 `json:"publishRate"`
	DeliveryRate         float64 `json:"deliveryRate"`
	MessagesPublished    uint64  `json:"messagesPublished"`
	Deliveries           uint64  `json:"deliveries"`
	SubscriptionsCurrent *int64  `json:"subscriptionsCurrent"`
	SubscriptionsCreated uint64  `json:"subscriptionsCreated"`
	SubscriptionsDeleted uint64  `json:"subscriptionsDeleted"`
	UpdatedAt            int64   `json:"updatedAt"`
}

// MetricsChartResponse represents time-series data for charts.
type MetricsChartResponse struct {
	MetricName string                `json:"metricName"`
	QueueID    string                `json:"queueId,omitempty"`
	TopicID    string                `json:"topicId,omitempty"`
	TimeRange  TimeRange             `json:"timeRange"`
	Resolution string                `json:"resolution"`
	DataPoints []collector.DataPoint `json:"dataPoints"`
}

// MultiMetricsChartResponse represents multiple metrics for comparison.
type MultiMetricsChartResponse struct {
	Metrics   []MetricsChartResponse `json:"metrics"`
	TimeRange TimeRange              `json:"timeRange"`
}

// GetDashboardOverview returns the overview dashboard data.
func (h *MetricsHandler) GetDashboardOverview(w http.ResponseWriter, r *http.Request) {
	// Get system rates.
	sysRates := h.collector.GetSystemRates()
	sysCounters := h.collector.GetSystemCounters()

	// Build system metrics. The totals were declared on the response from the
	// start and never filled in, so the overview's top row read as a server
	// that had never handled a message.
	systemMetrics := SystemMetricsData{
		QueuesExist:   sysCounters.QueuesExist,
		TotalInFlight: h.collector.GetSystemInFlightCount(),
		SendRate:      sysRates.SendRate,
		ReceiveRate:   sysRates.ReceiveRate,
		DeleteRate:    sysRates.DeleteRate,
		TotalSent:     sysCounters.TotalSent,
		TotalReceived: sysCounters.TotalReceived,
		TotalDeleted:  sysCounters.TotalDeleted,
	}

	// Build per-queue metrics.
	queueIDs := h.collector.GetAllQueueIDs()
	queueMetrics := make([]QueueMetricsData, 0, len(queueIDs))

	for _, queueID := range queueIDs {
		rates := h.collector.GetRates(queueID)
		counters := h.collector.GetCounters(queueID)

		queueMetrics = append(queueMetrics, QueueMetricsData{
			QueueID:          queueID,
			InFlight:         h.collector.GetInFlightCount(queueID),
			SendRate:         rates.SendRate,
			ReceiveRate:      rates.ReceiveRate,
			DeleteRate:       rates.DeleteRate,
			MessagesSent:     counters[collector.MetricMessagesSentTotal],
			MessagesReceived: counters[collector.MetricMessagesReceivedTotal],
			MessagesDeleted:  counters[collector.MetricMessagesDeletedTotal],
			EmptyReceives:    counters[collector.MetricEmptyReceivesTotal],
		})
	}

	resp := DashboardOverviewResponse{
		SystemMetrics: systemMetrics,
		QueueMetrics:  queueMetrics,
		TimeRange:     TimeRange{From: time.Now().Add(-1 * time.Hour).UnixMilli(), To: time.Now().UnixMilli()},
		UpdatedAt:     time.Now().UnixMilli(),
	}

	httpkit.JSON(w, r, resp)
}

// GetMetricsChart returns time-series data for a metric.
func (h *MetricsHandler) GetMetricsChart(w http.ResponseWriter, r *http.Request) {
	metricName := r.URL.Query().Get("metric")
	if metricName == "" {
		http.Error(w, `{"error": "metric parameter required"}`, http.StatusBadRequest)

		return
	}

	queueID := r.URL.Query().Get("queue_id")
	preset := r.URL.Query().Get("range")
	resolution := r.URL.Query().Get("resolution")

	var customFrom, customTo int64

	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		v, err := strconv.ParseInt(fromStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'from' parameter"}`, http.StatusBadRequest)

			return
		}

		customFrom = v
	}

	if toStr := r.URL.Query().Get("to"); toStr != "" {
		v, err := strconv.ParseInt(toStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'to' parameter"}`, http.StatusBadRequest)

			return
		}

		customTo = v
	}

	tr := ParseTimeRange(preset, customFrom, customTo)

	if resolution == "" {
		resolution = SelectResolution(tr)
	}

	// Get data from store.
	dataPoints, err := h.store.GetMetrics(r.Context(), metricName, queueID, tr.From, tr.To, resolution)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	resp := MetricsChartResponse{
		MetricName: metricName,
		QueueID:    queueID,
		TimeRange:  tr,
		Resolution: resolution,
		DataPoints: dataPoints,
	}

	httpkit.JSON(w, r, resp)
}

// GetTopicDashboardOverview returns the topic overview dashboard data.
func (h *MetricsHandler) GetTopicDashboardOverview(w http.ResponseWriter, r *http.Request) {
	query, err := h.parseMetricsQuery(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusBadRequest)

		return
	}

	systemRates := h.collector.GetTopicSystemRates()
	systemCounters := h.collector.GetTopicSystemCounters()

	topicIDs := h.collector.GetAllTopicIDs()
	topicMetrics := make([]TopicMetricsData, 0, len(topicIDs))

	for _, topicID := range topicIDs {
		rates := h.collector.GetTopicRates(topicID)
		counters := h.collector.GetTopicCounters(topicID)
		subscriptionsCurrent, subscriptionsKnown := h.collector.GetTopicSubscriptionsCurrentKnown(topicID)
		topicMetrics = append(topicMetrics, TopicMetricsData{
			TopicID:              topicID,
			PublishRate:          rates.PublishRate,
			DeliveryRate:         rates.DeliveryRate,
			MessagesPublished:    counters.MessagesPublished,
			Deliveries:           counters.Deliveries,
			SubscriptionsCurrent: int64PtrIfKnown(subscriptionsCurrent, subscriptionsKnown),
			SubscriptionsCreated: counters.SubscriptionsCreated,
			SubscriptionsDeleted: counters.SubscriptionsDeleted,
			UpdatedAt:            h.collector.GetTopicLastUpdated(topicID),
		})
	}

	operationSummaries, err := h.summarizeOperations(r.Context(), "", query, false)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	storageOperationSummaries, err := h.summarizeOperations(r.Context(), "", query, true)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	resp := TopicDashboardOverviewResponse{
		SystemMetrics: TopicSystemMetricsData{
			PublishRate:               systemRates.PublishRate,
			DeliveryRate:              systemRates.DeliveryRate,
			MessagesPublished:         systemCounters.MessagesPublished,
			PublishedBytes:            systemCounters.PublishedBytes,
			Deliveries:                systemCounters.Deliveries,
			DeliveryFailures:          systemCounters.DeliveryFailures,
			SubscriptionsCurrent:      int64PtrIfKnown(systemCounters.SubscriptionsCurrent, systemCounters.SubscriptionsCurrentKnown),
			SubscriptionsCreated:      systemCounters.SubscriptionsCreated,
			SubscriptionsDeleted:      systemCounters.SubscriptionsDeleted,
			TopicsExist:               systemCounters.TopicsExist,
			OperationSummaries:        operationSummaries,
			StorageOperationSummaries: storageOperationSummaries,
		},
		TopicMetrics:       topicMetrics,
		TimeRange:          query.TimeRange,
		EffectiveTimeRange: query.EffectiveTimeRange,
		Resolution:         string(query.Resolution),
		UpdatedAt:          query.GeneratedAt,
	}

	httpkit.JSON(w, r, resp)
}

func int64PtrIfKnown(value int64, known bool) *int64 {
	if !known {
		return nil
	}

	return &value
}

// GetRatesChart returns rate history for a queue.
func (h *MetricsHandler) GetRatesChart(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	preset := r.URL.Query().Get("range")

	var customFrom, customTo int64

	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		v, err := strconv.ParseInt(fromStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'from' parameter"}`, http.StatusBadRequest)

			return
		}

		customFrom = v
	}

	if toStr := r.URL.Query().Get("to"); toStr != "" {
		v, err := strconv.ParseInt(toStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'to' parameter"}`, http.StatusBadRequest)

			return
		}

		customTo = v
	}

	tr := ParseTimeRange(preset, customFrom, customTo)

	// Get rate history for all rate types.
	//nolint:errcheck // best-effort metrics retrieval; errors fall back to empty data points.
	sendRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricSendRate, queueID, tr.From, tr.To)
	//nolint:errcheck // best-effort metrics retrieval; errors fall back to empty data points.
	receiveRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricReceiveRate, queueID, tr.From, tr.To)
	//nolint:errcheck // best-effort metrics retrieval; errors fall back to empty data points.
	deleteRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricDeleteRate, queueID, tr.From, tr.To)

	resp := MultiMetricsChartResponse{
		Metrics: []MetricsChartResponse{
			{MetricName: collector.MetricSendRate, QueueID: queueID, DataPoints: sendRates},
			{MetricName: collector.MetricReceiveRate, QueueID: queueID, DataPoints: receiveRates},
			{MetricName: collector.MetricDeleteRate, QueueID: queueID, DataPoints: deleteRates},
		},
		TimeRange: tr,
	}

	httpkit.JSON(w, r, resp)
}

// GetTopicMetrics returns detailed metrics for a specific topic.
func (h *MetricsHandler) GetTopicMetrics(w http.ResponseWriter, r *http.Request) {
	topicID := chi.URLParam(r, "id")

	query, err := h.parseMetricsQuery(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusBadRequest)

		return
	}

	specs := []metricSeriesSpec{
		{Name: collector.MetricTopicMessagesPublishedTotal, Kind: collector.MetricKindCounter},
		{Name: collector.MetricTopicDeliveriesTotal, Kind: collector.MetricKindCounter},
		{Name: collector.MetricTopicPublishedBytesTotal, Kind: collector.MetricKindCounter},
		{Name: collector.MetricTopicDeliveryFailuresTotal, Kind: collector.MetricKindCounter},
		{Name: collector.MetricTopicSubscriptionsCreatedTotal, Kind: collector.MetricKindCounter},
		{Name: collector.MetricTopicSubscriptionsDeletedTotal, Kind: collector.MetricKindCounter},
		{Name: collector.MetricTopicPublishRate, Kind: collector.MetricKindRate},
		{Name: collector.MetricTopicDeliveryRate, Kind: collector.MetricKindRate},
		{Name: collector.MetricTopicSubscriptionsCurrent, Kind: collector.MetricKindGauge, CarryForward: true},
		{Name: collector.MetricTopicFanout, Kind: collector.MetricKindEvent},
	}

	results := make(map[string]collector.SeriesResult, len(specs))
	for _, spec := range specs {
		result, queryErr := h.queryTopicSeries(r.Context(), topicID, spec, query)
		if queryErr != nil {
			http.Error(w, `{"error": "`+queryErr.Error()+`"}`, http.StatusInternalServerError)

			return
		}

		results[spec.Name] = result
	}

	published := summarizeCounterIncrease(results[collector.MetricTopicMessagesPublishedTotal], query)
	deliveries := summarizeCounterIncrease(results[collector.MetricTopicDeliveriesTotal], query)
	publishedBytes := floatToUint64(summarizeCounterIncrease(results[collector.MetricTopicPublishedBytesTotal], query))
	deliveryFailures := floatToUint64(summarizeCounterIncrease(results[collector.MetricTopicDeliveryFailuresTotal], query))
	created := floatToInt64(summarizeCounterIncrease(results[collector.MetricTopicSubscriptionsCreatedTotal], query))
	removed := floatToInt64(summarizeCounterIncrease(results[collector.MetricTopicSubscriptionsDeletedTotal], query))
	avgPublish, maxPublish := summarizeRate(results[collector.MetricTopicPublishRate], query)
	avgDelivery, maxDelivery := summarizeRate(results[collector.MetricTopicDeliveryRate], query)
	subscriptions, _ := latestGaugeValue(results[collector.MetricTopicSubscriptionsCurrent], query)
	fanout := summarizeDistribution(results[collector.MetricTopicFanout], query)

	var averageFanout, maxFanout *float64
	if fanout != nil && fanout.Count > 0 {
		averageFanout = float64Pointer(fanout.Avg)
		maxFanout = float64Pointer(fanout.Max)
	}

	operationSummaries, err := h.summarizeOperations(r.Context(), topicID, query, false)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	storageOperationSummaries, err := h.summarizeOperations(r.Context(), topicID, query, true)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	rates := h.collector.GetTopicRates(topicID)
	resp := TopicMetricsResponse{
		TopicMetricsSummary: &collector.TopicMetricsSummary{
			TopicID:         topicID,
			From:            query.TimeRange.From,
			To:              query.TimeRange.To,
			TotalPublished:  compatibilityInt64(published),
			TotalDeliveries: compatibilityInt64(deliveries),
			AvgPublishRate:  compatibilityFloat64(avgPublish),
			AvgDeliveryRate: compatibilityFloat64(avgDelivery),
			MaxPublishRate:  compatibilityFloat64(maxPublish),
			MaxDeliveryRate: compatibilityFloat64(maxDelivery),
			Subscriptions:   subscriptions,
		},
		CurrentPublishRate:               rates.PublishRate,
		CurrentDeliveryRate:              rates.DeliveryRate,
		TimeRange:                        query.TimeRange,
		TotalPublishedBytes:              publishedBytes,
		TotalDeliveryFailures:            deliveryFailures,
		AverageFanout:                    averageFanout,
		MaxFanout:                        maxFanout,
		SubscriptionsCreatedDuringWindow: created,
		SubscriptionsRemovedDuringWindow: removed,
		EffectiveTimeRange:               query.EffectiveTimeRange,
		Resolution:                       string(query.Resolution),
		GeneratedAt:                      query.GeneratedAt,
		OperationSummaries:               operationSummaries,
		StorageOperationSummaries:        storageOperationSummaries,
	}

	httpkit.JSON(w, r, resp)
}

// GetQueueMetrics returns detailed metrics for a specific queue.
func (h *MetricsHandler) GetQueueMetrics(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	preset := r.URL.Query().Get("range")

	var customFrom, customTo int64

	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		v, err := strconv.ParseInt(fromStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'from' parameter"}`, http.StatusBadRequest)

			return
		}

		customFrom = v
	}

	if toStr := r.URL.Query().Get("to"); toStr != "" {
		v, err := strconv.ParseInt(toStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'to' parameter"}`, http.StatusBadRequest)

			return
		}

		customTo = v
	}

	tr := ParseTimeRange(preset, customFrom, customTo)

	// Get summary.
	summary, err := h.store.GetMetricsSummary(r.Context(), queueID, tr.From, tr.To)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	// Get current rates.
	rates := h.collector.GetRates(queueID)

	resp := struct {
		*collector.MetricsSummary
		CurrentSendRate    float64   `json:"currentSendRate"`
		CurrentReceiveRate float64   `json:"currentReceiveRate"`
		CurrentDeleteRate  float64   `json:"currentDeleteRate"`
		TimeRange          TimeRange `json:"timeRange"`
	}{
		MetricsSummary:     summary,
		CurrentSendRate:    rates.SendRate,
		CurrentReceiveRate: rates.ReceiveRate,
		CurrentDeleteRate:  rates.DeleteRate,
		TimeRange:          tr,
	}

	httpkit.JSON(w, r, resp)
}

// GetTopicRatesChart returns topic rate history for a topic.
func (h *MetricsHandler) GetTopicRatesChart(w http.ResponseWriter, r *http.Request) {
	topicID := chi.URLParam(r, "id")

	query, err := h.parseMetricsQuery(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusBadRequest)

		return
	}

	specs := []metricSeriesSpec{
		{
			Name: collector.MetricTopicPublishRate, Kind: collector.MetricKindRate,
			Unit: metricUnitMessagesPerSecond, Interpolation: metricInterpolationLinear,
		},
		{
			Name: collector.MetricTopicDeliveryRate, Kind: collector.MetricKindRate,
			Unit: metricUnitMessagesPerSecond, Interpolation: metricInterpolationLinear,
		},
		{
			Name: collector.MetricTopicDeliveryFailureRate, Kind: collector.MetricKindRate,
			Unit: metricUnitMessagesPerSecond, Interpolation: metricInterpolationLinear,
		},
	}

	series := make([]MetricSeriesResponse, 0, len(specs))
	for _, spec := range specs {
		result, queryErr := h.queryTopicSeries(r.Context(), topicID, spec, query)
		if queryErr != nil {
			http.Error(w, `{"error": "`+queryErr.Error()+`"}`, http.StatusInternalServerError)

			return
		}

		series = append(series, buildMetricSeries(topicID, spec, query, result))
	}

	resp := TopicSeriesResponse{
		TopicID:            topicID,
		Metrics:            series,
		TimeRange:          query.TimeRange,
		EffectiveTimeRange: query.EffectiveTimeRange,
		Resolution:         string(query.Resolution),
		SampleIntervalMS:   query.SampleIntervalMS,
		GeneratedAt:        query.GeneratedAt,
	}

	httpkit.JSON(w, r, resp)
}

// GetTopicSubscriptions returns active and lifecycle-rate subscription history.
func (h *MetricsHandler) GetTopicSubscriptions(w http.ResponseWriter, r *http.Request) {
	topicID := chi.URLParam(r, "id")

	query, err := h.parseMetricsQuery(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusBadRequest)

		return
	}

	specs := []metricSeriesSpec{
		{
			Name: collector.MetricTopicSubscriptionsCurrent, Kind: collector.MetricKindGauge,
			Unit: "subscriptions", Interpolation: "stepAfter", CarryForward: true,
		},
		{
			Name: collector.MetricTopicSubscriptionsCreatedRate, Kind: collector.MetricKindRate,
			Unit: "subscriptions/s", Interpolation: metricInterpolationLinear,
		},
		{
			Name: collector.MetricTopicSubscriptionsDeletedRate, Kind: collector.MetricKindRate,
			Unit: "subscriptions/s", Interpolation: metricInterpolationLinear,
		},
	}

	results := make([]collector.SeriesResult, 0, len(specs))

	series := make([]MetricSeriesResponse, 0, len(specs))
	for _, spec := range specs {
		result, queryErr := h.queryTopicSeries(r.Context(), topicID, spec, query)
		if queryErr != nil {
			http.Error(w, `{"error": "`+queryErr.Error()+`"}`, http.StatusInternalServerError)

			return
		}

		results = append(results, result)
		series = append(series, buildMetricSeries(topicID, spec, query, result))
	}

	created, err := h.queryTopicSeries(r.Context(), topicID, metricSeriesSpec{
		Name: collector.MetricTopicSubscriptionsCreatedTotal, Kind: collector.MetricKindCounter,
	}, query)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	removed, err := h.queryTopicSeries(r.Context(), topicID, metricSeriesSpec{
		Name: collector.MetricTopicSubscriptionsDeletedTotal, Kind: collector.MetricKindCounter,
	}, query)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	current, updatedAt := latestGaugeValue(results[0], query)
	createdIncrease := floatToInt64(summarizeCounterIncrease(created, query))
	removedIncrease := floatToInt64(summarizeCounterIncrease(removed, query))
	avgCreate, maxCreate := summarizeRate(results[1], query)
	avgRemove, maxRemove := summarizeRate(results[2], query)

	resp := TopicSubscriptionsResponse{
		TopicID: topicID,
		Summary: TopicSubscriptionSummary{
			SubscriptionsCurrent: current,
			CreatedDuringWindow:  createdIncrease,
			RemovedDuringWindow:  removedIncrease,
			AvgCreateRate:        avgCreate,
			AvgRemoveRate:        avgRemove,
			MaxCreateRate:        maxCreate,
			MaxRemoveRate:        maxRemove,
			UpdatedAt:            updatedAt,
		},
		Metrics:            series,
		TimeRange:          query.TimeRange,
		EffectiveTimeRange: query.EffectiveTimeRange,
		Resolution:         string(query.Resolution),
		SampleIntervalMS:   query.SampleIntervalMS,
		GeneratedAt:        query.GeneratedAt,
	}

	httpkit.JSON(w, r, resp)
}

func (h *MetricsHandler) queryTopicSeries(
	ctx context.Context, topicID string, spec metricSeriesSpec, query MetricsQuery,
) (collector.SeriesResult, error) {
	if query.ExpectedPointCount() == 0 {
		return collector.SeriesResult{
			DataPoints: make([]collector.DataPoint, 0), Coverage: make([]collector.CoverageBucket, 0),
			PriorCoverage: make([]collector.CoverageBucket, 0),
		}, nil
	}

	result, err := h.store.QuerySeries(ctx, collector.SeriesQuery{
		MetricName:   spec.Name,
		SubjectID:    topicID,
		Labels:       spec.Labels,
		Kind:         spec.Kind,
		Resolution:   query.Resolution,
		From:         query.EffectiveTimeRange.From,
		To:           query.EffectiveTimeRange.To,
		CarryForward: spec.CarryForward || (spec.Kind == collector.MetricKindCounter && query.Resolution == collector.ResolutionRaw),
	})
	if err != nil {
		return collector.SeriesResult{}, fmt.Errorf("query topic series %s: %w", spec.Name, err)
	}

	return result, nil
}

// GetInFlightMetrics returns in-flight message counts.
func (h *MetricsHandler) GetInFlightMetrics(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")

	var count int64
	if queueID != "" {
		count = h.collector.GetInFlightCount(queueID)
	} else {
		count = h.collector.GetSystemInFlightCount()
	}

	// Also get history from store.
	preset := r.URL.Query().Get("range")
	tr := ParseTimeRange(preset, 0, 0)

	//nolint:errcheck // best-effort metrics query
	history, _ := h.store.GetMetrics(r.Context(), collector.MetricMessagesInFlight, queueID, tr.From, tr.To, SelectResolution(tr))

	resp := struct {
		Current   int64                 `json:"current"`
		QueueID   string                `json:"queueId,omitempty"`
		History   []collector.DataPoint `json:"history"`
		TimeRange TimeRange             `json:"timeRange"`
	}{
		Current:   count,
		QueueID:   queueID,
		History:   history,
		TimeRange: tr,
	}

	httpkit.JSON(w, r, resp)
}

// GetAvailableMetrics returns list of available metrics.
func (*MetricsHandler) GetAvailableMetrics(w http.ResponseWriter, r *http.Request) {
	available := []struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description"`
	}{
		{collector.MetricSendRate, metricTypeGauge, "Messages sent per second"},
		{collector.MetricReceiveRate, metricTypeGauge, "Messages received per second"},
		{collector.MetricDeleteRate, metricTypeGauge, "Messages deleted per second"},
		{collector.MetricMessagesInFlight, metricTypeGauge, "Messages currently being processed"},
		{collector.MetricQueueDepth, metricTypeGauge, "Total messages in queue"},
		{collector.MetricMessagesVisible, metricTypeGauge, "Messages available to receive"},
		{collector.MetricMessagesInvisible, metricTypeGauge, "Messages being processed"},
		{collector.MetricOldestMessageAge, metricTypeGauge, "Age of oldest message in seconds"},
		{collector.MetricMessagesSentTotal, metricTypeCounter, "Total messages sent"},
		{collector.MetricMessagesReceivedTotal, metricTypeCounter, "Total messages received"},
		{collector.MetricMessagesDeletedTotal, metricTypeCounter, "Total messages deleted"},
		{collector.MetricEmptyReceivesTotal, metricTypeCounter, "Total empty receive attempts"},
		{collector.MetricMessagesRedelivered, metricTypeCounter, "Total messages redelivered"},
		{collector.MetricMessagesToDLQ, metricTypeCounter, "Total messages moved to DLQ"},
		{collector.MetricMessageProcessingDuration, metricTypeHistogram, "Message processing duration"},
		{collector.MetricMessageDwellTime, metricTypeHistogram, "Time from send to receive"},
		{collector.MetricBatchSize, metricTypeHistogram, "Batch operation sizes"},
		{collector.MetricMessageSizeBytes, metricTypeHistogram, "Message body sizes"},
		{collector.MetricTopicPublishRate, metricTypeGauge, "Messages published to a topic per second"},
		{collector.MetricTopicDeliveryRate, metricTypeGauge, "Topic message deliveries per second"},
		{collector.MetricTopicMessagesPublishedTotal, metricTypeCounter, "Total messages published to a topic"},
		{collector.MetricTopicDeliveriesTotal, metricTypeCounter, "Total topic message deliveries"},
		{collector.MetricTopicSubscriptionsCurrent, metricTypeGauge, "Current subscriptions on a topic"},
		{collector.MetricTopicSubscriptionsCreatedTotal, metricTypeCounter, "Total topic subscriptions created"},
		{collector.MetricTopicSubscriptionsDeletedTotal, metricTypeCounter, "Total topic subscriptions deleted"},
	}

	httpkit.JSON(w, r, available)
}

// PrometheusMetricDescription documents one metric family on the /metrics
// endpoint.
type PrometheusMetricDescription struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Help   string   `json:"help"`
	Labels []string `json:"labels,omitempty"`
}

// GetPrometheusCatalog lists every metric family the Prometheus endpoint can
// expose.
//
// It is a package-level handler rather than a method because it reads the
// process-wide metric registry and nothing else. Hanging it off the metrics
// handler would have tied it to the telemetry store, and a server running
// with `--telemetry.enable=false` still has a /metrics endpoint worth
// documenting.
//
// The exposition format the metrics library writes carries a metric's type but
// not its description, so a `/metrics` page is a list of names with no
// explanation attached. This is where the explanation lives, and because both
// come from the same declaration they cannot drift apart.
//
// It answers what the binary is *able* to emit, not what it has emitted so
// far: a counter that has never been incremented has no series yet, but an
// operator building a dashboard still needs to know it exists.
func GetPrometheusCatalog(w http.ResponseWriter, r *http.Request) {
	catalog := metrics.Catalog()
	out := make([]PrometheusMetricDescription, 0, len(catalog))

	for _, def := range catalog {
		out = append(out, PrometheusMetricDescription{
			Name:   def.Name,
			Type:   string(def.Kind),
			Help:   def.Help,
			Labels: def.Labels,
		})
	}

	httpkit.JSON(w, r, out)
}

// GetTimeRangePresets returns available time range presets.
func (*MetricsHandler) GetTimeRangePresets(w http.ResponseWriter, r *http.Request) {
	presets := []struct {
		Value string `json:"value"`
		Label string `json:"label"`
	}{
		{string(TimeRangeLast5m), "Last 5 minutes"},
		{string(TimeRangeLast15m), "Last 15 minutes"},
		{string(TimeRangeLast30m), "Last 30 minutes"},
		{string(TimeRangeLast1h), "Last 1 hour"},
		{string(TimeRangeLast3h), "Last 3 hours"},
		{string(TimeRangeLast6h), "Last 6 hours"},
		{string(TimeRangeLast12h), "Last 12 hours"},
		{string(TimeRangeLast24h), "Last 24 hours"},
		{string(TimeRangeLast2d), "Last 2 days"},
		{string(TimeRangeLastSevenD), "Last 7 days"},
		{string(TimeRangeLast30d), "Last 30 days"},
		{string(TimeRangeLast90d), "Last 90 days"},
		{string(TimeRangeLast1y), "Last 1 year"},
	}

	httpkit.JSON(w, r, presets)
}

// ExportMetrics exports metrics in a format suitable for Metabase.
//
//nolint:cyclop // export handler dispatches over format and time-window inputs.
func (h *MetricsHandler) ExportMetrics(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	metricName := r.URL.Query().Get("metric")
	queueID := r.URL.Query().Get("queue_id")
	preset := r.URL.Query().Get("range")

	var customFrom, customTo int64

	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		v, err := strconv.ParseInt(fromStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'from' parameter"}`, http.StatusBadRequest)

			return
		}

		customFrom = v
	}

	if toStr := r.URL.Query().Get("to"); toStr != "" {
		v, err := strconv.ParseInt(toStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error": "invalid 'to' parameter"}`, http.StatusBadRequest)

			return
		}

		customTo = v
	}

	tr := ParseTimeRange(preset, customFrom, customTo)
	resolution := SelectResolution(tr)

	dataPoints, err := h.store.GetMetrics(r.Context(), metricName, queueID, tr.From, tr.To, resolution)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)

		return
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=metrics.csv")
		//nolint:errcheck // HTTP write failure is not recoverable.
		_, _ = w.Write([]byte("timestamp,value,min,max,avg,sum,count\n"))

		for _, p := range dataPoints {
			line := strconv.FormatInt(p.Timestamp, 10) + csvSeparator +
				strconv.FormatFloat(p.Value, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Min, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Max, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Avg, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Sum, 'f', 6, 64) + csvSeparator +
				strconv.FormatInt(p.Count, 10) + "\n"
			//nolint:errcheck // HTTP write failure is not recoverable.
			_, _ = w.Write([]byte(line))
		}
	default:
		// Metabase-friendly JSON format.
		export := struct {
			Columns []string `json:"columns"`
			Rows    [][]any  `json:"rows"`
		}{
			Columns: []string{"timestamp", "datetime", "value", "min", "max", "avg", "sum", "count"},
			Rows:    make([][]any, len(dataPoints)),
		}

		for i, p := range dataPoints {
			export.Rows[i] = []any{
				p.Timestamp,
				time.UnixMilli(p.Timestamp).Format(time.RFC3339),
				p.Value,
				p.Min,
				p.Max,
				p.Avg,
				p.Sum,
				p.Count,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck,errchkjson // best-effort HTTP response encoding.
		_ = json.NewEncoder(w).Encode(export)
	}
}
