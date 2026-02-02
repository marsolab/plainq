package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/plainq/plainq/internal/server/telemetry/collector"
	"github.com/plainq/servekit/respond"
)

// MetricsHandler handles metrics API requests.
type MetricsHandler struct {
	collector *collector.Collector
	store     *collector.SQLiteStore
}

// NewMetricsHandler creates a new MetricsHandler.
func NewMetricsHandler(c *collector.Collector, s *collector.SQLiteStore) *MetricsHandler {
	return &MetricsHandler{
		collector: c,
		store:     s,
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
	TimeRangeLast5m  TimeRangePreset = "5m"
	TimeRangeLast15m TimeRangePreset = "15m"
	TimeRangeLast30m TimeRangePreset = "30m"
	TimeRangeLast1h  TimeRangePreset = "1h"
	TimeRangeLast3h  TimeRangePreset = "3h"
	TimeRangeLast6h  TimeRangePreset = "6h"
	TimeRangeLast12h TimeRangePreset = "12h"
	TimeRangeLast24h TimeRangePreset = "24h"
	TimeRangeLast2d  TimeRangePreset = "2d"
	TimeRangeLast7d  TimeRangePreset = "7d"
	TimeRangeLast30d TimeRangePreset = "30d"
	TimeRangeLast90d TimeRangePreset = "90d"
	TimeRangeLast1y  TimeRangePreset = "1y"
)

// ParseTimeRange parses a time range preset or custom range.
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
		duration = 15 * time.Minute
	case TimeRangeLast30m:
		duration = 30 * time.Minute
	case TimeRangeLast1h:
		duration = 1 * time.Hour
	case TimeRangeLast3h:
		duration = 3 * time.Hour
	case TimeRangeLast6h:
		duration = 6 * time.Hour
	case TimeRangeLast12h:
		duration = 12 * time.Hour
	case TimeRangeLast24h:
		duration = 24 * time.Hour
	case TimeRangeLast2d:
		duration = 2 * 24 * time.Hour
	case TimeRangeLast7d:
		duration = 7 * 24 * time.Hour
	case TimeRangeLast30d:
		duration = 30 * 24 * time.Hour
	case TimeRangeLast90d:
		duration = 90 * 24 * time.Hour
	case TimeRangeLast1y:
		duration = 365 * 24 * time.Hour
	default:
		duration = 1 * time.Hour // Default to last hour
	}

	return TimeRange{
		From: now - int64(duration.Milliseconds()),
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

// MetricsChartResponse represents time-series data for charts.
type MetricsChartResponse struct {
	MetricName string                `json:"metricName"`
	QueueID    string                `json:"queueId,omitempty"`
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
	sendRate, receiveRate, deleteRate := h.collector.GetSystemRates()

	// Build system metrics.
	systemMetrics := SystemMetricsData{
		TotalInFlight: h.collector.GetSystemInFlightCount(),
		SendRate:      sendRate,
		ReceiveRate:   receiveRate,
		DeleteRate:    deleteRate,
	}

	// Build per-queue metrics.
	queueIDs := h.collector.GetAllQueueIDs()
	queueMetrics := make([]QueueMetricsData, 0, len(queueIDs))

	for _, queueID := range queueIDs {
		sr, rr, dr := h.collector.GetRates(queueID)
		counters := h.collector.GetCounters(queueID)

		queueMetrics = append(queueMetrics, QueueMetricsData{
			QueueID:          queueID,
			InFlight:         h.collector.GetInFlightCount(queueID),
			SendRate:         sr,
			ReceiveRate:      rr,
			DeleteRate:       dr,
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

	respond.JSON(w, r, resp)
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
		customFrom, _ = strconv.ParseInt(fromStr, 10, 64)
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		customTo, _ = strconv.ParseInt(toStr, 10, 64)
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

	respond.JSON(w, r, resp)
}

// GetRatesChart returns rate history for a queue.
func (h *MetricsHandler) GetRatesChart(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	preset := r.URL.Query().Get("range")

	var customFrom, customTo int64
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		customFrom, _ = strconv.ParseInt(fromStr, 10, 64)
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		customTo, _ = strconv.ParseInt(toStr, 10, 64)
	}

	tr := ParseTimeRange(preset, customFrom, customTo)

	// Get rate history for all rate types.
	sendRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricSendRate, queueID, tr.From, tr.To)
	receiveRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricReceiveRate, queueID, tr.From, tr.To)
	deleteRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricDeleteRate, queueID, tr.From, tr.To)

	resp := MultiMetricsChartResponse{
		Metrics: []MetricsChartResponse{
			{MetricName: collector.MetricSendRate, QueueID: queueID, DataPoints: sendRates},
			{MetricName: collector.MetricReceiveRate, QueueID: queueID, DataPoints: receiveRates},
			{MetricName: collector.MetricDeleteRate, QueueID: queueID, DataPoints: deleteRates},
		},
		TimeRange: tr,
	}

	respond.JSON(w, r, resp)
}

// GetQueueMetrics returns detailed metrics for a specific queue.
func (h *MetricsHandler) GetQueueMetrics(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	preset := r.URL.Query().Get("range")

	var customFrom, customTo int64
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		customFrom, _ = strconv.ParseInt(fromStr, 10, 64)
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		customTo, _ = strconv.ParseInt(toStr, 10, 64)
	}

	tr := ParseTimeRange(preset, customFrom, customTo)

	// Get summary.
	summary, err := h.store.GetMetricsSummary(r.Context(), queueID, tr.From, tr.To)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Get current rates.
	sr, rr, dr := h.collector.GetRates(queueID)

	resp := struct {
		*collector.MetricsSummary
		CurrentSendRate    float64   `json:"currentSendRate"`
		CurrentReceiveRate float64   `json:"currentReceiveRate"`
		CurrentDeleteRate  float64   `json:"currentDeleteRate"`
		TimeRange          TimeRange `json:"timeRange"`
	}{
		MetricsSummary:     summary,
		CurrentSendRate:    sr,
		CurrentReceiveRate: rr,
		CurrentDeleteRate:  dr,
		TimeRange:          tr,
	}

	respond.JSON(w, r, resp)
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

	respond.JSON(w, r, resp)
}

// GetAvailableMetrics returns list of available metrics.
func (h *MetricsHandler) GetAvailableMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := []struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description"`
	}{
		{collector.MetricSendRate, "gauge", "Messages sent per second"},
		{collector.MetricReceiveRate, "gauge", "Messages received per second"},
		{collector.MetricDeleteRate, "gauge", "Messages deleted per second"},
		{collector.MetricMessagesInFlight, "gauge", "Messages currently being processed"},
		{collector.MetricQueueDepth, "gauge", "Total messages in queue"},
		{collector.MetricMessagesVisible, "gauge", "Messages available to receive"},
		{collector.MetricMessagesInvisible, "gauge", "Messages being processed"},
		{collector.MetricOldestMessageAge, "gauge", "Age of oldest message in seconds"},
		{collector.MetricMessagesSentTotal, "counter", "Total messages sent"},
		{collector.MetricMessagesReceivedTotal, "counter", "Total messages received"},
		{collector.MetricMessagesDeletedTotal, "counter", "Total messages deleted"},
		{collector.MetricEmptyReceivesTotal, "counter", "Total empty receive attempts"},
		{collector.MetricMessagesRedelivered, "counter", "Total messages redelivered"},
		{collector.MetricMessagesToDLQ, "counter", "Total messages moved to DLQ"},
		{collector.MetricMessageProcessingDuration, "histogram", "Message processing duration"},
		{collector.MetricMessageDwellTime, "histogram", "Time from send to receive"},
		{collector.MetricBatchSize, "histogram", "Batch operation sizes"},
		{collector.MetricMessageSizeBytes, "histogram", "Message body sizes"},
	}

	respond.JSON(w, r, metrics)
}

// GetTimeRangePresets returns available time range presets.
func (h *MetricsHandler) GetTimeRangePresets(w http.ResponseWriter, r *http.Request) {
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
		{string(TimeRangeLast7d), "Last 7 days"},
		{string(TimeRangeLast30d), "Last 30 days"},
		{string(TimeRangeLast90d), "Last 90 days"},
		{string(TimeRangeLast1y), "Last 1 year"},
	}

	respond.JSON(w, r, presets)
}

// ExportMetrics exports metrics in a format suitable for Metabase.
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
		customFrom, _ = strconv.ParseInt(fromStr, 10, 64)
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		customTo, _ = strconv.ParseInt(toStr, 10, 64)
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
		w.Write([]byte("timestamp,value,min,max,avg,sum,count\n"))
		for _, p := range dataPoints {
			line := strconv.FormatInt(p.Timestamp, 10) + "," +
				strconv.FormatFloat(p.Value, 'f', 6, 64) + "," +
				strconv.FormatFloat(p.Min, 'f', 6, 64) + "," +
				strconv.FormatFloat(p.Max, 'f', 6, 64) + "," +
				strconv.FormatFloat(p.Avg, 'f', 6, 64) + "," +
				strconv.FormatFloat(p.Sum, 'f', 6, 64) + "," +
				strconv.FormatInt(p.Count, 10) + "\n"
			w.Write([]byte(line))
		}
	default:
		// Metabase-friendly JSON format.
		export := struct {
			Columns []string        `json:"columns"`
			Rows    [][]interface{} `json:"rows"`
		}{
			Columns: []string{"timestamp", "datetime", "value", "min", "max", "avg", "sum", "count"},
			Rows:    make([][]interface{}, len(dataPoints)),
		}

		for i, p := range dataPoints {
			export.Rows[i] = []interface{}{
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
		json.NewEncoder(w).Encode(export)
	}
}
