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

	// csvSeparator is the comma separator used in CSV export.
	csvSeparator = ","
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

//nolint:revive // cyclomatic: this function is a simple range selector
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
	sysRates := h.collector.GetSystemRates()

	// Build system metrics.
	systemMetrics := SystemMetricsData{
		TotalInFlight: h.collector.GetSystemInFlightCount(),
		SendRate:      sysRates.SendRate,
		ReceiveRate:   sysRates.ReceiveRate,
		DeleteRate:    sysRates.DeleteRate,
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

	respond.JSON(w, r, resp)
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
	sendRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricSendRate, queueID, tr.From, tr.To)       //nolint:errcheck // best-effort
	receiveRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricReceiveRate, queueID, tr.From, tr.To) //nolint:errcheck // best-effort
	deleteRates, _ := h.store.GetRateHistory(r.Context(), collector.MetricDeleteRate, queueID, tr.From, tr.To)   //nolint:errcheck // best-effort

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

	respond.JSON(w, r, resp)
}

// GetAvailableMetrics returns list of available metrics.
func (*MetricsHandler) GetAvailableMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := []struct {
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
		{collector.MetricMessageProcessingDuration, "histogram", "Message processing duration"},
		{collector.MetricMessageDwellTime, "histogram", "Time from send to receive"},
		{collector.MetricBatchSize, "histogram", "Batch operation sizes"},
		{collector.MetricMessageSizeBytes, "histogram", "Message body sizes"},
	}

	respond.JSON(w, r, metrics)
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
		_, _ = w.Write([]byte("timestamp,value,min,max,avg,sum,count\n")) //nolint:errcheck // HTTP write failure is not recoverable
		for _, p := range dataPoints {
			line := strconv.FormatInt(p.Timestamp, 10) + csvSeparator +
				strconv.FormatFloat(p.Value, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Min, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Max, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Avg, 'f', 6, 64) + csvSeparator +
				strconv.FormatFloat(p.Sum, 'f', 6, 64) + csvSeparator +
				strconv.FormatInt(p.Count, 10) + "\n"
			_, _ = w.Write([]byte(line)) //nolint:errcheck // HTTP write failure is not recoverable
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
		_ = json.NewEncoder(w).Encode(export) //nolint:errcheck // best-effort HTTP response encoding
	}
}
