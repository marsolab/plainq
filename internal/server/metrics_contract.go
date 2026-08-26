package server

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
)

const (
	defaultMetricsCollectionInterval = time.Second
	defaultMetricsRetentionPeriod    = 14 * 24 * time.Hour
	metricSourceAggregated           = "aggregated"
	metricInterpolationLinear        = "linear"
	metricUnitMessagesPerSecond      = "messages/s"
)

// MissingRange describes a contiguous interval without usable samples.
type MissingRange struct {
	From   int64  `json:"from"`
	To     int64  `json:"to"`
	Reason string `json:"reason"`
}

// SampleMetadata describes the completeness of one exact metric series.
type SampleMetadata struct {
	ExpectedPointCount int64          `json:"expectedPointCount"`
	ReturnedPointCount int64          `json:"returnedPointCount"`
	FirstSampleAt      *int64         `json:"firstSampleAt"`
	LastSampleAt       *int64         `json:"lastSampleAt"`
	Complete           bool           `json:"complete"`
	MissingRanges      []MissingRange `json:"missingRanges"`
}

// MetricDataPoint is one stable pub/sub telemetry point.
type MetricDataPoint struct {
	Timestamp int64    `json:"timestamp"`
	Value     float64  `json:"value"`
	Source    string   `json:"source"`
	Min       *float64 `json:"min,omitempty"`
	Max       *float64 `json:"max,omitempty"`
	Avg       *float64 `json:"avg,omitempty"`
	Sum       *float64 `json:"sum,omitempty"`
	Count     *int64   `json:"count,omitempty"`
}

// MetricSeriesResponse is one typed telemetry series and its coverage.
type MetricSeriesResponse struct {
	MetricName    string            `json:"metricName"`
	TopicID       string            `json:"topicId"`
	Kind          string            `json:"kind"`
	Unit          string            `json:"unit"`
	Interpolation string            `json:"interpolation"`
	TimeRange     TimeRange         `json:"timeRange"`
	Resolution    string            `json:"resolution"`
	Samples       SampleMetadata    `json:"samples"`
	DataPoints    []MetricDataPoint `json:"dataPoints"`
}

// TopicSeriesResponse is the stable envelope shared by topic graphs.
type TopicSeriesResponse struct {
	TopicID            string                 `json:"topicId"`
	Metrics            []MetricSeriesResponse `json:"metrics"`
	TimeRange          TimeRange              `json:"timeRange"`
	EffectiveTimeRange TimeRange              `json:"effectiveTimeRange"`
	Resolution         string                 `json:"resolution"`
	SampleIntervalMS   int64                  `json:"sampleIntervalMs"`
	GeneratedAt        int64                  `json:"generatedAt"`
}

// TopicSubscriptionSummary contains only values supported by complete coverage.
type TopicSubscriptionSummary struct {
	SubscriptionsCurrent *int64   `json:"subscriptionsCurrent"`
	CreatedDuringWindow  *int64   `json:"createdDuringWindow"`
	RemovedDuringWindow  *int64   `json:"removedDuringWindow"`
	AvgCreateRate        *float64 `json:"avgCreateRate"`
	AvgRemoveRate        *float64 `json:"avgRemoveRate"`
	MaxCreateRate        *float64 `json:"maxCreateRate"`
	MaxRemoveRate        *float64 `json:"maxRemoveRate"`
	UpdatedAt            *int64   `json:"updatedAt"`
}

// TopicSubscriptionsResponse combines subscription history and summary values.
type TopicSubscriptionsResponse struct {
	TopicID            string                   `json:"topicId"`
	Summary            TopicSubscriptionSummary `json:"summary"`
	Metrics            []MetricSeriesResponse   `json:"metrics"`
	TimeRange          TimeRange                `json:"timeRange"`
	EffectiveTimeRange TimeRange                `json:"effectiveTimeRange"`
	Resolution         string                   `json:"resolution"`
	SampleIntervalMS   int64                    `json:"sampleIntervalMs"`
	GeneratedAt        int64                    `json:"generatedAt"`
}

// DurationSummary is an exact weighted distribution summary.
type DurationSummary struct {
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	Avg   float64 `json:"avg"`
	Sum   float64 `json:"sum"`
	Count int64   `json:"count"`
}

// OperationSummary keeps request/storage work in a fixed public vocabulary.
type OperationSummary struct {
	Backend         string          `json:"backend"`
	Operation       string          `json:"operation"`
	OK              int64           `json:"ok"`
	Error           int64           `json:"error"`
	DurationSeconds DurationSummary `json:"durationSeconds"`
}

// TopicMetricsResponse extends the compatibility summary with exact-range data.
type TopicMetricsResponse struct {
	*collector.TopicMetricsSummary
	CurrentPublishRate               float64             `json:"currentPublishRate"`
	CurrentDeliveryRate              float64             `json:"currentDeliveryRate"`
	TimeRange                        TimeRange           `json:"timeRange"`
	TotalPublishedBytes              *uint64             `json:"totalPublishedBytes"`
	TotalDeliveryFailures            *uint64             `json:"totalDeliveryFailures"`
	AverageFanout                    *float64            `json:"averageFanout"`
	MaxFanout                        *float64            `json:"maxFanout"`
	SubscriptionsCreatedDuringWindow *int64              `json:"subscriptionsCreatedDuringWindow"`
	SubscriptionsRemovedDuringWindow *int64              `json:"subscriptionsRemovedDuringWindow"`
	EffectiveTimeRange               TimeRange           `json:"effectiveTimeRange"`
	Resolution                       string              `json:"resolution"`
	GeneratedAt                      int64               `json:"generatedAt"`
	OperationSummaries               *[]OperationSummary `json:"operationSummaries"`
	StorageOperationSummaries        *[]OperationSummary `json:"storageOperationSummaries"`
}

// MetricsQuery is the single authoritative interpretation of a metrics request.
type MetricsQuery struct {
	TimeRange          TimeRange
	EffectiveTimeRange TimeRange
	Resolution         collector.Resolution
	SampleIntervalMS   int64
	GeneratedAt        int64
	RetentionFrom      int64
}

// ExpectedPointCount returns the non-negative size of the effective half-open grid.
func (q MetricsQuery) ExpectedPointCount() int64 {
	if q.SampleIntervalMS <= 0 || q.EffectiveTimeRange.To <= q.EffectiveTimeRange.From {
		return 0
	}

	return rangeSpan(q.EffectiveTimeRange) / q.SampleIntervalMS
}

// MetricsHandlerConfig pins the public raw grid, retention, and response clock.
type MetricsHandlerConfig struct {
	CollectionInterval time.Duration
	RetentionPeriod    time.Duration
	Now                func() time.Time
}

type metricSeriesSpec struct {
	Name          string
	Kind          collector.MetricKind
	Unit          string
	Interpolation string
	Labels        string
	CarryForward  bool
}

func normalizeMetricsHandlerConfig(cfg MetricsHandlerConfig) MetricsHandlerConfig {
	if cfg.CollectionInterval <= 0 {
		cfg.CollectionInterval = defaultMetricsCollectionInterval
	}

	if cfg.RetentionPeriod <= 0 {
		cfg.RetentionPeriod = defaultMetricsRetentionPeriod
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return cfg
}

func metricsHandlerConfigFromCollector(c *collector.Collector, now func() time.Time) MetricsHandlerConfig {
	return MetricsHandlerConfig{
		CollectionInterval: c.CollectionInterval(),
		RetentionPeriod:    c.RetentionPeriod(),
		Now:                now,
	}
}

func floorTo(value, interval int64) int64 {
	if interval <= 0 {
		return value
	}

	quotient := value / interval
	if value < 0 && value%interval != 0 {
		if quotient <= math.MinInt64/interval {
			return math.MinInt64
		}

		quotient--
	}

	return quotient * interval
}

func ceilTo(value, interval int64) int64 {
	if interval <= 0 {
		return value
	}

	floor := floorTo(value, interval)
	if floor == value {
		return value
	}

	if floor > math.MaxInt64-interval {
		return math.MaxInt64
	}

	return floor + interval
}

func canonicalEmptyRange(request TimeRange, closedThrough int64) TimeRange {
	point := min(request.To, closedThrough)
	point = max(request.From, point)

	return TimeRange{From: point, To: point}
}

func selectTopicResolution(tr TimeRange) collector.Resolution {
	span := rangeSpan(tr)

	switch {
	case span <= time.Hour.Milliseconds():
		return collector.ResolutionRaw
	case span <= (24 * time.Hour).Milliseconds():
		return collector.Resolution1m
	case span <= (30 * 24 * time.Hour).Milliseconds():
		return collector.Resolution1h
	default:
		return collector.Resolution1d
	}
}

func rangeSpan(tr TimeRange) int64 {
	if tr.To <= tr.From {
		return 0
	}

	if tr.From < 0 && tr.To > math.MaxInt64+tr.From {
		return math.MaxInt64
	}

	return tr.To - tr.From
}

func topicResolutionRank(resolution collector.Resolution) (int, bool) {
	switch resolution {
	case collector.ResolutionRaw:
		return 0, true
	case collector.Resolution1m:
		return 1, true
	case collector.Resolution1h:
		return 2, true
	case collector.Resolution1d:
		return 3, true
	default:
		return 0, false
	}
}

func resolutionIntervalMS(resolution collector.Resolution, rawInterval int64) int64 {
	switch resolution {
	case collector.ResolutionRaw:
		return rawInterval
	case collector.Resolution1m:
		return time.Minute.Milliseconds()
	case collector.Resolution1h:
		return time.Hour.Milliseconds()
	case collector.Resolution1d:
		return (24 * time.Hour).Milliseconds()
	default:
		return 0
	}
}

func publicTierHorizon(resolution collector.Resolution, retention time.Duration) time.Duration {
	horizon := retention

	switch resolution {
	case collector.ResolutionRaw:
		horizon = min(horizon, time.Hour)
	case collector.Resolution1m:
		horizon = min(horizon, 24*time.Hour)
	case collector.Resolution1h:
		horizon = min(horizon, 30*24*time.Hour)
	case collector.Resolution1d:
		// The 1d public tier uses the configured retention horizon.
	}

	return horizon
}

func (h *MetricsHandler) parseMetricsQuery(r *http.Request) (MetricsQuery, error) {
	generatedAt := h.cfg.Now().UnixMilli()

	requested, err := parseRequestedTimeRange(r, generatedAt)
	if err != nil {
		return MetricsQuery{}, err
	}

	automatic := selectTopicResolution(requested)
	resolution := automatic

	if override := r.URL.Query().Get("resolution"); override != "" {
		resolution = collector.Resolution(override)
		overrideRank, valid := topicResolutionRank(resolution)

		automaticRank, _ := topicResolutionRank(automatic)
		if !valid || overrideRank < automaticRank {
			return MetricsQuery{}, errors.New("resolution is unsupported or finer than retained automatic tier")
		}
	}

	interval := resolutionIntervalMS(resolution, h.cfg.CollectionInterval.Milliseconds())
	closedThrough := floorTo(generatedAt, interval)
	candidateFrom := ceilTo(requested.From, interval)
	candidateTo := min(floorTo(requested.To, interval), closedThrough)

	effective := TimeRange{From: candidateFrom, To: candidateTo}
	if candidateTo <= candidateFrom {
		effective = canonicalEmptyRange(requested, closedThrough)
	}

	horizonMS := publicTierHorizon(resolution, h.cfg.RetentionPeriod).Milliseconds()

	var retentionCandidate int64
	if generatedAt < math.MinInt64+horizonMS {
		retentionCandidate = math.MinInt64
	} else {
		retentionCandidate = generatedAt - horizonMS
	}

	return MetricsQuery{
		TimeRange:          requested,
		EffectiveTimeRange: effective,
		Resolution:         resolution,
		SampleIntervalMS:   interval,
		GeneratedAt:        generatedAt,
		RetentionFrom:      ceilTo(retentionCandidate, interval),
	}, nil
}

func parseRequestedTimeRange(r *http.Request, generatedAt int64) (TimeRange, error) {
	fromText, hasFrom := r.URL.Query()["from"]

	toText, hasTo := r.URL.Query()["to"]
	if hasFrom != hasTo || (hasFrom && (len(fromText) == 0 || len(toText) == 0)) {
		return TimeRange{}, errors.New("from and to must be provided together")
	}

	if hasFrom {
		from, err := strconv.ParseInt(fromText[0], 10, 64)
		if err != nil {
			return TimeRange{}, errors.New("invalid from parameter")
		}

		to, err := strconv.ParseInt(toText[0], 10, 64)
		if err != nil {
			return TimeRange{}, errors.New("invalid to parameter")
		}

		if from >= to {
			return TimeRange{}, errors.New("from must be before to")
		}

		return TimeRange{From: from, To: to}, nil
	}

	duration := presetDuration(r.URL.Query().Get("range"))

	return TimeRange{From: generatedAt - duration.Milliseconds(), To: generatedAt}, nil
}

//nolint:cyclop // The stable preset vocabulary is clearest as one exhaustive switch.
func presetDuration(preset string) time.Duration {
	switch TimeRangePreset(preset) {
	case TimeRangeLast5m:
		return 5 * time.Minute
	case TimeRangeLast15m:
		return durationMinutes15 * time.Minute
	case TimeRangeLast30m:
		return 30 * time.Minute
	case TimeRangeLast1h, "":
		return time.Hour
	case TimeRangeLast3h:
		return 3 * time.Hour
	case TimeRangeLast6h:
		return 6 * time.Hour
	case TimeRangeLast12h:
		return durationHours12 * time.Hour
	case TimeRangeLast24h:
		return 24 * time.Hour
	case TimeRangeLast2d:
		return 2 * 24 * time.Hour
	case TimeRangeLastSevenD:
		return 7 * 24 * time.Hour
	case TimeRangeLast30d:
		return 30 * 24 * time.Hour
	case TimeRangeLast90d:
		return durationDays90 * 24 * time.Hour
	case TimeRangeLast1y:
		return durationDays365 * 24 * time.Hour
	default:
		return time.Hour
	}
}

func completeSeriesCoverage(result collector.SeriesResult, query MetricsQuery) bool {
	if query.ExpectedPointCount() == 0 {
		return false
	}

	covered := make(map[int64]struct{}, len(result.Coverage))
	for _, coverage := range result.Coverage {
		if coverage.SampleIntervalMS == query.SampleIntervalMS {
			covered[coverage.BucketStart] = struct{}{}
		}
	}

	for bucket := query.EffectiveTimeRange.From; bucket < query.EffectiveTimeRange.To; {
		if bucket < query.RetentionFrom {
			return false
		}

		if _, ok := covered[bucket]; !ok {
			return false
		}

		next := addInterval(bucket, query.SampleIntervalMS)
		if next <= bucket {
			return false
		}

		bucket = next
	}

	return true
}

func coveredPoints(result collector.SeriesResult, query MetricsQuery) []collector.DataPoint {
	covered := make(map[int64]struct{}, len(result.Coverage))
	for _, coverage := range result.Coverage {
		if coverage.SampleIntervalMS == query.SampleIntervalMS {
			covered[coverage.BucketStart] = struct{}{}
		}
	}

	points := make([]collector.DataPoint, 0, len(result.DataPoints))
	for _, point := range result.DataPoints {
		bucket := point.Timestamp
		if point.Source == "observed" {
			bucket = floorTo(point.Timestamp, query.SampleIntervalMS)
		}

		if bucket < query.RetentionFrom || bucket < query.EffectiveTimeRange.From || bucket >= query.EffectiveTimeRange.To {
			continue
		}

		if _, ok := covered[bucket]; !ok {
			continue
		}

		points = append(points, point)
	}

	sort.SliceStable(points, func(i, j int) bool { return points[i].Timestamp < points[j].Timestamp })

	return points
}

func buildMetricSeries(
	topicID string,
	spec metricSeriesSpec,
	query MetricsQuery,
	result collector.SeriesResult,
) MetricSeriesResponse {
	missing := missingRanges(result.Coverage, query)
	points := coveredPoints(result, query)
	dataPoints := make([]MetricDataPoint, 0, len(points)+1)

	for _, point := range points {
		converted := MetricDataPoint{
			Timestamp: point.Timestamp,
			Value:     point.Value,
			Source:    point.Source,
		}

		if point.Source == metricSourceAggregated {
			converted.Min = float64Pointer(point.Min)
			converted.Max = float64Pointer(point.Max)
			converted.Avg = float64Pointer(point.Avg)
			converted.Sum = float64Pointer(point.Sum)
			converted.Count = integerPointer(point.Count)
		} else {
			converted.Count = integerPointer(1)
		}

		dataPoints = append(dataPoints, converted)
	}

	if spec.CarryForward && canCarryGauge(result, query, dataPoints) {
		dataPoints = append(dataPoints, MetricDataPoint{
			Timestamp: query.EffectiveTimeRange.From,
			Value:     result.Prior.Value,
			Source:    "carriedForward",
		})
		sort.SliceStable(dataPoints, func(i, j int) bool { return dataPoints[i].Timestamp < dataPoints[j].Timestamp })
	}

	metadata := SampleMetadata{
		ExpectedPointCount: query.ExpectedPointCount(),
		ReturnedPointCount: int64(len(dataPoints)),
		Complete:           query.ExpectedPointCount() > 0 && len(missing) == 0,
		MissingRanges:      missing,
	}
	if len(dataPoints) > 0 {
		metadata.FirstSampleAt = integerPointer(dataPoints[0].Timestamp)
		metadata.LastSampleAt = integerPointer(dataPoints[len(dataPoints)-1].Timestamp)
	}

	return MetricSeriesResponse{
		MetricName:    spec.Name,
		TopicID:       topicID,
		Kind:          string(spec.Kind),
		Unit:          spec.Unit,
		Interpolation: spec.Interpolation,
		TimeRange:     query.TimeRange,
		Resolution:    string(query.Resolution),
		Samples:       metadata,
		DataPoints:    dataPoints,
	}
}

//nolint:cyclop // Retention and exact-coverage gaps deliberately share one ordered range walk.
func missingRanges(coverage []collector.CoverageBucket, query MetricsQuery) []MissingRange {
	missing := make([]MissingRange, 0)
	if query.ExpectedPointCount() == 0 {
		return missing
	}

	covered := make(map[int64]struct{}, len(coverage))
	for _, item := range coverage {
		if item.SampleIntervalMS == query.SampleIntervalMS {
			covered[item.BucketStart] = struct{}{}
		}
	}

	bucket := query.EffectiveTimeRange.From
	if bucket < query.RetentionFrom {
		outsideTo := min(query.RetentionFrom, query.EffectiveTimeRange.To)
		missing = append(missing, MissingRange{From: bucket, To: outsideTo, Reason: "outsideRetention"})
		bucket = outsideTo
	}

	for bucket < query.EffectiveTimeRange.To {
		reason := ""
		if _, ok := covered[bucket]; !ok {
			reason = "notRecorded"
		}

		next := addInterval(bucket, query.SampleIntervalMS)

		if reason != "" {
			last := len(missing) - 1
			if last >= 0 && missing[last].Reason == reason && missing[last].To == bucket {
				missing[last].To = next
			} else {
				missing = append(missing, MissingRange{From: bucket, To: next, Reason: reason})
			}
		}

		if next <= bucket {
			break
		}

		bucket = next
	}

	return missing
}

//nolint:cyclop // Every guard is an independent proof required before carrying a gauge.
func canCarryGauge(result collector.SeriesResult, query MetricsQuery, points []MetricDataPoint) bool {
	if result.Prior == nil || query.ExpectedPointCount() == 0 ||
		query.EffectiveTimeRange.From < query.RetentionFrom || result.Prior.Timestamp >= query.EffectiveTimeRange.From ||
		floorTo(result.Prior.Timestamp, query.SampleIntervalMS) != result.Prior.Timestamp ||
		!coverageContains(result.Coverage, query.EffectiveTimeRange.From, query.SampleIntervalMS) {
		return false
	}

	for _, point := range points {
		if point.Timestamp == query.EffectiveTimeRange.From {
			return false
		}
	}

	for bucket := result.Prior.Timestamp; bucket < query.EffectiveTimeRange.From; {
		if !coverageContains(result.PriorCoverage, bucket, query.SampleIntervalMS) {
			return false
		}

		next := addInterval(bucket, query.SampleIntervalMS)
		if next <= bucket {
			return false
		}

		bucket = next
	}

	return true
}

func addInterval(value, interval int64) int64 {
	if interval <= 0 || value > math.MaxInt64-interval {
		return math.MaxInt64
	}

	return value + interval
}

func integerPointer(value int64) *int64     { return &value }
func float64Pointer(value float64) *float64 { return &value }

func floatToInt64(value *float64) *int64 {
	if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 ||
		*value >= math.Exp2(63) || math.Trunc(*value) != *value {
		return nil
	}

	converted := int64(*value)

	return &converted
}

func floatToUint64(value *float64) *uint64 {
	if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 ||
		*value >= math.Exp2(64) || math.Trunc(*value) != *value {
		return nil
	}

	converted := uint64(*value)

	return &converted
}

func compatibilityInt64(value *float64) int64 {
	converted := floatToInt64(value)
	if converted == nil {
		return 0
	}

	return *converted
}

func compatibilityFloat64(value *float64) float64 {
	if value == nil {
		return 0
	}

	return *value
}

//nolint:gocritic // The two pointers are independently nullable value and timestamp fields.
func latestGaugeValue(result collector.SeriesResult, query MetricsQuery) (*int64, *int64) {
	points := coveredPoints(result, query)
	if len(points) > 0 {
		latest := points[len(points)-1]

		return floatToInt64(&latest.Value), integerPointer(latest.Timestamp)
	}

	if canCarryGauge(result, query, nil) {
		return floatToInt64(&result.Prior.Value), integerPointer(result.Prior.Timestamp)
	}

	return nil, nil
}

//nolint:cyclop // Raw reset math and aggregate increase math intentionally have distinct contracts.
func summarizeCounterIncrease(result collector.SeriesResult, query MetricsQuery) *float64 {
	if !completeSeriesCoverage(result, query) {
		return nil
	}

	points := coveredPoints(result, query)
	if query.Resolution != collector.ResolutionRaw {
		if int64(len(points)) != query.ExpectedPointCount() {
			return nil
		}

		var total float64

		for _, point := range points {
			if point.Source != metricSourceAggregated {
				return nil
			}

			total += point.Increase
		}

		return &total
	}

	priorTimestamp, ok := subtractInterval(query.EffectiveTimeRange.From, query.SampleIntervalMS)
	if !ok || result.Prior == nil || result.Prior.Timestamp != priorTimestamp ||
		!coverageContains(result.PriorCoverage, result.Prior.Timestamp, query.SampleIntervalMS) {
		return nil
	}

	if int64(len(points)) != query.ExpectedPointCount() {
		return nil
	}

	var total float64

	previous := result.Prior.Value

	for _, point := range points {
		if point.Source != "observed" {
			return nil
		}

		if point.Value < previous {
			total += point.Value
		} else {
			total += point.Value - previous
		}

		previous = point.Value
	}

	return &total
}

func subtractInterval(value, interval int64) (int64, bool) {
	if interval <= 0 || value < math.MinInt64+interval {
		return 0, false
	}

	return value - interval, true
}

//nolint:gocritic // The two pointers are independently nullable average and maximum fields.
func summarizeRate(result collector.SeriesResult, query MetricsQuery) (*float64, *float64) {
	if !completeSeriesCoverage(result, query) {
		return nil, nil
	}

	points := coveredPoints(result, query)
	if int64(len(points)) != query.ExpectedPointCount() {
		return nil, nil
	}

	var weighted, windows, maximum float64

	for index, point := range points {
		if point.WindowMS <= 0 {
			return nil, nil
		}

		value := point.Value

		peak := point.Value
		if point.Source == metricSourceAggregated {
			value = point.Avg
			peak = point.Max
		}

		weighted += value * float64(point.WindowMS)
		windows += float64(point.WindowMS)

		if index == 0 || peak > maximum {
			maximum = peak
		}
	}

	if windows <= 0 {
		return nil, nil
	}

	average := weighted / windows

	return &average, &maximum
}

//nolint:cyclop // Raw events and weighted rollups require separate zero/count handling.
func summarizeDistribution(result collector.SeriesResult, query MetricsQuery) *DurationSummary {
	if !completeSeriesCoverage(result, query) {
		return nil
	}

	points := coveredPoints(result, query)
	summary := DurationSummary{}
	haveValue := false

	for _, point := range points {
		minimum, maximum, sum, count := point.Value, point.Value, point.Value, int64(1)
		if point.Source == metricSourceAggregated {
			minimum, maximum, sum, count = point.Min, point.Max, point.Sum, point.Count
		}

		if count < 0 {
			return nil
		}

		if count == 0 {
			continue
		}

		if !haveValue || minimum < summary.Min {
			summary.Min = minimum
		}

		if !haveValue || maximum > summary.Max {
			summary.Max = maximum
		}

		haveValue = true
		summary.Sum += sum
		summary.Count += count
	}

	if summary.Count > 0 {
		summary.Avg = summary.Sum / float64(summary.Count)
	}

	return &summary
}

//nolint:cyclop // The fixed backend/operation matrix independently gates three exact series per entry.
func (h *MetricsHandler) summarizeOperations(
	ctx context.Context, subjectID string, query MetricsQuery, storage bool,
) (*[]OperationSummary, error) {
	counterName := collector.MetricTopicRequestsTotal
	durationName := collector.MetricTopicRequestDuration

	if storage {
		counterName = collector.MetricTopicOperationsTotal
		durationName = collector.MetricTopicOperationDuration
	}

	backends := []string{
		metrics.BackendSQLite,
		metrics.BackendTurso,
		metrics.BackendPostgres,
		metrics.BackendCluster,
	}
	operations := []string{
		metrics.OpListTopics,
		metrics.OpCreateTopic,
		metrics.OpDeleteTopic,
		metrics.OpSubscribe,
		metrics.OpUnsubscribe,
		metrics.OpPublish,
	}

	summaries := make([]OperationSummary, 0)

	for _, backend := range backends {
		for _, operation := range operations {
			okResult, err := h.queryTopicSeries(ctx, subjectID, metricSeriesSpec{
				Name: counterName, Kind: collector.MetricKindCounter,
				Labels: collector.CanonicalTopicResultLabels(backend, operation, metrics.ResultOK),
			}, query)
			if err != nil {
				return nil, err
			}

			errorResult, err := h.queryTopicSeries(ctx, subjectID, metricSeriesSpec{
				Name: counterName, Kind: collector.MetricKindCounter,
				Labels: collector.CanonicalTopicResultLabels(backend, operation, metrics.ResultError),
			}, query)
			if err != nil {
				return nil, err
			}

			durationResult, err := h.queryTopicSeries(ctx, subjectID, metricSeriesSpec{
				Name: durationName, Kind: collector.MetricKindEvent,
				Labels: collector.CanonicalTopicDurationLabels(backend, operation),
			}, query)
			if err != nil {
				return nil, err
			}

			okCount := floatToInt64(summarizeCounterIncrease(okResult, query))
			errorCount := floatToInt64(summarizeCounterIncrease(errorResult, query))

			duration := summarizeDistribution(durationResult, query)
			if okCount == nil || errorCount == nil || duration == nil {
				return nil, nil
			}

			if *okCount == 0 && *errorCount == 0 && duration.Count == 0 {
				continue
			}

			summaries = append(summaries, OperationSummary{
				Backend: backend, Operation: operation, OK: *okCount, Error: *errorCount,
				DurationSeconds: *duration,
			})
		}
	}

	return &summaries, nil
}

func coverageContains(coverage []collector.CoverageBucket, bucket, interval int64) bool {
	for _, item := range coverage {
		if item.BucketStart == bucket && item.SampleIntervalMS == interval {
			return true
		}
	}

	return false
}
