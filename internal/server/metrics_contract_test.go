package server

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
	"github.com/maxatome/go-testdeep/td"
)

const contractNowMS int64 = 1_700_006_400_000

func TestMetricsContractSignedAlignment(t *testing.T) {
	tests := map[string]struct {
		value    int64
		interval int64
		floor    int64
		ceil     int64
	}{
		"positive aligned":   {value: 2_000, interval: 1_000, floor: 2_000, ceil: 2_000},
		"positive unaligned": {value: 2_001, interval: 1_000, floor: 2_000, ceil: 3_000},
		"negative aligned":   {value: -2_000, interval: 1_000, floor: -2_000, ceil: -2_000},
		"negative unaligned": {value: -2_001, interval: 1_000, floor: -3_000, ceil: -2_000},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			td.Cmp(t, floorTo(tc.value, tc.interval), tc.floor)
			td.Cmp(t, ceilTo(tc.value, tc.interval), tc.ceil)
		})
	}
}

func TestMetricsContractExtremeRangesNeverOverflowNegative(t *testing.T) {
	td.Cmp(t, floorTo(math.MinInt64, 3), int64(math.MinInt64))
	td.Cmp(t, ceilTo(math.MaxInt64, 3), int64(math.MaxInt64))

	query := MetricsQuery{
		EffectiveTimeRange: TimeRange{From: math.MinInt64, To: math.MaxInt64},
		SampleIntervalMS:   1_000,
	}
	td.Cmp(t, query.ExpectedPointCount(), int64(math.MaxInt64/1_000))
}

func TestMetricsContractIntegerConversionsRejectRoundedOverflow(t *testing.T) {
	intOverflow := math.Exp2(63)
	uintOverflow := math.Exp2(64)
	td.Cmp(t, floatToInt64(&intOverflow), (*int64)(nil))
	td.Cmp(t, floatToUint64(&uintOverflow), (*uint64)(nil))

	zero := float64(0)
	td.Cmp(t, floatToInt64(&zero), td.Ptr(int64(0)))
	td.Cmp(t, floatToUint64(&zero), td.Ptr(uint64(0)))
}

func TestMetricsContractSelectsPublicTiers(t *testing.T) {
	tests := map[string]struct {
		span time.Duration
		want collector.Resolution
	}{
		"one hour stays raw":          {span: time.Hour, want: collector.ResolutionRaw},
		"over one hour selects 1m":    {span: time.Hour + time.Millisecond, want: collector.Resolution1m},
		"one day stays 1m":            {span: 24 * time.Hour, want: collector.Resolution1m},
		"over one day selects 1h":     {span: 24*time.Hour + time.Millisecond, want: collector.Resolution1h},
		"thirty days stays 1h":        {span: 30 * 24 * time.Hour, want: collector.Resolution1h},
		"over thirty days selects 1d": {span: 30*24*time.Hour + time.Millisecond, want: collector.Resolution1d},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := selectTopicResolution(TimeRange{From: 10, To: 10 + tc.span.Milliseconds()})
			td.Cmp(t, got, tc.want)
		})
	}
}

func TestMetricsContractParsesRequestedAndEffectiveRanges(t *testing.T) {
	now := time.UnixMilli(contractNowMS)
	h := NewMetricsHandler(nil, nil, MetricsHandlerConfig{
		CollectionInterval: 10 * time.Second,
		RetentionPeriod:    48 * time.Hour,
		Now:                func() time.Time { return now },
	})

	t.Run("unaligned request keeps requested bounds and aligns calculations", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/?from=1700006345001&to=1700006399999", nil)
		query, err := h.parseMetricsQuery(req)
		td.CmpNoError(t, err)
		td.Cmp(t, query.TimeRange, TimeRange{From: 1_700_006_345_001, To: 1_700_006_399_999})
		td.Cmp(t, query.EffectiveTimeRange, TimeRange{From: 1_700_006_350_000, To: 1_700_006_390_000})
		td.Cmp(t, query.Resolution, collector.ResolutionRaw)
		td.Cmp(t, query.SampleIntervalMS, int64(10_000))
		td.Cmp(t, query.GeneratedAt, contractNowMS)
		td.Cmp(t, query.RetentionFrom, int64(1_700_002_800_000))
	})

	t.Run("future-only request is a canonical empty range", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/?from=1700006410000&to=1700006420000", nil)
		query, err := h.parseMetricsQuery(req)
		td.CmpNoError(t, err)
		td.Cmp(t, query.EffectiveTimeRange, TimeRange{From: 1_700_006_410_000, To: 1_700_006_410_000})
		td.Cmp(t, query.ExpectedPointCount(), int64(0))
	})

	t.Run("sub-bucket request is a canonical empty range", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/?from=1700006350001&to=1700006359999", nil)
		query, err := h.parseMetricsQuery(req)
		td.CmpNoError(t, err)
		td.Cmp(t, query.EffectiveTimeRange, TimeRange{From: 1_700_006_359_999, To: 1_700_006_359_999})
		td.Cmp(t, query.ExpectedPointCount(), int64(0))
	})
}

func TestMetricsContractResolutionOverrides(t *testing.T) {
	now := time.UnixMilli(contractNowMS)
	h := NewMetricsHandler(nil, nil, MetricsHandlerConfig{
		CollectionInterval: 10 * time.Second,
		RetentionPeriod:    45 * 24 * time.Hour,
		Now:                func() time.Time { return now },
	})

	tests := map[string]struct {
		url     string
		want    collector.Resolution
		wantErr bool
	}{
		"automatic raw":        {url: "/?range=1h", want: collector.ResolutionRaw},
		"coarser accepted":     {url: "/?range=1h&resolution=1h", want: collector.Resolution1h},
		"legacy 5m rejected":   {url: "/?range=24h&resolution=5m", wantErr: true},
		"unknown rejected":     {url: "/?range=1h&resolution=2m", wantErr: true},
		"finer tier rejected":  {url: "/?range=30d&resolution=1m", wantErr: true},
		"invalid custom range": {url: "/?from=5&to=5", wantErr: true},
		"one custom bound":     {url: "/?from=5", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			query, err := h.parseMetricsQuery(httptest.NewRequest("GET", tc.url, nil))
			if tc.wantErr {
				td.CmpError(t, err)
				return
			}
			td.CmpNoError(t, err)
			td.Cmp(t, query.Resolution, tc.want)
		})
	}
}

func TestMetricsContractCollectorConfigWiringControlsGridAndRetention(t *testing.T) {
	c := collector.New(nil,
		collector.WithCollectionInterval(7*time.Second),
		collector.WithRetentionPeriod(2*time.Hour),
	)
	h := NewMetricsHandler(c, nil, metricsHandlerConfigFromCollector(c, func() time.Time {
		return time.UnixMilli(contractNowMS)
	}))
	query, err := h.parseMetricsQuery(httptest.NewRequest("GET",
		"/?from=1700002800000&to=1700006400000&resolution=raw", nil))
	td.CmpNoError(t, err)
	td.Cmp(t, query.SampleIntervalMS, int64(7_000))
	// Raw's public horizon is one hour even when configured retention is longer.
	td.Cmp(t, query.RetentionFrom, ceilTo(contractNowMS-time.Hour.Milliseconds(), 7_000))
}

func TestMetricsContractCounterSummaryIsResetAndCoverageAware(t *testing.T) {
	query := testMetricsQuery(1_000, 4_000, 1_000)
	result := collector.SeriesResult{
		Prior:         &collector.DataPoint{Timestamp: 0, Value: 3, Source: "observed", Count: 1},
		PriorCoverage: []collector.CoverageBucket{testCoverage(0, 1_000)},
		Coverage: []collector.CoverageBucket{
			testCoverage(1_000, 1_000), testCoverage(2_000, 1_000), testCoverage(3_000, 1_000),
		},
		DataPoints: []collector.DataPoint{
			{Timestamp: 1_000, Value: 5, Source: "observed", Count: 1},
			{Timestamp: 2_000, Value: 2, Source: "observed", Count: 1},
			{Timestamp: 3_000, Value: 8, Source: "observed", Count: 1},
		},
	}

	td.Cmp(t, summarizeCounterIncrease(result, query), td.Ptr(float64(10)))

	withoutBaseline := result
	withoutBaseline.Prior = nil
	td.Cmp(t, summarizeCounterIncrease(withoutBaseline, query), (*float64)(nil))

	result.Coverage = append([]collector.CoverageBucket(nil), result.Coverage[:1]...)
	result.Coverage = append(result.Coverage, testCoverage(3_000, 1_000))
	td.Cmp(t, summarizeCounterIncrease(result, query), (*float64)(nil))
}

func TestMetricsContractSummariesWeightRawAndRollupRows(t *testing.T) {
	query := testMetricsQuery(0, 3_000, 1_000)
	result := collector.SeriesResult{
		Coverage: []collector.CoverageBucket{
			testCoverage(0, 1_000), testCoverage(1_000, 1_000), testCoverage(2_000, 1_000),
		},
		DataPoints: []collector.DataPoint{
			{Timestamp: 0, Value: 10, Source: "observed", Count: 1, WindowMS: 1_000},
			{Timestamp: 1_000, Value: 2, Source: "aggregated", Min: 1, Max: 4, Avg: 2, Sum: 6, Count: 3, WindowMS: 9_000},
			{Timestamp: 2_000, Value: 5, Source: "observed", Count: 1, WindowMS: 2_000},
		},
	}

	avg, max := summarizeRate(result, query)
	td.Cmp(t, avg, td.Ptr(38.0/12.0))
	td.Cmp(t, max, td.Ptr(float64(10)))

	distribution := summarizeDistribution(result, query)
	td.Cmp(t, distribution, td.Ptr(DurationSummary{
		Min:   1,
		Max:   10,
		Avg:   21.0 / 5.0,
		Sum:   21,
		Count: 5,
	}))

	result.DataPoints[1].WindowMS = 0
	avg, max = summarizeRate(result, query)
	td.Cmp(t, avg, (*float64)(nil))
	td.Cmp(t, max, (*float64)(nil))

	result.DataPoints[1].WindowMS = 9_000
	result.Coverage = result.Coverage[:2]
	avg, max = summarizeRate(result, query)
	td.Cmp(t, avg, (*float64)(nil))
	td.Cmp(t, max, (*float64)(nil))
}

func TestMetricsContractAggregateCounterSummarySumsIncreases(t *testing.T) {
	query := testMetricsQuery(0, 120_000, 60_000)
	query.Resolution = collector.Resolution1m
	result := collector.SeriesResult{
		Coverage: []collector.CoverageBucket{
			testCoverage(0, 60_000), testCoverage(60_000, 60_000),
		},
		DataPoints: []collector.DataPoint{
			{Timestamp: 0, Source: "aggregated", Increase: 4},
			{Timestamp: 60_000, Source: "aggregated", Increase: 0},
		},
	}

	td.Cmp(t, summarizeCounterIncrease(result, query), td.Ptr(float64(4)))
}

func TestMetricsContractBuildSeriesUsesExactCoverageAndRetention(t *testing.T) {
	query := testMetricsQuery(0, 6_000, 1_000)
	query.RetentionFrom = 1_000
	result := collector.SeriesResult{
		Coverage: []collector.CoverageBucket{
			testCoverage(0, 1_000), testCoverage(1_000, 1_000), testCoverage(2_000, 1_000),
			testCoverage(5_000, 1_000),
		},
		DataPoints: []collector.DataPoint{
			{Timestamp: 0, Value: 99, Source: "observed", Count: 1},
			{Timestamp: 1_000, Value: 1, Source: "observed", Count: 1},
			{Timestamp: 2_000, Value: 2, Source: "observed", Count: 1},
			{Timestamp: 3_000, Value: 999, Source: "observed", Count: 1},
			{Timestamp: 4_000, Value: 4, Source: "observed", Count: 1},
			{Timestamp: 5_000, Value: 5, Source: "observed", Count: 1},
		},
	}

	series := buildMetricSeries("topic-1", metricSeriesSpec{
		Name: collector.MetricTopicPublishRate, Kind: collector.MetricKindRate,
		Unit: "messages/s", Interpolation: "linear",
	}, query, result)

	td.Cmp(t, series.Samples, SampleMetadata{
		ExpectedPointCount: 6,
		ReturnedPointCount: 3,
		FirstSampleAt:      int64Pointer(1_000),
		LastSampleAt:       int64Pointer(5_000),
		Complete:           false,
		MissingRanges: []MissingRange{
			{From: 0, To: 1_000, Reason: "outsideRetention"},
			{From: 3_000, To: 5_000, Reason: "notRecorded"},
		},
	})
	td.Cmp(t, series.DataPoints, []MetricDataPoint{
		{Timestamp: 1_000, Value: 1, Source: "observed", Count: int64Pointer(1)},
		{Timestamp: 2_000, Value: 2, Source: "observed", Count: int64Pointer(1)},
		{Timestamp: 5_000, Value: 5, Source: "observed", Count: int64Pointer(1)},
	})
}

func TestMetricsContractBuildSeriesPreservesAggregateZeroFields(t *testing.T) {
	query := testMetricsQuery(0, 60_000, 60_000)
	query.Resolution = collector.Resolution1m
	result := collector.SeriesResult{
		Coverage: []collector.CoverageBucket{testCoverage(0, 60_000)},
		DataPoints: []collector.DataPoint{{
			Timestamp: 0, Source: "aggregated", Value: 0,
			Min: 0, Max: 0, Avg: 0, Sum: 0, Count: 0,
		}},
	}

	series := buildMetricSeries("topic-1", metricSeriesSpec{
		Name: collector.MetricTopicPublishRate, Kind: collector.MetricKindRate,
		Unit: "messages/s", Interpolation: "linear",
	}, query, result)
	encoded, err := json.Marshal(series.DataPoints)
	td.CmpNoError(t, err)
	td.Cmp(t, string(encoded),
		`[{"timestamp":0,"value":0,"source":"aggregated","min":0,"max":0,"avg":0,"sum":0,"count":0}]`)
}

func TestMetricsContractGaugeCarryForwardIsContinuousAndDeduplicated(t *testing.T) {
	query := testMetricsQuery(2_000, 5_000, 1_000)
	result := collector.SeriesResult{
		Prior: &collector.DataPoint{Timestamp: 0, Value: 7, Source: "observed", Count: 1},
		PriorCoverage: []collector.CoverageBucket{
			testCoverage(0, 1_000), testCoverage(1_000, 1_000),
		},
		Coverage: []collector.CoverageBucket{
			testCoverage(2_000, 1_000), testCoverage(3_000, 1_000), testCoverage(4_000, 1_000),
		},
		DataPoints: []collector.DataPoint{{Timestamp: 3_000, Value: 9, Source: "observed", Count: 1}},
	}
	spec := metricSeriesSpec{
		Name: collector.MetricTopicSubscriptionsCurrent, Kind: collector.MetricKindGauge,
		Unit: "subscriptions", Interpolation: "stepAfter", CarryForward: true,
	}

	t.Run("continuous coverage carries to effective start", func(t *testing.T) {
		series := buildMetricSeries("topic-1", spec, query, result)
		td.Cmp(t, series.DataPoints, []MetricDataPoint{
			{Timestamp: 2_000, Value: 7, Source: "carriedForward"},
			{Timestamp: 3_000, Value: 9, Source: "observed", Count: int64Pointer(1)},
		})
	})

	t.Run("prior coverage gap stops carry", func(t *testing.T) {
		withGap := result
		withGap.PriorCoverage = []collector.CoverageBucket{testCoverage(0, 1_000)}
		series := buildMetricSeries("topic-1", spec, query, withGap)
		td.Cmp(t, series.DataPoints, []MetricDataPoint{
			{Timestamp: 3_000, Value: 9, Source: "observed", Count: int64Pointer(1)},
		})
	})

	t.Run("covered point at effective start wins without duplicate", func(t *testing.T) {
		withStart := result
		withStart.DataPoints = append([]collector.DataPoint{
			{Timestamp: 2_000, Value: 8, Source: "observed", Count: 1},
		}, result.DataPoints...)
		series := buildMetricSeries("topic-1", spec, query, withStart)
		if len(series.DataPoints) != 2 || series.DataPoints[0].Timestamp != 2_000 ||
			series.DataPoints[0].Source != "observed" {
			t.Fatalf("dataPoints = %#v, want observed start and one later point", series.DataPoints)
		}
	})
}

func TestMetricsContractCanonicalEmptySeriesUsesArrays(t *testing.T) {
	query := testMetricsQuery(5_000, 5_000, 1_000)
	series := buildMetricSeries("topic-1", metricSeriesSpec{
		Name: collector.MetricTopicPublishRate, Kind: collector.MetricKindRate,
		Unit: "messages/s", Interpolation: "linear",
	}, query, collector.SeriesResult{})

	encoded, err := json.Marshal(series)
	td.CmpNoError(t, err)
	if !strings.Contains(string(encoded), `"missingRanges":[]`) ||
		!strings.Contains(string(encoded), `"dataPoints":[]`) ||
		!strings.Contains(string(encoded), `"complete":false`) {
		t.Fatalf("canonical empty JSON = %s", encoded)
	}
}

func testMetricsQuery(from, to, interval int64) MetricsQuery {
	return MetricsQuery{
		TimeRange:          TimeRange{From: from, To: to},
		EffectiveTimeRange: TimeRange{From: from, To: to},
		Resolution:         collector.ResolutionRaw,
		SampleIntervalMS:   interval,
		GeneratedAt:        to,
		RetentionFrom:      from,
	}
}

func testCoverage(timestamp, interval int64) collector.CoverageBucket {
	return collector.CoverageBucket{
		Resolution:       collector.ResolutionRaw,
		BucketStart:      timestamp,
		MetricName:       "metric",
		Kind:             collector.MetricKindRate,
		SampleIntervalMS: interval,
	}
}

func int64Pointer(value int64) *int64 { return &value }
