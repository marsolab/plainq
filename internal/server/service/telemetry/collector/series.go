package collector

// MetricKind identifies the semantic aggregation behavior of a series.
type MetricKind string

const (
	MetricKindCounter MetricKind = "counter"
	MetricKindGauge   MetricKind = "gauge"
	MetricKindRate    MetricKind = "rate"
	MetricKindEvent   MetricKind = "event"
)

// Resolution identifies a persisted telemetry tier.
type Resolution string

const (
	ResolutionRaw Resolution = "raw"
	Resolution1m  Resolution = "1m"
	Resolution1h  Resolution = "1h"
	Resolution1d  Resolution = "1d"
)

// MetricSample is one typed raw telemetry sample.
type MetricSample struct {
	Timestamp  int64
	SubjectID  string
	MetricName string
	Kind       MetricKind
	Value      float64
	Labels     string
	WindowMS   int64
}

// DataPoint represents a single metric data point.
type DataPoint struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
	Min       float64 `json:"min,omitempty"`
	Max       float64 `json:"max,omitempty"`
	Avg       float64 `json:"avg,omitempty"`
	Sum       float64 `json:"sum,omitempty"`
	Count     int64   `json:"count,omitempty"`
	First     float64 `json:"first,omitempty"`
	Last      float64 `json:"last,omitempty"`
	Increase  float64 `json:"increase,omitempty"`
	Source    string  `json:"source,omitempty"`
	WindowMS  int64   `json:"windowMs,omitempty"`
}

// CoverageBucket proves that collection ran for one exact identity and bucket.
type CoverageBucket struct {
	Resolution       Resolution
	BucketStart      int64
	SubjectID        string
	MetricName       string
	Labels           string
	Kind             MetricKind
	SampleIntervalMS int64
}

// SeriesQuery selects one exact typed series over a half-open range.
type SeriesQuery struct {
	MetricName   string
	SubjectID    string
	Labels       string
	Kind         MetricKind
	Resolution   Resolution
	From         int64
	To           int64
	CarryForward bool
}

// SubjectCoverageQuery selects collector-wide coverage, never series coverage.
type SubjectCoverageQuery struct {
	SubjectID  string
	Resolution Resolution
	From       int64
	To         int64
}

// SeriesResult is one snapshot-consistent series response.
type SeriesResult struct {
	DataPoints    []DataPoint
	Coverage      []CoverageBucket
	Prior         *DataPoint
	PriorCoverage []CoverageBucket
}

// TerminalState is durable work for a subject that disappeared.
type TerminalState struct {
	SubjectID        string
	Generation       int64
	ObservedAt       int64
	TargetBucket     *int64
	SampleIntervalMS *int64
}

// RateSnapshot retains the compatibility rate history beside a typed sample.
type RateSnapshot struct {
	Timestamp  int64
	SubjectID  string
	MetricName string
	Rate       float64
	WindowMS   int64
}

// CollectionBatch is one atomically committed closed collection boundary.
type CollectionBatch struct {
	Boundary         int64
	SampleIntervalMS int64
	Samples          []MetricSample
	RateSnapshots    []RateSnapshot
	Coverage         []CoverageBucket
}
