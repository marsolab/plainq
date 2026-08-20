// Package metrics is PlainQ's Prometheus registry.
//
// Every metric the binary exposes is declared here, in one place, with its
// type, its labels and a sentence saying what it is for. Two things follow
// from that. The `/metrics` endpoint has a single owner rather than a dozen
// packages each inventing a name, and the catalog is readable at runtime —
// `Catalog` returns the same list the documentation is generated from, so a
// metric cannot quietly exist without being documented.
//
// The underlying library is VictoriaMetrics/metrics, which writes the
// Prometheus text exposition format. Latency and size distributions use its
// PrometheusHistogram rather than its native one: the native histogram
// exports `vmrange` buckets, which Prometheus will happily scrape and
// `histogram_quantile` will silently refuse to work with.
package metrics

import (
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

// Namespace prefixes every metric PlainQ exposes.
//
// It is not decoration. A queue server is scraped alongside everything else
// in a cluster, and an unprefixed `http_requests_total` collides with the
// three other exporters that also thought it was a reasonable name.
const Namespace = "plainq"

// maxSeriesPerFamily caps how many label combinations one metric family may
// create.
//
// Queue and topic identifiers come from users, and a client that creates
// queues in a loop would otherwise turn the metric registry into an
// unbounded memory leak that also takes the scrape down with it. Past the
// cap, further label combinations collapse onto a single `__overflow__`
// series and plainq_metrics_series_dropped_total starts climbing — the
// numbers stay correct in aggregate, the attribution is what is lost.
const maxSeriesPerFamily = 1024

// overflowLabelValue marks the series that absorbs everything past the cap.
const overflowLabelValue = "__overflow__"

// Result label values. Nearly every operation records whether it worked, and
// it has to be spelled the same way everywhere for a query to sum across
// subsystems.
const (
	ResultOK    = "ok"
	ResultError = "error"
)

// Kind classifies a metric family for the catalog.
type Kind string

// The metric kinds PlainQ exposes.
const (
	KindCounter   Kind = "counter"
	KindGauge     Kind = "gauge"
	KindHistogram Kind = "histogram"
	KindSummary   Kind = "summary"
)

// Definition describes one metric family: what it is called, what it
// measures, and how it is broken down.
type Definition struct {
	// Name is the fully-qualified metric name, prefix included.
	Name string

	// Kind is the Prometheus metric type.
	Kind Kind

	// Help is one sentence on what the metric means and, where it matters,
	// what a bad value looks like.
	Help string

	// Labels are the label names, in the order they are supplied to With.
	Labels []string
}

// catalog holds every declared family, keyed by name.
var (
	catalogMu sync.RWMutex
	catalog   = make(map[string]Definition, 128)
)

// Catalog returns every metric family PlainQ can expose, sorted by name.
//
// It reports what the binary is *able* to emit, not what it has emitted so
// far: a counter that has never been incremented has no series yet, but an
// operator planning dashboards still needs to know it exists.
func Catalog() []Definition {
	catalogMu.RLock()

	out := make([]Definition, 0, len(catalog))
	for _, def := range catalog {
		out = append(out, def)
	}

	catalogMu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

// define registers a family in the catalog and returns it.
//
// Families whose series are created later — a callback gauge only exists once
// the subsystem it reads is running — are declared through it at package
// scope, so the catalog answers "what can this binary emit" rather than "what
// has it emitted so far". Those are different questions on a server whose
// clustering is off by default.
//
// Re-declaring a family identically is allowed: one family often has several
// fixed label combinations registered separately, and each of them names the
// same metric. Declaring it *differently* — same name, different type, help
// or labels — is a programming error, and panicking at startup beats two
// metrics quietly fighting over one series.
func define(def Definition) Definition {
	catalogMu.Lock()
	defer catalogMu.Unlock()

	if existing, exists := catalog[def.Name]; exists {
		if !existing.sameAs(def) {
			panic("metrics: conflicting metric definition: " + def.Name)
		}

		return existing
	}

	catalog[def.Name] = def

	return def
}

// sameAs reports whether two declarations of one metric family agree.
func (d Definition) sameAs(other Definition) bool {
	if d.Name != other.Name || d.Kind != other.Kind || d.Help != other.Help {
		return false
	}

	return slices.Equal(d.Labels, other.Labels)
}

// vec is the shared machinery behind every labeled metric family.
//
// The library's GetOrCreate* functions key on the fully rendered name, so
// calling them on a hot path means formatting `name{queue="…"}` on every
// message. vec formats once per label combination and hands back the same
// handle after that.
type vec[T any] struct {
	def    Definition
	create func(name string) T

	mu    sync.RWMutex
	cache map[string]T
}

func newVec[T any](def Definition, create func(name string) T) *vec[T] {
	return &vec[T]{
		def:    define(def),
		create: create,
		cache:  make(map[string]T),
	}
}

// with returns the handle for one label combination, creating it on first
// use. The number of values must match the family's label names.
func (v *vec[T]) with(values ...string) T {
	if len(values) != len(v.def.Labels) {
		panic("metrics: " + v.def.Name + ": wrong number of label values")
	}

	key := labelKey(values)

	v.mu.RLock()
	handle, ok := v.cache[key]
	v.mu.RUnlock()

	if ok {
		return handle
	}

	return v.create1(key, values)
}

// create1 is the slow path: a label combination seen for the first time.
func (v *vec[T]) create1(key string, values []string) T {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Another goroutine may have won the race to the write lock.
	if handle, ok := v.cache[key]; ok {
		return handle
	}

	if len(v.cache) >= maxSeriesPerFamily {
		values = overflowValues(len(values))
		key = labelKey(values)

		// Counted per attempt, not per series: the useful signal is how much
		// attribution is being lost, not that it is being lost at all.
		droppedSeries.with(v.def.Name).Inc()

		if handle, ok := v.cache[key]; ok {
			return handle
		}
	}

	handle := v.create(render(v.def.Name, v.def.Labels, values))
	v.cache[key] = handle

	return handle
}

// overflowValues returns the label values every over-cap series collapses to.
func overflowValues(n int) []string {
	values := make([]string, 0, n)
	for range n {
		values = append(values, overflowLabelValue)
	}

	return values
}

// labelSeparator joins label values into a cache key. It is a unit separator
// because no label value can legitimately contain one.
const labelSeparator = "\x1f"

func labelKey(values []string) string {
	switch len(values) {
	case 0:
		return ""

	case 1:
		return values[0]

	default:
		return strings.Join(values, labelSeparator)
	}
}

// render builds the `name{label="value",…}` form the library registers under.
func render(name string, labels, values []string) string {
	if len(labels) == 0 {
		return name
	}

	var b strings.Builder

	// Rough but useful: the exact size does not matter, avoiding the first
	// few grows does.
	b.Grow(len(name) + len(labels)*16)

	b.WriteString(name)
	//nolint:errcheck // strings.Builder never returns an error.
	_ = b.WriteByte('{')

	for i, label := range labels {
		if i > 0 {
			//nolint:errcheck // strings.Builder never returns an error.
			_ = b.WriteByte(',')
		}

		b.WriteString(label)
		b.WriteString(`="`)
		writeEscaped(&b, values[i])
		//nolint:errcheck // strings.Builder never returns an error.
		_ = b.WriteByte('"')
	}

	//nolint:errcheck // strings.Builder never returns an error.
	_ = b.WriteByte('}')

	return b.String()
}

// writeEscaped writes a label value with the escaping the exposition format
// requires.
//
// This is not hypothetical tidiness. Queue and topic identifiers reach these
// labels from user input, and the metrics library *panics* on a name it
// cannot parse — so an unescaped quote in an identifier would take down the
// process that recorded it.
func writeEscaped(b *strings.Builder, value string) {
	if !needsEscaping(value) {
		b.WriteString(value)

		return
	}

	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)

		case '"':
			b.WriteString(`\"`)

		case '\n':
			b.WriteString(`\n`)

		default:
			// Other control characters are dropped rather than escaped: the
			// format has no escape for them, and a label value is a name, not
			// a payload.
			if r >= ' ' {
				//nolint:errcheck // strings.Builder never returns an error.
				_, _ = b.WriteRune(r)
			}
		}
	}
}

func needsEscaping(value string) bool {
	for i := range len(value) {
		if c := value[i]; c == '\\' || c == '"' || c < ' ' {
			return true
		}
	}

	return false
}

// Counter is a monotonically increasing count.
type Counter = metrics.Counter

// Gauge is a value that goes up and down.
type Gauge = metrics.Gauge

// Histogram is a Prometheus histogram with explicit `le` buckets, so
// histogram_quantile works on it.
type Histogram = metrics.PrometheusHistogram

// Summary is a streaming quantile summary over a sliding window.
type Summary = metrics.Summary

// CounterVec is a counter family broken down by labels.
type CounterVec struct{ vec *vec[*Counter] }

// NewCounterVec declares a counter family.
func NewCounterVec(def Definition) *CounterVec {
	def.Kind = KindCounter

	return &CounterVec{vec: newVec(def, metrics.GetOrCreateCounter)}
}

// With returns the counter for one label combination.
func (c *CounterVec) With(values ...string) *Counter { return c.vec.with(values...) }

// Add increments the counter for one label combination by n. It is a
// convenience for the common `With(…).Add(int(n))` with the conversion done
// once, safely, here.
func (c *CounterVec) Add(n uint64, values ...string) {
	if n == 0 {
		return
	}

	c.vec.with(values...).AddInt64(int64(min(n, maxCounterAdd) & (1<<63 - 1)))
}

// maxCounterAdd caps a single Add so an implausible count cannot wrap the
// signed conversion the library's API requires.
const maxCounterAdd uint64 = 1 << 62

// GaugeVec is a settable gauge family broken down by labels.
type GaugeVec struct{ vec *vec[*Gauge] }

// NewGaugeVec declares a gauge family whose values are pushed by the code
// that owns them.
func NewGaugeVec(def Definition) *GaugeVec {
	def.Kind = KindGauge

	return &GaugeVec{vec: newVec(def, func(name string) *Gauge {
		return metrics.GetOrCreateGauge(name, nil)
	})}
}

// With returns the gauge for one label combination.
func (g *GaugeVec) With(values ...string) *Gauge { return g.vec.with(values...) }

// Set assigns the gauge for one label combination.
func (g *GaugeVec) Set(value float64, labels ...string) { g.vec.with(labels...).Set(value) }

// Add moves the gauge for one label combination by delta.
func (g *GaugeVec) Add(delta float64, labels ...string) { g.vec.with(labels...).Add(delta) }

// HistogramVec is a histogram family broken down by labels.
type HistogramVec struct {
	vec     *vec[*Histogram]
	buckets []float64
}

// NewHistogramVec declares a histogram family with explicit bucket bounds.
//
// Buckets are given per family rather than defaulted, because the default
// set is tuned for HTTP latency and says almost nothing useful about a
// message body size or a snapshot duration.
func NewHistogramVec(def Definition, buckets []float64) *HistogramVec {
	def.Kind = KindHistogram

	h := HistogramVec{buckets: buckets}

	h.vec = newVec(def, func(name string) *Histogram {
		return metrics.GetOrCreatePrometheusHistogramExt(name, buckets)
	})

	return &h
}

// With returns the histogram for one label combination.
func (h *HistogramVec) With(values ...string) *Histogram { return h.vec.with(values...) }

// Observe records a value.
func (h *HistogramVec) Observe(value float64, labels ...string) {
	h.vec.with(labels...).Update(value)
}

// ObserveDuration records a duration in seconds.
func (h *HistogramVec) ObserveDuration(d time.Duration, labels ...string) {
	h.vec.with(labels...).Update(d.Seconds())
}

// ObserveSince records the time elapsed since start, in seconds.
func (h *HistogramVec) ObserveSince(start time.Time, labels ...string) {
	h.vec.with(labels...).UpdateDuration(start)
}

// GaugeFunc registers a gauge whose value is read from fn at scrape time.
//
// Callback gauges are the right shape for state someone else already owns —
// cluster membership, connection-pool counters — because a scrape then
// reports what is true now rather than what was true when some background
// loop last looked.
func GaugeFunc(def Definition, fn func() float64, labelValues ...string) {
	// A callback-read metric is usually a gauge, but not always: a
	// monotonically increasing count read at scrape time is a counter, and the
	// exposition layer will type it as one on the strength of its `_total`
	// suffix. Let the declaration say so rather than overruling it.
	if def.Kind == "" {
		def.Kind = KindGauge
	}

	def = define(def)

	metrics.GetOrCreateGauge(render(def.Name, def.Labels, labelValues), fn)
}

// CounterFunc registers a cumulative value read from fn at scrape time.
//
// It exists because the library types a metric by its Go type, and a callback
// is always a Gauge — so a monotonically increasing value read at scrape time
// would be announced as `# TYPE … gauge` while its name ends in `_total`.
// PromQL never consults the metadata, but the humans and the tooling that
// read a /metrics page do, and a series that disagrees with itself is exactly
// the kind of thing this package exists to stop.
func CounterFunc(def Definition, fn func() float64, labelValues ...string) {
	if def.Kind == "" {
		def.Kind = KindCounter
	}

	def = define(def)
	name := render(def.Name, def.Labels, labelValues)

	metrics.RegisterMetricsWriter(func(w io.Writer) {
		metrics.WriteCounterFloat64(w, name, fn())
	})
}

// Info registers a constant `1` series carrying its facts in labels — the
// build-info idiom, which lets a dashboard join a version onto any other
// series.
func Info(def Definition, labelValues ...string) {
	if def.Kind == "" {
		def.Kind = KindGauge
	}

	def = define(def)

	metrics.GetOrCreateGauge(render(def.Name, def.Labels, labelValues), func() float64 { return 1 })
}

// droppedSeries counts label combinations rejected by the per-family cap.
var droppedSeries = newVec(
	Definition{
		Name:   Namespace + "_metrics_series_dropped_total",
		Kind:   KindCounter,
		Help:   "Metric samples that exceeded the per-family series cap and were folded into an __overflow__ series.",
		Labels: []string{"family"},
	},
	metrics.GetOrCreateCounter,
)

// Bucket sets. Sharing them keeps related metrics comparable and keeps
// bucket choices out of the call sites.
var (
	// LatencyBuckets covers request-shaped work: sub-millisecond to a few
	// seconds.
	LatencyBuckets = []float64{
		0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
	}

	// SlowBuckets covers background work — snapshots, restores, sweeps —
	// where the interesting range is seconds to minutes.
	SlowBuckets = []float64{0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 300}

	// SizeBuckets covers payload sizes in bytes, from a tiny message to the
	// 256 KiB the API allows.
	SizeBuckets = []float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304}

	// CountBuckets covers small counts: batch sizes, fan-out widths, peers
	// returned by a discovery provider.
	CountBuckets = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 5000}
)

// ExposeMetadata turns on `# TYPE` lines in the exposition output.
//
// Prometheus does not need them, but everything a human points at a
// `/metrics` endpoint does: without a TYPE line a counter is indistinguishable
// from a gauge, and tooling guesses wrong.
func ExposeMetadata(enabled bool) { metrics.ExposeMetadata(enabled) }
