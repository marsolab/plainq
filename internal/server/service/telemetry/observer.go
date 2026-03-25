package telemetry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/VictoriaMetrics/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// observedMetrics represents a set of observed metrics.
var observedMetrics = map[string]struct{}{
	"queues_exist":              {}, // gauge.
	"message_in_queue_duration": {}, // histogram.
	"messages_sent_total":       {}, // counter.
	"messages_sent_bytes_total": {}, // counter.
	"messages_received_total":   {}, // counter.
	"messages_deleted_total":    {}, // counter.
	"messages_dropped_total":    {}, // counter.
	"empty_receives_total":      {}, // counter.
	"gc_schedules_total":        {}, // counter.
	"gc_duration":               {}, // histogram.
}

// Observable checks if a given metric is being observed.
func Observable(_ context.Context, metric string) (bool, error) {
	_, ok := observedMetrics[metric]
	return ok, nil
}

// ObservableCount returns the number of observed metrics as an uint32 value.
func ObservableCount() uint32 { return uint32(len(observedMetrics)) }

// Observer interface abstracts the logic of observing events and
// measuring metrics of those events.
type Observer interface {
	// Observable tels whether the metric is observed by collector.
	// Method is case-insensitive and will lowercase metric name.
	Observable(ctx context.Context, metric string) (bool, error)

	// MessagesSent returns a Counter to measure
	// the amount of messages that have been sent.
	MessagesSent(queueID string) Counter

	// MessagesSentBytes returns a Counter to measure
	// the size of messages body that have been sent.
	MessagesSentBytes(queueID string) Counter

	// MessagesReceived returns a Counter to measure
	// the amount of messages that have been received.
	MessagesReceived(queueID string) Counter

	// MessagesDeleted returns a Counter to measure
	// the amount of messages that have been deleted.
	MessagesDeleted(queueID string) Counter

	// MessageDropped returns a Counter to measure
	// the amount of messages that have been dropped.
	MessageDropped(queueID string, policy v1.EvictionPolicy) Counter

	// EmptyReceives returns a Counter to measure
	// the amount of empty receives.
	EmptyReceives(queueID string) Counter

	// TimeInQueue returns a Histogram to measure the amount
	// of time each message stay in a queue.
	TimeInQueue(queueID string) Histogram

	// GCSchedules
	GCSchedules() Counter

	// GCDuration
	GCDuration() Histogram

	// QueuesExist returns a Gauge to measure the amount of
	// queues that exist now.
	QueuesExist() Gauge
}

// Histogram interface represents a type that can be used to collect and analyze duration data.
type Histogram interface {
	// Dur track the duration since given time.
	Dur(since time.Time)
}

// Counter represents a simple counter.
type Counter interface {
	// Inc increments the underlying value.
	Inc()

	// Add adds n to the underlying value.
	Add(n uint64)

	// Get returns the underlying value.
	Get() uint64
}

// Gauge wraps Counter with decrementing logic.
type Gauge interface {
	Counter

	// Dec decrements the underlying value.
	Dec()

	// Sub decrements n from the underlying value.
	Sub(n uint64)
}

// MetricsObserver implements the Observer interface.
type MetricsObserver struct{ observers obsPool[observe] }

func (o *MetricsObserver) Observable(ctx context.Context, metric string) (bool, error) {
	return Observable(ctx, metric)
}

// NewObserver returns a pointer to a new instance of MetricsObserver.
func NewObserver() *MetricsObserver {
	o := MetricsObserver{observers: obsPool[observe]{
		pool: sync.Pool{New: func() any { return &observe{} }},
	}}

	return &o
}

func (o *MetricsObserver) MessagesReceived(queueID string) Counter {
	vmCounter := metrics.GetOrCreateCounter(
		`messages_received_total{queue="` + queueID + `"}`,
	)

	obs := o.observers.get()
	obs.inc = func() { vmCounter.Inc() }
	obs.get = func() uint64 { return vmCounter.Get() }
	obs.add = func(n uint64) { vmCounter.Add(int(n)) }

	return obs
}

func (o *MetricsObserver) MessagesDeleted(queueID string) Counter {
	vmCounter := metrics.GetOrCreateCounter(
		`messages_deleted_total{queue="` + queueID + `"}`,
	)

	obs := o.observers.get()
	obs.inc = func() { vmCounter.Inc() }
	obs.get = func() uint64 { return vmCounter.Get() }
	obs.add = func(n uint64) { vmCounter.Add(int(n)) }

	return obs
}

func (o *MetricsObserver) MessageDropped(queueID string, policy v1.EvictionPolicy) Counter {
	vmCounter := metrics.GetOrCreateCounter(
		`messages_dropped_total{queue="` + queueID + `", policy="` + policy.String() + `"}`,
	)

	obs := o.observers.get()
	obs.inc = func() { vmCounter.Inc() }
	obs.get = func() uint64 { return vmCounter.Get() }
	obs.add = func(n uint64) { vmCounter.Add(int(n)) }

	return obs
}

func (o *MetricsObserver) EmptyReceives(queueID string) Counter {
	vmCounter := metrics.GetOrCreateCounter(
		`messages_sent_total{queue="` + queueID + `"}`,
	)

	obs := o.observers.get()
	obs.inc = func() { vmCounter.Inc() }
	obs.get = func() uint64 { return vmCounter.Get() }
	obs.add = func(n uint64) { vmCounter.Add(int(n)) }

	return obs
}

func (o *MetricsObserver) MessagesSent(queueID string) Counter {
	vmCounter := metrics.GetOrCreateCounter(
		`messages_sent_total{queue="` + queueID + `"}`,
	)

	obs := o.observers.get()
	obs.inc = func() { vmCounter.Inc() }
	obs.get = func() uint64 { return vmCounter.Get() }
	obs.add = func(n uint64) { vmCounter.Add(int(n)) }

	return obs
}

func (o *MetricsObserver) MessagesSentBytes(queueID string) Counter {
	vmCounter := metrics.GetOrCreateCounter(
		`messages_sent_bytes_total{queue="` + queueID + `"}`,
	)

	obs := o.observers.get()
	obs.inc = func() { vmCounter.Inc() }
	obs.get = func() uint64 { return vmCounter.Get() }
	obs.add = func(n uint64) { vmCounter.Add(int(n)) }

	return obs
}

func (o *MetricsObserver) TimeInQueue(queueID string) Histogram {
	vmHis := metrics.GetOrCreateHistogram(
		`message_in_queue_duration{queue="` + queueID + `"}`,
	)

	obs := o.observers.get()
	obs.dur = func(t time.Time) { vmHis.UpdateDuration(t) }
	obs.upd = func(n float64) { vmHis.Update(n) }

	return obs
}

func (o *MetricsObserver) QueuesExist() Gauge {
	vmGauge := metrics.GetOrCreateCounter(`queues_exist`)

	obs := o.observers.get()
	obs.inc = func() { vmGauge.Inc() }
	obs.dec = func() { vmGauge.Dec() }
	obs.get = func() uint64 { return vmGauge.Get() }
	obs.add = func(n uint64) { vmGauge.Add(int(n)) }
	obs.sub = func(n uint64) { vmGauge.Add(-int(n)) }

	return obs
}

func (o *MetricsObserver) GCSchedules() Counter {
	vmCounter := metrics.GetOrCreateCounter(`gc_schedules_total`)

	obs := o.observers.get()
	obs.inc = func() { vmCounter.Inc() }
	obs.get = func() uint64 { return vmCounter.Get() }
	obs.add = func(n uint64) { vmCounter.Add(int(n)) }

	return obs
}

func (o *MetricsObserver) GCDuration() Histogram {
	vmHis := metrics.GetOrCreateHistogram(`gc_duration`)

	obs := o.observers.get()
	obs.dur = func(t time.Time) { vmHis.UpdateDuration(t) }
	obs.upd = func(n float64) { vmHis.Update(n) }

	return obs
}

// observe implements Counter and Gauge interfaces
// using the VictoriaMetrics metric library.
type observe struct {
	inc func()
	dec func()
	get func() uint64
	add func(n uint64)
	sub func(n uint64)
	dur func(t time.Time)
	upd func(n float64)
}

func (c *observe) Dec()                { c.dec() }
func (c *observe) Inc()                { c.inc() }
func (c *observe) Add(n uint64)        { c.add(n) }
func (c *observe) Sub(n uint64)        { c.sub(n) }
func (c *observe) Get() uint64         { return c.get() }
func (c *observe) Dur(since time.Time) { c.dur(since) }
func (c *observe) Upd(n float64)       { c.upd(n) }

type obsPool[T observe] struct{ pool sync.Pool }

func (p *obsPool[T]) put(v *T) { p.pool.Put(v) }
func (p *obsPool[T]) get() *T {
	v, ok := p.pool.Get().(*T)
	if !ok {
		panic(fmt.Errorf("failed to cast %v to T", v))
	}

	return v
}
