package metrics

import "time"

// Storage backend names, used as the `backend` label everywhere an operation
// is attributed to the store that ran it.
const (
	BackendSQLite   = "sqlite"
	BackendPostgres = "postgres"
	BackendCluster  = "cluster"
)

// Connection-pool states, as reported by the driver.
const (
	connStateOpen   = "open"
	connStateInUse  = "in_use"
	connStateIdle   = "idle"
	labelConnState  = "state"
	labelGCQueueSet = "scope"
)

// Storage and garbage-collection metrics.
var (
	gcRuns = NewCounterVec(Definition{
		Name:   Namespace + "_storage_gc_runs_total",
		Help:   "Retention sweeps started, by outcome.",
		Labels: []string{labelBackend, labelResult},
	})

	gcDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_storage_gc_duration_seconds",
		Help:   "How long a full retention sweep took. Approaching the sweep interval means the sweeper is falling behind.",
		Labels: []string{labelBackend, labelGCQueueSet},
	}, SlowBuckets)

	storageErrors = NewCounterVec(Definition{
		Name:   Namespace + "_storage_errors_total",
		Help:   "Storage-layer failures that were not attributable to a single API operation.",
		Labels: []string{labelBackend, labelOperation},
	})

	dbConnectionsDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_storage_db_connections",
		Help:   "Database connections by state. Saturating `in_use` is what a queue stalling on the write lock looks like.",
		Labels: []string{labelBackend, labelConnState},
	})

	dbWaitCountDef = define(Definition{
		Kind:   KindCounter,
		Name:   Namespace + "_storage_db_waits_total",
		Help:   "Connection acquisitions that had to wait for a free connection.",
		Labels: []string{labelBackend},
	})

	dbWaitSecondsDef = define(Definition{
		Kind:   KindCounter,
		Name:   Namespace + "_storage_db_wait_seconds_total",
		Help:   "Cumulative time spent waiting for a database connection.",
		Labels: []string{labelBackend},
	})
)

// GC sweep scopes. A sweep either walked every queue on its schedule or was
// asked to sweep exactly one.
const (
	GCScopeAll   = "all"
	GCScopeQueue = "queue"
)

// RecordGC records a retention sweep.
func RecordGC(backend, scope string, start time.Time, err error) {
	gcRuns.With(backend, resultOf(err)).Inc()
	gcDuration.ObserveSince(start, backend, scope)
}

// RecordStorageError records a storage failure that no single API operation
// owns — a background sweep blowing up, a cache refill failing.
func RecordStorageError(backend, operation string) {
	storageErrors.With(backend, operation).Inc()
}

// PoolStats is the subset of a driver's pool statistics worth exposing. Both
// database/sql and pgxpool report all of it, under different names.
type PoolStats struct {
	// Open is the total number of established connections.
	Open int64

	// InUse is how many of them are currently checked out.
	InUse int64

	// Idle is how many are sitting free in the pool.
	Idle int64

	// WaitCount is the cumulative number of acquisitions that had to wait.
	WaitCount int64

	// WaitDuration is the cumulative time spent waiting.
	WaitDuration time.Duration
}

// RegisterPoolCollector publishes a connection pool's statistics.
//
// Each series reads through to the driver at scrape time rather than being
// pushed by a timer, so the numbers describe the pool at the instant
// Prometheus asked. That matters most for the one anyone cares about:
// connections in use, whose interesting value is the momentary spike a
// five-second sampler would miss.
func RegisterPoolCollector(backend string, stats func() PoolStats) {
	GaugeFunc(dbConnectionsDef, func() float64 { return float64(stats().Open) }, backend, connStateOpen)
	GaugeFunc(dbConnectionsDef, func() float64 { return float64(stats().InUse) }, backend, connStateInUse)
	GaugeFunc(dbConnectionsDef, func() float64 { return float64(stats().Idle) }, backend, connStateIdle)
	CounterFunc(dbWaitCountDef, func() float64 { return float64(stats().WaitCount) }, backend)
	CounterFunc(dbWaitSecondsDef, func() float64 { return stats().WaitDuration.Seconds() }, backend)
}
