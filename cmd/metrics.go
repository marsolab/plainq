package main

import (
	"runtime"

	"github.com/marsolab/plainq/internal/metrics"
)

// registerRuntimeMetrics publishes the facts about this process that nothing
// else owns: what it was built from, how long it has been up, and how its
// database connection pool is doing.
//
// Metadata exposition is switched on here too. Prometheus does not need the
// `# TYPE` lines, but everyone who has ever pointed a browser at a /metrics
// endpoint does — without them a counter is indistinguishable from a gauge,
// and tooling guesses wrong.
func registerRuntimeMetrics(backend *storageBackend) {
	metrics.ExposeMetadata(true)
	metrics.RegisterBuildInfo(Branch, Commit, runtime.Version())

	registerPoolMetrics(backend)
}

// registerPoolMetrics exposes the storage driver's connection-pool counters.
//
// For SQLite this is the most direct read available on the thing that
// actually limits a queue server: writes serialize on one connection, so
// `in_use` sitting at the pool ceiling is what "the queue is slow" looks like
// from the inside.
func registerPoolMetrics(backend *storageBackend) {
	switch {
	case backend.sqlite != nil:
		metrics.RegisterPoolCollector(metrics.BackendSQLite, func() metrics.PoolStats {
			stats := backend.sqlite.Stats()

			return metrics.PoolStats{
				Open:         int64(stats.OpenConnections),
				InUse:        int64(stats.InUse),
				Idle:         int64(stats.Idle),
				WaitCount:    stats.WaitCount,
				WaitDuration: stats.WaitDuration,
			}
		})

	case backend.pgpool != nil:
		metrics.RegisterPoolCollector(metrics.BackendPostgres, func() metrics.PoolStats {
			stats := backend.pgpool.Stat()

			return metrics.PoolStats{
				Open:         int64(stats.TotalConns()),
				InUse:        int64(stats.AcquiredConns()),
				Idle:         int64(stats.IdleConns()),
				WaitCount:    stats.EmptyAcquireCount(),
				WaitDuration: stats.AcquireDuration(),
			}
		})
	}
}
