package litestore

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
)

// statsSampleTimeout bounds one queue's stats query, so a sampler can never
// hold a connection long enough to matter to a writer.
const statsSampleTimeout = 5 * time.Second

// queueStats is a queue's exact contents at one instant.
type queueStats struct {
	// depth is how many messages the queue holds.
	depth int64

	// inFlight is how many of them are claimed and not yet visible again.
	inFlight int64
}

// queueStats counts a queue's rows.
//
// Both numbers come from one pass. Counting rows is the only way to be right
// about either: the delta tracking on the write path starts from zero on a
// process that restarts onto a database full of messages, and nothing emits an
// event when a visibility timeout lapses and a claimed message quietly becomes
// available again.
func (s *Storage) queueStats(ctx context.Context, queueID string) (queueStats, error) {
	var stats queueStats

	if !validQueueID(queueID) {
		return stats, fmt.Errorf("invalid queue id %q", queueID)
	}

	row := s.db.QueryRowContext(ctx, queryQueueStats(queueID), sqliteTime(time.Now().UTC()))

	if err := row.Scan(&stats.depth, &stats.inFlight); err != nil {
		return stats, fmt.Errorf("count queue %q: %w", queueID, err)
	}

	return stats, nil
}

// sampleQueue publishes one queue's exact depth and in-flight count.
//
// A failure is logged and dropped rather than returned: the caller is a
// retention sweep or a start-up pass, and neither should fail because a gauge
// could not be corrected.
func (s *Storage) sampleQueue(ctx context.Context, queueID string) {
	ctx, cancel := context.WithTimeout(ctx, statsSampleTimeout)
	defer cancel()

	stats, err := s.queueStats(ctx, queueID)
	if err != nil {
		s.observer.StorageError(metrics.OpSample)

		s.logger.Debug("Failed to sample queue statistics",
			slog.String("queue_id", queueID),
			slog.String("error", err.Error()),
		)

		return
	}

	s.observer.QueueStats(queueID, stats.depth, stats.inFlight)
}

// sampleAllQueues corrects every queue's gauges once.
//
// It runs in the background at start-up rather than inline, because a server
// holding a thousand queues should not wait on a thousand counts before it
// accepts its first request — and the gauges being briefly absent is a much
// smaller problem than the server being briefly down.
func (s *Storage) sampleAllQueues(ctx context.Context) {
	for _, queueID := range s.cache.ids() {
		select {
		case <-ctx.Done():
			return

		default:
		}

		s.sampleQueue(ctx, queueID)
	}
}
