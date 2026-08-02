package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/queue/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqlite"
)

type sweepResult struct {
	Duration        time.Duration
	MessagesDropped uint64
}

func (s *Storage) gc(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("GC routine recovered from panic",
				slog.Any("panic", r),
			)
		}
	}()

	// In a cluster every node holds the same rows, so a per-node sweeper would
	// have each one independently deciding what to evict. Eviction has to be a
	// replicated decision like any other write, so the cluster leader proposes
	// sweeps through the log and this local routine stands down.
	if s.gcDisabled {
		s.logger.Debug("Local garbage collection is disabled; the cluster leader drives eviction")

		return
	}

	s.logger.Debug("Starting garbage collection routine...")

	timer := time.NewTicker(s.gcTimeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			// If there are no queues, there is no need for GC, obviously.
			if s.observer.Queues() == 0 {
				continue
			}

			s.collect(ctx)
		}
	}
}

// collect runs one full sweep and records how it went.
//
// The failure paths still panic — that is the store's existing contract, and a
// sweep that cannot read the queue list is not something to carry on from —
// but the outcome is recorded first. Reporting only successes would leave
// plainq_storage_gc_runs_total{result="error"} permanently at zero for exactly
// the failures an operator needs to see. A deferred recorder runs while the
// panic unwinds, so the metric is written on the way out either way.
func (s *Storage) collect(ctx context.Context) {
	var (
		start = time.Now()
		cErr  error
	)

	defer func() { s.observer.GC(metrics.GCScopeAll, start, cErr) }()

	queues, queuesErr := s.queuesForGC(ctx)
	if queuesErr != nil {
		cErr = queuesErr

		panic(fmt.Sprintf("get queue IDs for GC: %v", queuesErr))
	}

	for _, queueID := range queues {
		s.logger.Debug("Running garbage collection for queue",
			slog.String("queue_id", queueID),
		)

		result, sweepErr := s.sweep(ctx, queueID)
		if sweepErr != nil {
			cErr = sweepErr

			panic(fmt.Errorf("sweep queue (id: %q): %s", queueID, sweepErr.Error()))
		}

		// A sweep is the one moment the store already knows a queue changed
		// size, so it is where the delta-tracked gauges are corrected against
		// an exact count.
		s.sampleQueue(ctx, queueID)

		s.logger.Debug("Garbage collection",
			slog.String("queue_id", queueID),
			slog.String("duration", result.Duration.String()),
			slog.Uint64("messages_dropped", result.MessagesDropped),
		)
	}
}

func (s *Storage) queuesForGC(ctx context.Context) (_ []string, sErr error) {
	limit := s.observer.Queues()
	offset := uint64(0)
	cutoff := time.Now().Add(-s.gcTimeout)
	queues := make([]string, 0, limit)

	tx, txErr := pqlite.BeginTx(ctx, s.db)
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	q := s.queries.WithTx(tx)

	for {
		batch, err := q.SelectQueuesForGC(ctx, sqlcgen.SelectQueuesForGCParams{
			GcAt:   cutoff,
			Limit:  int64(limit), //nolint:gosec // limit and offset come from a clamped CLI flag.
			Offset: int64(offset),
		})
		if err != nil {
			return nil, fmt.Errorf("query queues: %w", err)
		}

		queues = append(queues, batch...)

		if uint64(len(batch)) != limit {
			break
		}

		offset += limit
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return queues, nil
}

// Sweep evicts the messages of one queue that have exhausted their retries or
// outlived their retention, applying the queue's eviction policy, and reports
// how many it removed.
//
// It is exported because eviction is a write like any other: in a cluster the
// leader proposes it through the consensus log with an explicit cutoff, and
// every replica applies it here.
func (s *Storage) Sweep(ctx context.Context, queueID string) (uint64, error) {
	result, err := s.sweep(ctx, queueID)
	if err != nil {
		return 0, err
	}

	return result.MessagesDropped, nil
}

// recordEviction reports what a sweep removed.
//
// A dead-lettered message is not gone, it moved — counting it only as a drop
// would hide the one queue state that reliably needs a human.
func (s *Storage) recordEviction(queueID string, evictionPolicy uint32, dropped uint64) {
	//nolint:gosec // EvictionPolicy enum is non-negative.
	policy := v1.EvictionPolicy(evictionPolicy)

	s.observer.Dropped(queueID, policy, dropped)

	if policy == v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER {
		s.observer.DeadLettered(queueID, dropped)
	}
}

//nolint:cyclop // One branch per eviction policy plus the transaction's error paths.
func (s *Storage) sweep(ctx context.Context, queueID string) (_ *sweepResult, sErr error) {
	start := time.Now()

	props, ok := s.cache.getByID(queueID)
	if !ok {
		return nil, fmt.Errorf("queue props (id: %q) not cached", queueID)
	}

	// The retention cutoff is derived from the command's instant, so a
	// replicated sweep deletes exactly the same rows on every node.
	//nolint:gosec // the retention period is bounded by validation on the way in.
	retention := time.Duration(props.RetentionPeriodSeconds) * time.Second
	cutoff := sqliteTime(queue.WriteTime(ctx).Add(-retention))

	tx, txErr := pqlite.BeginTx(ctx, s.db)
	if txErr != nil {
		panic(fmt.Errorf("begin transaction: %w", txErr))
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	var messagesDropped uint64

	switch props.EvictionPolicy {
	case uint32(v1.EvictionPolicy_EVICTION_POLICY_DROP):
		dropped, dropErr := dropMessages(ctx, tx, props, cutoff)
		if dropErr != nil {
			return nil, fmt.Errorf("apply drop (drop) policy to a queue (id: %q): %w", queueID, dropErr)
		}

		messagesDropped = dropped

	case uint32(v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER):
		moved, moveErr := moveMessagesToDLQ(ctx, tx, props, cutoff)
		if moveErr != nil {
			return nil, fmt.Errorf("apply drop (dead letter) policy to a queue (id: %q): %w", queueID, moveErr)
		}

		messagesDropped = moved

	default:
		return nil, fmt.Errorf("queue props (id: %q) contains unsuppoted drop policy: %d", queueID, props.EvictionPolicy)
	}

	if err := s.updateQueuePropsAfterGC(ctx, queueID, tx); err != nil {
		return nil, fmt.Errorf("update queue (id: %q) props record: %w", queueID, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.recordEviction(queueID, props.EvictionPolicy, messagesDropped)

	result := sweepResult{
		Duration:        time.Since(start),
		MessagesDropped: messagesDropped,
	}

	return &result, nil
}

func dropMessages(ctx context.Context, tx *sql.Tx, props QueueProps, cutoff string) (uint64, error) {
	r, execErr := tx.ExecContext(ctx, queryDropMessages(props.ID),
		props.MaxReceiveAttempts,
		cutoff,
	)
	if execErr != nil {
		return 0, fmt.Errorf("execute query: %w", execErr)
	}

	rows, rowsErr := r.RowsAffected()
	if rowsErr != nil {
		return 0, fmt.Errorf("get affected rows: %w", rowsErr)
	}

	if rows < 0 {
		return 0, nil
	}

	return uint64(rows), nil
}

// moveMessagesToDLQ copies evicted messages into the queue's dead-letter
// target and removes them from the source, so a message that a consumer could
// never handle survives for inspection instead of vanishing.
func moveMessagesToDLQ(ctx context.Context, tx *sql.Tx, props QueueProps, cutoff string) (uint64, error) {
	if props.DeadLetterQueueID == "" {
		return 0, fmt.Errorf("queue (id: %q) has the dead-letter policy but no dead-letter queue", props.ID)
	}

	// The cursor is drained into memory before any write: SQLite cannot write
	// through an open read cursor on the same connection, which is the same
	// constraint Receive works around.
	evicted, selectErr := selectEvicted(ctx, tx, props, cutoff)
	if selectErr != nil {
		return 0, selectErr
	}

	if len(evicted) == 0 {
		return 0, nil
	}

	stmt, prepareErr := tx.PrepareContext(ctx, queryInsertMessages(props.DeadLetterQueueID))
	if prepareErr != nil {
		return 0, fmt.Errorf("prepare statement: %w", prepareErr)
	}

	defer func() { _ = stmt.Close() }()

	// The dead-letter copy keeps its original enqueue time — how long a
	// message sat before it was given up on is the useful fact — and becomes
	// immediately visible to whoever inspects the dead-letter queue.
	movedAt := sqliteTime(queue.WriteTime(ctx))

	for _, msg := range evicted {
		if _, err := stmt.ExecContext(ctx, msg.id, msg.body, msg.createdAt, movedAt); err != nil {
			return 0, fmt.Errorf("insert message into dead-letter queue: %w", err)
		}
	}

	ids := make([]any, 0, len(evicted))
	for _, msg := range evicted {
		ids = append(ids, msg.id)
	}

	if _, err := tx.ExecContext(ctx, queryDeleteMessagesNoReturning(props.ID, len(ids)), ids...); err != nil {
		return 0, fmt.Errorf("remove dead-lettered messages: %w", err)
	}

	return uint64(len(evicted)), nil
}

// evictedMessage is one row selected for eviction.
type evictedMessage struct {
	id        string
	body      []byte
	createdAt string
}

func selectEvicted(ctx context.Context, tx *sql.Tx, props QueueProps, cutoff string) (_ []evictedMessage, err error) {
	rows, queryErr := tx.QueryContext(ctx, querySelectMoveToDLQ(props.ID), props.MaxReceiveAttempts, cutoff)
	if queryErr != nil {
		return nil, fmt.Errorf("execute query: %w", queryErr)
	}

	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close rows: %w", closeErr)
		}
	}()

	var evicted []evictedMessage

	for rows.Next() {
		var msg evictedMessage

		if scanErr := rows.Scan(&msg.id, &msg.body, &msg.createdAt); scanErr != nil {
			return nil, fmt.Errorf("scan message record: %w", scanErr)
		}

		evicted = append(evicted, msg)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate rows: %w", rowsErr)
	}

	return evicted, nil
}

func (s *Storage) updateQueuePropsAfterGC(ctx context.Context, queueID string, tx *sql.Tx) error {
	// The generated statement stamps gc_at from the node's own clock. Under
	// replication that is one more way for two replicas to disagree, so use
	// the leader's instant instead.
	if queue.Replicated(ctx) {
		result, execErr := tx.ExecContext(ctx, queryStampQueueGCAt(), sqliteTime(queue.WriteTime(ctx)), queueID)
		if execErr != nil {
			return fmt.Errorf("execute query: %w", execErr)
		}

		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("get affected rows: %w", rowsErr)
		}

		if rows == 0 {
			return errors.New("no affected rows")
		}

		return nil
	}

	rows, execErr := s.queries.WithTx(tx).UpdateQueuePropertiesGCAt(ctx, queueID)
	if execErr != nil {
		return fmt.Errorf("execute query: %w", execErr)
	}

	if rows == 0 {
		return errors.New("no affected rows")
	}

	return nil
}
