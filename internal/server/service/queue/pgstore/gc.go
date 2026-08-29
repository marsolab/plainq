package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/marsolab/plainq/internal/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

type sweepResult struct {
	Duration        time.Duration
	MessagesDropped uint64
}

func (s *Storage) gc(ctx context.Context) {
	s.logger.Debug("Starting garbage collection routine...")

	timer := time.NewTicker(s.gcTimeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error("GC iteration recovered from panic", slog.Any("panic", r))
					}
				}()

				if s.observer.Queues() == 0 {
					return
				}

				if err := s.collect(ctx); err != nil {
					s.logger.Error("GC collection failed", slog.Any("error", err))
				}
			}()
		}
	}
}

// collect runs one full sweep and records how it went. A queue may disappear
// after queuesForGC takes its snapshot, and one failed queue must not stop the
// background routine from maintaining the remaining queues or trying again.
func (s *Storage) collect(ctx context.Context) error {
	var (
		start = time.Now()
		cErr  error
	)

	defer func() { s.observer.GC(metrics.GCScopeAll, start, cErr) }()

	queues, queuesErr := s.queuesForGC(ctx)
	if queuesErr != nil {
		cErr = queuesErr
		s.logger.Error("Get queue IDs for garbage collection",
			slog.Any("error", queuesErr),
		)

		return fmt.Errorf("get queue IDs for GC: %w", queuesErr)
	}

	cErr = runSweepBatch(ctx, queues, func(ctx context.Context, queueID string) error {
		s.logger.Debug("Running garbage collection for queue",
			slog.String("queue_id", queueID),
		)

		result, sweepErr := s.sweep(ctx, queueID)
		if sweepErr != nil {
			return fmt.Errorf("sweep queue (id: %q): %w", queueID, sweepErr)
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

		return nil
	}, s.logger)

	return cErr
}

func runSweepBatch(ctx context.Context, queueIDs []string, sweep func(context.Context, string) error, logger *slog.Logger) error {
	errs := make([]error, 0)

	for _, queueID := range queueIDs {
		if err := sweep(ctx, queueID); err != nil {
			logger.Error("queue sweep failed", slog.String("queue_id", queueID), slog.Any("error", err))
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (s *Storage) queuesForGC(ctx context.Context) (_ []string, sErr error) {
	limit := s.observer.Queues()
	offset := uint64(0)
	cutoff := time.Now().Add(-s.gcTimeout)
	queues := make([]string, 0, limit)

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	q := s.queries.WithTx(tx)

	for {
		batch, err := q.SelectQueuesForGC(ctx, sqlcgen.SelectQueuesForGCParams{
			GcAt:   toTimestamptz(cutoff),
			Limit:  int32(limit), //nolint:gosec // limit is clamped by configuration.
			Offset: int32(offset),
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

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return queues, nil
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

func (s *Storage) sweep(ctx context.Context, queueID string) (_ *sweepResult, sErr error) {
	start := time.Now()

	props, ok := s.cache.getByID(queueID)
	if !ok {
		return nil, fmt.Errorf("queue props (id: %q) not cached: %w", queueID, pqerr.ErrNotFound)
	}

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf("begin transaction: %w", txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	// DeleteQueue takes this same parent row before it requests ACCESS
	// EXCLUSIVE on the queue table. Updating gc_at first gives every sweep the
	// same parent-first order; rollback restores the timestamp on any policy
	// failure.
	if err := s.updateQueuePropsAfterGC(ctx, queueID, tx); err != nil {
		return nil, fmt.Errorf("lock queue (id: %q) props for GC: %w", queueID, err)
	}

	var messagesDropped uint64

	switch props.EvictionPolicy {
	case uint32(v1.EvictionPolicy_EVICTION_POLICY_DROP):
		dropped, dropErr := dropMessages(ctx, tx, props)
		if dropErr != nil {
			return nil, fmt.Errorf("apply drop (drop) policy to a queue (id: %q): %w", queueID, dropErr)
		}

		messagesDropped = dropped

	case uint32(v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER):
		moved, moveErr := moveMessagesToDLQ(ctx, tx, props)
		if moveErr != nil {
			return nil, fmt.Errorf("apply drop (dead letter) policy to a queue (id: %q): %w", queueID, moveErr)
		}

		messagesDropped = moved

	default:
		return nil, fmt.Errorf("queue props (id: %q) contains unsupported drop policy: %d", queueID, props.EvictionPolicy)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.recordEviction(queueID, props.EvictionPolicy, messagesDropped)

	return &sweepResult{
		Duration:        time.Since(start),
		MessagesDropped: messagesDropped,
	}, nil
}

func dropMessages(ctx context.Context, tx pgx.Tx, props QueueProps) (uint64, error) {
	tag, err := tx.Exec(ctx, queryDropMessages(props.ID),
		int32(props.MaxReceiveAttempts),     //nolint:gosec // max receive attempts is bounded by validation.
		int32(props.RetentionPeriodSeconds), //nolint:gosec // retention seconds is bounded by validation.
	)
	if err != nil {
		return 0, fmt.Errorf("execute query: %w", err)
	}

	rows := tag.RowsAffected()
	if rows < 0 {
		return 0, nil
	}

	return uint64(rows), nil
}

func moveMessagesToDLQ(ctx context.Context, tx pgx.Tx, props QueueProps) (uint64, error) {
	if props.DeadLetterQueueID == "" {
		return 0, fmt.Errorf("queue (id: %q) has the dead-letter policy but no dead-letter queue", props.ID)
	}

	rows, execErr := tx.Query(ctx, querySelectMoveToDLQ(props.ID),
		int32(props.MaxReceiveAttempts),     //nolint:gosec // max receive attempts is bounded by validation.
		int32(props.RetentionPeriodSeconds), //nolint:gosec // retention seconds is bounded by validation.
	)
	if execErr != nil {
		return 0, fmt.Errorf("execute query: %w", execErr)
	}

	msgs, err := scanDeadLetterMessages(rows)
	if err != nil {
		return 0, err
	}

	if len(msgs) == 0 {
		return 0, nil
	}

	insertSQL := queryInsertDeadLetterMessage(props.DeadLetterQueueID)
	ids := make([]string, 0, len(msgs))

	for _, m := range msgs {
		if _, err := tx.Exec(ctx, insertSQL, m.ID, m.Body, m.CreatedAt); err != nil {
			return 0, fmt.Errorf("insert into DLQ: %w", err)
		}

		ids = append(ids, m.ID)
	}

	tag, err := tx.Exec(ctx, queryDeleteMessagesNoReturning(props.ID), ids)
	if err != nil {
		return 0, fmt.Errorf("remove dead-lettered messages: %w", err)
	}

	if tag.RowsAffected() != int64(len(ids)) {
		return 0, fmt.Errorf("remove dead-lettered messages: deleted %d rows, want %d", tag.RowsAffected(), len(ids))
	}

	return uint64(len(msgs)), nil
}

type deadLetterMessage struct {
	ID        string
	Body      []byte
	CreatedAt time.Time
}

func scanDeadLetterMessages(rows pgx.Rows) ([]deadLetterMessage, error) {
	var messages []deadLetterMessage

	for rows.Next() {
		var message deadLetterMessage

		if err := rows.Scan(&message.ID, &message.Body, &message.CreatedAt); err != nil {
			rows.Close()

			return nil, fmt.Errorf("scan message record: %w", err)
		}

		messages = append(messages, message)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return messages, nil
}

func (s *Storage) updateQueuePropsAfterGC(ctx context.Context, queueID string, tx pgx.Tx) error {
	rows, err := s.queries.WithTx(tx).UpdateQueuePropertiesGCAt(ctx, queueID)
	if err != nil {
		return fmt.Errorf("execute query: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("queue (id: %q): %w", queueID, pqerr.ErrNotFound)
	}

	return nil
}
