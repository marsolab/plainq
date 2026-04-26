package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue/pgstore/sqlcgen"
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

	s.logger.Debug("Starting garbage collection routine...")

	timer := time.NewTicker(s.gcTimeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			start := time.Now()

			if s.observer.QueuesExist().Get() == 0 {
				continue
			}

			s.observer.GCSchedules().Inc()

			queues, queuesErr := s.queuesForGC(ctx)
			if queuesErr != nil {
				panic(fmt.Sprintf("get queue IDs for GC: %v", queuesErr))
			}

			for _, queueID := range queues {
				s.logger.Debug("Running garbage collection for queue",
					slog.String("queue_id", queueID),
				)

				result, sweepErr := s.sweep(ctx, queueID)
				if sweepErr != nil {
					panic(fmt.Errorf("sweep queue (id: %q): %s", queueID, sweepErr.Error()))
				}

				s.logger.Debug("Garbage collection",
					slog.String("queue_id", queueID),
					slog.String("duration", result.Duration.String()),
					slog.Uint64("messages_dropped", result.MessagesDropped),
				)
			}

			s.observer.GCDuration().Dur(start)
		}
	}
}

func (s *Storage) queuesForGC(ctx context.Context) (_ []string, sErr error) {
	limit := s.observer.QueuesExist().Get()
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

func (s *Storage) sweep(ctx context.Context, queueID string) (_ *sweepResult, sErr error) {
	start := time.Now()

	props, ok := s.cache.getByID(queueID)
	if !ok {
		return nil, fmt.Errorf("queue props (id: %q) not cached", queueID)
	}

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		panic(fmt.Errorf("begin transaction: %w", txErr))
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

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

	if err := s.updateQueuePropsAfterGC(ctx, queueID, tx); err != nil {
		return nil, fmt.Errorf("update queue (id: %q) props record: %w", queueID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	//nolint:gosec // EvictionPolicy enum is non-negative.
	s.observer.MessageDropped(queueID, v1.EvictionPolicy(props.EvictionPolicy)).Add(messagesDropped)

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
	rows, execErr := tx.Query(ctx, querySelectMoveToDLQ(props.ID),
		int32(props.MaxReceiveAttempts),     //nolint:gosec // max receive attempts is bounded by validation.
		int32(props.RetentionPeriodSeconds), //nolint:gosec // retention seconds is bounded by validation.
	)
	if execErr != nil {
		return 0, fmt.Errorf("execute query: %w", execErr)
	}

	type msg struct {
		ID   string
		Body []byte
	}

	var msgs []msg

	for rows.Next() {
		var m msg

		if err := rows.Scan(&m.ID, &m.Body); err != nil {
			rows.Close()

			return 0, fmt.Errorf("scan message record: %w", err)
		}

		msgs = append(msgs, m)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate rows: %w", err)
	}

	insertSQL := queryInsertMessages(props.DeadLetterQueueID)

	for _, m := range msgs {
		if _, err := tx.Exec(ctx, insertSQL, m.ID, m.Body); err != nil {
			return 0, fmt.Errorf("insert into DLQ: %w", err)
		}
	}

	return uint64(len(msgs)), nil
}

func (s *Storage) updateQueuePropsAfterGC(ctx context.Context, queueID string, tx pgx.Tx) error {
	rows, err := s.queries.WithTx(tx).UpdateQueuePropertiesGCAt(ctx, queueID)
	if err != nil {
		return fmt.Errorf("execute query: %w", err)
	}

	if rows == 0 {
		return errors.New("no affected rows")
	}

	return nil
}
