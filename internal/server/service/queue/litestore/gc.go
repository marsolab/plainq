package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue/litestore/sqlcgen"
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

			// If there are no queues, there is no need for GC, obviously.
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

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
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

//nolint:cyclop // Complex message eviction logic with multiple policy checks.
func (s *Storage) sweep(ctx context.Context, queueID string) (_ *sweepResult, sErr error) {
	start := time.Now()

	props, ok := s.cache.getByID(queueID)
	if !ok {
		return nil, fmt.Errorf("queue props (id: %q) not cached", queueID)
	}

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
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
		return nil, fmt.Errorf("queue props (id: %q) contains unsuppoted drop policy: %d", queueID, props.EvictionPolicy)
	}

	if err := s.updateQueuePropsAfterGC(ctx, queueID, tx); err != nil {
		return nil, fmt.Errorf("update queue (id: %q) props record: %w", queueID, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	//nolint:gosec // EvictionPolicy enum is non-negative.
	s.observer.MessageDropped(queueID, v1.EvictionPolicy(props.EvictionPolicy)).
		Add(messagesDropped)

	result := sweepResult{
		Duration:        time.Since(start),
		MessagesDropped: messagesDropped,
	}

	return &result, nil
}

func dropMessages(ctx context.Context, tx *sql.Tx, props QueueProps) (uint64, error) {
	r, execErr := tx.ExecContext(ctx, queryDropMessages(props.ID),
		props.MaxReceiveAttempts,
		props.RetentionPeriodSeconds,
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

func moveMessagesToDLQ(ctx context.Context, tx *sql.Tx, props QueueProps) (uint64, error) {
	rows, execErr := tx.QueryContext(ctx, querySelectMoveToDLQ(props.ID),
		props.MaxReceiveAttempts,
		props.RetentionPeriodSeconds,
	)
	if execErr != nil {
		return 0, fmt.Errorf("execute query: %w", execErr)
	}

	defer func() { _ = rows.Close() }()

	stmt, prepareErr := tx.PrepareContext(ctx, queryInsertMessages(props.DeadLetterQueueID))
	if prepareErr != nil {
		return 0, fmt.Errorf("prepare statement: %w", prepareErr)
	}

	defer func() { _ = stmt.Close() }()

	var moved uint64

	for rows.Next() {
		var (
			msgID   string
			msgBody []byte
		)

		if err := rows.Scan(&msgID, &msgBody); err != nil {
			return 0, fmt.Errorf("scan message record: %w", err)
		}

		if _, err := stmt.ExecContext(ctx, msgID, msgBody); err != nil {
			return 0, fmt.Errorf("update message record: %w", err)
		}

		moved++
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate rows: %w", err)
	}

	return moved, nil
}

func (s *Storage) updateQueuePropsAfterGC(ctx context.Context, queueID string, tx *sql.Tx) error {
	rows, execErr := s.queries.WithTx(tx).UpdateQueuePropertiesGCAt(ctx, queueID)
	if execErr != nil {
		return fmt.Errorf("execute query: %w", execErr)
	}

	if rows == 0 {
		return errors.New("no affected rows")
	}

	return nil
}
