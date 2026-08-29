package litestore

import (
	"context"
	"database/sql"
	"fmt"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

const (
	topicDeleteLowerBoundQuery = `SELECT COUNT(*),
			COALESCE(SUM(
				length(CAST(s.subscription_id AS BLOB)) +
				length(CAST(s.topic_id AS BLOB)) +
				length(CAST(s.queue_id AS BLOB)) +
				length(CAST(COALESCE(q.queue_name, '') AS BLOB))
			), 0),
			COALESCE(SUM(CASE WHEN COALESCE(q.queue_name, '') <> '' THEN 1 ELSE 0 END), 0)
		FROM topic_subscriptions s
		LEFT JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.topic_id = ?;`

	queueDeleteLowerBoundQuery = `SELECT COUNT(*),
			COALESCE(SUM(
				length(CAST(s.subscription_id AS BLOB)) +
				length(CAST(s.topic_id AS BLOB)) +
				length(CAST(s.queue_id AS BLOB)) +
				length(CAST(COALESCE(q.queue_name, '') AS BLOB))
			), 0),
		COALESCE(SUM(CASE WHEN COALESCE(q.queue_name, '') <> '' THEN 1 ELSE 0 END), 0)
		FROM topic_subscriptions s
		LEFT JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.queue_id = ?;`

	// Sizing is order-independent. Omitting ORDER BY lets SQLite stream rows
	// instead of materializing a temporary sort before an early capacity stop.
	topicDeleteRowsQuery = `SELECT s.subscription_id, s.topic_id, s.queue_id, COALESCE(q.queue_name, ''), s.created_at
		FROM topic_subscriptions s
		LEFT JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.topic_id = ?;`

	queueDeleteRowsQuery = `SELECT s.subscription_id, s.topic_id, s.queue_id, COALESCE(q.queue_name, ''), s.created_at
		FROM topic_subscriptions s
		LEFT JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.queue_id = ?;`
)

// PreflightDeleteTopic validates a leader-side clustered delete and computes
// its exact canonical response size from one read snapshot without building
// the response or changing replicated storage.
func (s *Storage) PreflightDeleteTopic(ctx context.Context, topicID string, limit int) (pErr error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin topic delete preflight: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}
	defer func() {
		pErr = joinSQLiteRollback(pErr, tx, pubSubDeleteTopic, "preflight topic delete")
	}()

	topicExists, err := exists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM topic_properties WHERE topic_id = ?);`, topicID)
	if err != nil {
		return fmt.Errorf("check topic delete preflight: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	if !topicExists {
		return fmt.Errorf("preflight topic delete: %w", pqerr.ErrNotFound)
	}

	if err := preflightDeleteSubscriptions(
		ctx,
		tx,
		topicDeleteLowerBoundQuery,
		topicDeleteRowsQuery,
		topicID,
		limit,
		pubSubDeleteTopic,
	); err != nil {
		return fmt.Errorf("preflight topic delete subscriptions: %w", err)
	}

	return nil
}

// PreflightDeleteQueue validates Force before sizing so a non-empty queue is
// rejected for its business precondition even when its effects are oversized.
func (s *Storage) PreflightDeleteQueue(
	ctx context.Context,
	input *v1.DeleteQueueRequest,
	limit int,
) (pErr error) {
	if input == nil {
		return fmt.Errorf("preflight queue delete: %w", pqerr.ErrInvalidInput)
	}

	queueID := input.GetQueueId()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin queue delete preflight: %w", normalizePubSubError(err, pubSubDeleteQueue))
	}
	defer func() {
		pErr = joinSQLiteRollback(pErr, tx, pubSubDeleteQueue, "preflight queue delete")
	}()

	queueExists, err := exists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM queue_properties WHERE queue_id = ?);`, queueID)
	if err != nil {
		return fmt.Errorf("check queue delete preflight: %w", normalizePubSubError(err, pubSubDeleteQueue))
	}

	if !queueExists {
		return fmt.Errorf("preflight queue delete: %w", pqerr.ErrNotFound)
	}

	var messageCount int64
	if err := tx.QueryRowContext(ctx, queryCountMessages(queueID)).Scan(&messageCount); err != nil {
		return fmt.Errorf("count queue %q messages before preflight: %w", queueID, normalizePubSubError(err, pubSubDeleteQueue))
	}

	if messageCount > 0 && !input.GetForce() {
		return fmt.Errorf("delete non-empty queue %q: %w", queueID, pqerr.ErrFailedPrecondition)
	}

	if err := preflightDeleteSubscriptions(
		ctx,
		tx,
		queueDeleteLowerBoundQuery,
		queueDeleteRowsQuery,
		queueID,
		limit,
		pubSubDeleteQueue,
	); err != nil {
		return fmt.Errorf("preflight queue delete subscriptions: %w", err)
	}

	return nil
}

func preflightDeleteSubscriptions(
	ctx context.Context,
	tx *sql.Tx,
	lowerBoundQuery string,
	rowsQuery string,
	id string,
	limit int,
	operation pubSubErrorContext,
) error {
	var subscriptionCount, rawStringBytes, nonEmptyQueueNames int64
	if err := tx.QueryRowContext(ctx, lowerBoundQuery, id).Scan(
		&subscriptionCount,
		&rawStringBytes,
		&nonEmptyQueueNames,
	); err != nil {
		return fmt.Errorf("read subscription size lower bound: %w", normalizePubSubError(err, operation))
	}

	payloadLowerBound := deleteresult.MinimumPayloadBytes(subscriptionCount, rawStringBytes, nonEmptyQueueNames)
	if err := deleteresult.CheckPayloadLimit(payloadLowerBound, limit, false); err != nil {
		return fmt.Errorf("check subscription payload lower bound: %w", err)
	}

	rows, err := tx.QueryContext(ctx, rowsQuery, id)
	if err != nil {
		return fmt.Errorf("stream subscriptions for exact size: %w", normalizePubSubError(err, operation))
	}
	defer rows.Close()

	sizer := deleteresult.NewSizer()

	var rowsSeen int64

	for rows.Next() {
		if err := addSubscriptionSize(rows, sizer, operation); err != nil {
			return err
		}

		rowsSeen++
		if err := sizer.CheckLimit(limit, rowsSeen == subscriptionCount); err != nil {
			return fmt.Errorf("check streamed subscription payload: %w", err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate subscriptions for exact size: %w", normalizePubSubError(err, operation))
	}

	if rowsSeen != subscriptionCount {
		return fmt.Errorf("subscription count changed during preflight: counted %d, streamed %d", subscriptionCount, rowsSeen)
	}

	if err := sizer.CheckLimit(limit, true); err != nil {
		return fmt.Errorf("check final subscription payload: %w", err)
	}

	return nil
}

func addSubscriptionSize(rows *sql.Rows, sizer *deleteresult.Sizer, operation pubSubErrorContext) error {
	var subscription queue.Subscription

	if err := rows.Scan(
		&subscription.SubscriptionID,
		&subscription.TopicID,
		&subscription.QueueID,
		&subscription.QueueName,
		&subscription.CreatedAt,
	); err != nil {
		return fmt.Errorf("scan subscription for exact size: %w", normalizePubSubError(err, operation))
	}

	if err := sizer.AddSubscription(
		subscription.SubscriptionID,
		subscription.TopicID,
		subscription.QueueID,
		subscription.QueueName,
		subscription.CreatedAt,
	); err != nil {
		return fmt.Errorf("size subscription timestamp: %w", err)
	}

	return nil
}
