package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/idkit"
)

const (
	topicInventoryQuery = `SELECT t.topic_id, COUNT(s.subscription_id)
		FROM topic_properties t
		LEFT JOIN topic_subscriptions s ON s.topic_id = t.topic_id
		WHERE t.tenant_id = ?
		  AND (? = FALSE OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')))
		GROUP BY t.topic_id
		ORDER BY t.topic_id;`
	listTopicSubscriptionsQuery = `SELECT s.subscription_id, s.topic_id, s.queue_id,
		COALESCE(q.queue_name, ''), s.created_at
		FROM topic_subscriptions s
		JOIN topic_properties t ON t.topic_id = s.topic_id
		JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.topic_id = ?
		  AND t.tenant_id = ?
		  AND q.tenant_id = ?
		  AND (? = FALSE OR (
		      t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')
		      AND q.created_by_kind = 'system' AND q.created_by_id IN ('migration', 'legacy-v1')
		  ))
		ORDER BY s.created_at, s.subscription_id;`
	listQueueSubscriptionsQuery = `SELECT s.subscription_id, s.topic_id, s.queue_id,
		COALESCE(q.queue_name, ''), s.created_at
		FROM topic_subscriptions s
		JOIN topic_properties t ON t.topic_id = s.topic_id
		JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.queue_id = ?
		  AND t.tenant_id = ?
		  AND q.tenant_id = ?
		  AND (? = FALSE OR (
		      t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')
		      AND q.created_by_kind = 'system' AND q.created_by_id IN ('migration', 'legacy-v1')
		  ))
		ORDER BY s.topic_id, s.created_at, s.subscription_id;`
)

func (s *Storage) ListTopics(ctx context.Context) (*queue.ListTopicsResponse, error) {
	scope := queue.ScopeFromContext(ctx)

	rows, err := s.db.QueryContext(ctx, `
		SELECT topic_id, topic_name, created_at
		FROM topic_properties
		WHERE tenant_id = ?
		  AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))
		ORDER BY created_at DESC, topic_id;
	`, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("list topics: %w", normalizePubSubError(err, pubSubListTopics))
	}
	defer rows.Close()

	out := &queue.ListTopicsResponse{Topics: []queue.Topic{}}

	for rows.Next() {
		var topic queue.Topic

		if err := rows.Scan(&topic.TopicID, &topic.TopicName, &topic.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan topic: %w", normalizePubSubError(err, pubSubListTopics))
		}

		topic.Subscriptions, err = listSubscriptions(ctx, s.db, topic.TopicID, pubSubListTopics)
		if err != nil {
			return nil, fmt.Errorf("list subscriptions for topic %q: %w", topic.TopicID, err)
		}

		out.Topics = append(out.Topics, topic)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate topics: %w", normalizePubSubError(err, pubSubListTopics))
	}

	return out, nil
}

func (s *Storage) CreateTopic(ctx context.Context, input *queue.CreateTopicRequest) (_ *queue.CreateTopicResponse, sErr error) {
	if input == nil || strings.TrimSpace(input.TopicName) == "" {
		return nil, fmt.Errorf("%w: topic name is empty", pqerr.ErrInvalidInput)
	}

	id := queue.NextID(ctx, idkit.XID)
	scope := queue.ScopeFromContext(ctx)

	if mutation, ok := sqliteQueueMutation(ctx); ok {
		output, err := s.createTopicWithPolicy(ctx, id, input, scope, mutation)
		if err != nil {
			return nil, fmt.Errorf("create topic with policy: %w", normalizePubSubError(err, pubSubCreateTopic))
		}

		return output, nil
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("begin create topic: %w", normalizePubSubError(err, pubSubCreateTopic))
	}

	defer func() { sErr = joinSQLiteRollback(sErr, tx, pubSubCreateTopic, "create topic") }()

	result, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO topic_properties (
			topic_id, topic_name, created_at, tenant_id, created_by_kind, created_by_id
		) VALUES (?, ?, ?, ?, ?, ?);`,
		id,
		input.TopicName,
		writeTime(ctx),
		scope.TenantID,
		scope.CreatorKind,
		scope.CreatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("create topic: %w", normalizePubSubError(err, pubSubCreateTopic))
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("create topic rows affected: %w", normalizePubSubError(err, pubSubCreateTopic))
	}

	if rows == 0 {
		return nil, fmt.Errorf("create topic: %w", pqerr.ErrAlreadyExists)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit create topic: %w", normalizePubSubError(err, pubSubCreateTopic))
	}

	return &queue.CreateTopicResponse{TopicID: id}, nil
}

//nolint:cyclop // Topic locking, typed cascade capture, deletion, commit, and rollback must share one transaction.
func (s *Storage) DeleteTopic(ctx context.Context, topicID string) (_ *queue.DeleteTopicResult, sErr error) {
	scope := queue.ScopeFromContext(ctx)
	if mutation, ok := sqliteQueueMutation(ctx); ok {
		result, err := s.deleteTopicWithPolicy(ctx, topicID, scope, mutation)
		if err != nil {
			return nil, fmt.Errorf("delete topic with policy: %w", normalizePubSubError(err, pubSubDeleteTopic))
		}

		return result, nil
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("begin delete topic: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	defer func() { sErr = joinSQLiteRollback(sErr, tx, pubSubDeleteTopic, "delete topic") }()

	lockResult, err := tx.ExecContext(ctx, `UPDATE topic_properties SET topic_id = topic_id
		WHERE topic_id = ? AND tenant_id = ?
		  AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')));`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("lock topic for delete: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	lockedRows, err := lockResult.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("lock topic for delete rows affected: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	if lockedRows == 0 {
		return nil, fmt.Errorf("lock topic for delete: %w", pqerr.ErrNotFound)
	}

	removed, err := listSubscriptions(ctx, tx, topicID, pubSubDeleteTopic)
	if err != nil {
		return nil, fmt.Errorf("capture topic subscriptions: %w", err)
	}

	deleteResult := &queue.DeleteTopicResult{RemovedSubscriptions: removed}

	if _, err := tx.ExecContext(ctx, `DELETE FROM topic_subscriptions WHERE topic_id = ?;`, topicID); err != nil {
		return nil, fmt.Errorf("delete topic subscriptions: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM topic_properties
		WHERE topic_id = ? AND tenant_id = ?
		  AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')));`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("delete topic: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("delete topic rows affected: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	if rows == 0 {
		return nil, fmt.Errorf("delete topic: %w", pqerr.ErrNotFound)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit delete topic: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	return deleteResult, nil
}

func (s *Storage) Subscribe(
	ctx context.Context,
	topicID string,
	input *queue.SubscribeRequest,
) (_ *queue.SubscribeResponse, sErr error) {
	if input == nil {
		return nil, fmt.Errorf("subscribe queue: %w", pqerr.ErrInvalidInput)
	}

	id := queue.NextID(ctx, idkit.XID)
	if mutation, ok := sqliteQueueMutation(ctx); ok {
		output, err := s.subscribeWithPolicy(ctx, id, topicID, input, mutation)
		if err != nil {
			return nil, fmt.Errorf("subscribe with policy: %w", normalizePubSubError(err, pubSubSubscribe))
		}

		return output, nil
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("begin subscribe: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	defer func() { sErr = joinSQLiteRollback(sErr, tx, pubSubSubscribe, "subscribe") }()

	if err := ensureSubscriptionTargetsExist(ctx, tx, topicID, input.QueueID); err != nil {
		return nil, err
	}

	result, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO topic_subscriptions (subscription_id, topic_id, queue_id, created_at)
		 VALUES (?, ?, ?, ?);`,
		id,
		topicID,
		input.QueueID,
		writeTime(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("subscribe queue: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("subscribe rows affected: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	if rows == 0 {
		return nil, fmt.Errorf("subscribe queue: %w", pqerr.ErrAlreadyExists)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit subscribe: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	return &queue.SubscribeResponse{SubscriptionID: id}, nil
}

func ensureSubscriptionTargetsExist(ctx context.Context, tx *sql.Tx, topicID, queueID string) error {
	scope := queue.ScopeFromContext(ctx)

	topicExists, err := exists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM topic_properties
		WHERE topic_id = ? AND tenant_id = ?
		  AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1'))));`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("check subscription topic: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	queueExists, err := exists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM queue_properties
		WHERE queue_id = ? AND tenant_id = ?
		  AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1'))));`,
		queueID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("check subscription queue: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	if !topicExists || !queueExists {
		return fmt.Errorf("subscribe queue: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	scope := queue.ScopeFromContext(ctx)
	if mutation, ok := sqliteQueueMutation(ctx); ok {
		if err := s.unsubscribeWithPolicy(ctx, topicID, subscriptionID, scope, mutation); err != nil {
			return fmt.Errorf("unsubscribe with policy: %w", normalizePubSubError(err, pubSubUnsubscribe))
		}

		return nil
	}

	result, err := s.db.ExecContext(
		ctx,
		`DELETE FROM topic_subscriptions
		 WHERE topic_id = ?
		   AND subscription_id = ?
		   AND EXISTS (
		       SELECT 1
		       FROM topic_properties t
		       WHERE t.topic_id = topic_subscriptions.topic_id
		         AND t.tenant_id = ?
		         AND (? = FALSE OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')))
		   );`,
		topicID,
		subscriptionID,
		scope.TenantID,
		scope.Compatibility,
	)
	if err != nil {
		return fmt.Errorf("unsubscribe queue: %w", normalizePubSubError(err, pubSubUnsubscribe))
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("unsubscribe queue rows affected: %w", normalizePubSubError(err, pubSubUnsubscribe))
	}

	if rows == 0 {
		return fmt.Errorf("unsubscribe queue: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) Publish(ctx context.Context, topicID string, input *queue.PublishRequest) (*queue.PublishResponse, error) {
	if input == nil || len(input.Messages) == 0 {
		return nil, fmt.Errorf("%w: messages are empty", pqerr.ErrInvalidInput)
	}

	if mutation, ok := sqliteQueueMutation(ctx); ok {
		output, err := s.publishWithPolicy(ctx, topicID, input, mutation)
		if err != nil {
			return output, fmt.Errorf("publish with policy: %w", normalizePubSubError(err, pubSubPublish))
		}

		return output, nil
	}

	if err := s.ensureTopicExists(ctx, topicID); err != nil {
		return nil, err
	}

	subscriptions, err := listSubscriptions(ctx, s.db, topicID, pubSubPublish)
	if err != nil {
		return nil, err
	}

	bytes := publishedMessageBytes(input.Messages)
	send := func(ctx context.Context, request *v1.SendRequest) (*v1.SendResponse, error) {
		sent, err := s.Send(ctx, request)
		if err != nil {
			return sent, normalizePubSubError(err, pubSubPublish)
		}

		s.observer.Sent(request.GetQueueId(), uint64(len(sent.GetMessageIds())), bytes)

		return sent, nil
	}

	response, err := queue.FanOut(ctx, topicID, subscriptions, input.Messages, send)
	if err != nil {
		return response, fmt.Errorf("fan out topic %q: %w", topicID, err)
	}

	return response, nil
}

func (s *Storage) TopicInventory(ctx context.Context) (queue.TopicInventory, error) {
	scope := queue.ScopeFromContext(ctx)

	rows, err := s.db.QueryContext(ctx, topicInventoryQuery, scope.TenantID, scope.Compatibility)
	if err != nil {
		return queue.TopicInventory{}, fmt.Errorf("topic inventory: %w", normalizePubSubError(err, pubSubInventory))
	}
	defer rows.Close()

	inventory := queue.TopicInventory{SubscriptionCounts: map[string]int64{}}

	for rows.Next() {
		var (
			topicID string
			count   int64
		)

		if err := rows.Scan(&topicID, &count); err != nil {
			return queue.TopicInventory{}, fmt.Errorf("scan topic inventory: %w", normalizePubSubError(err, pubSubInventory))
		}

		inventory.TopicsExist++
		inventory.SubscriptionCounts[topicID] = count
	}

	if err := rows.Err(); err != nil {
		return queue.TopicInventory{}, fmt.Errorf("iterate topic inventory: %w", normalizePubSubError(err, pubSubInventory))
	}

	return inventory, nil
}

type queryContextRunner interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Storage) ensureTopicExists(ctx context.Context, topicID string) error {
	scope := queue.ScopeFromContext(ctx)

	ok, err := exists(ctx, s.db, `SELECT EXISTS(SELECT 1 FROM topic_properties
		WHERE topic_id = ? AND tenant_id = ?
		  AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1'))));`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("check topic exists: %w", normalizePubSubError(err, pubSubPublish))
	}

	if !ok {
		return fmt.Errorf("check topic exists: %w", pqerr.ErrNotFound)
	}

	return nil
}

func exists(ctx context.Context, db queryContextRunner, query string, args ...any) (bool, error) {
	var ok bool

	if err := db.QueryRowContext(ctx, query, args...).Scan(&ok); err != nil {
		return false, fmt.Errorf("scan existence query: %w", err)
	}

	return ok, nil
}

func listSubscriptions(
	ctx context.Context,
	db queryContextRunner,
	topicID string,
	operation pubSubErrorContext,
) ([]queue.Subscription, error) {
	scope := queue.ScopeFromContext(ctx)

	rows, err := db.QueryContext(
		ctx,
		listTopicSubscriptionsQuery,
		topicID,
		scope.TenantID,
		scope.TenantID,
		scope.Compatibility,
	)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", normalizePubSubError(err, operation))
	}
	defer rows.Close()

	subscriptions := []queue.Subscription{}

	for rows.Next() {
		var subscription queue.Subscription

		if err := rows.Scan(
			&subscription.SubscriptionID,
			&subscription.TopicID,
			&subscription.QueueID,
			&subscription.QueueName,
			&subscription.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan subscription: %w", normalizePubSubError(err, operation))
		}

		subscriptions = append(subscriptions, subscription)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscriptions: %w", normalizePubSubError(err, operation))
	}

	return subscriptions, nil
}

func listSubscriptionsByQueue(ctx context.Context, tx *sql.Tx, queueID string) ([]queue.Subscription, error) {
	scope := queue.ScopeFromContext(ctx)

	rows, err := tx.QueryContext(
		ctx,
		listQueueSubscriptionsQuery,
		queueID,
		scope.TenantID,
		scope.TenantID,
		scope.Compatibility,
	)
	if err != nil {
		return nil, fmt.Errorf("list queue subscriptions: %w", normalizePubSubError(err, pubSubDeleteQueue))
	}
	defer rows.Close()

	subscriptions := []queue.Subscription{}

	for rows.Next() {
		var subscription queue.Subscription

		if err := rows.Scan(
			&subscription.SubscriptionID,
			&subscription.TopicID,
			&subscription.QueueID,
			&subscription.QueueName,
			&subscription.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan queue subscription: %w", normalizePubSubError(err, pubSubDeleteQueue))
		}

		subscriptions = append(subscriptions, subscription)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate queue subscriptions: %w", normalizePubSubError(err, pubSubDeleteQueue))
	}

	return subscriptions, nil
}

func joinSQLiteRollback(current error, tx *sql.Tx, operation pubSubErrorContext, label string) error {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return errors.Join(current, fmt.Errorf("rollback %s: %w", label, normalizePubSubError(err, operation)))
	}

	return current
}

func publishedMessageBytes(messages []queue.PublishMessage) uint64 {
	var total uint64
	for _, message := range messages {
		total += uint64(len(message.Body))
	}

	return total
}
