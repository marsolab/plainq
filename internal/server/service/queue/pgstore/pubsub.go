package pgstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
)

const (
	topicInventoryQuery = `SELECT t.topic_id, COUNT(s.subscription_id)
	FROM topic_properties t
	LEFT JOIN topic_subscriptions s ON s.topic_id = t.topic_id
	WHERE t.tenant_id = $1
	  AND (NOT $2::boolean OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')))
	GROUP BY t.topic_id
	ORDER BY t.topic_id;`

	listTopicSubscriptionsQuery = `SELECT s.subscription_id, s.topic_id, s.queue_id, COALESCE(q.queue_name, ''), s.created_at
	FROM topic_subscriptions s
	JOIN topic_properties t ON t.topic_id = s.topic_id
	JOIN queue_properties q ON q.queue_id = s.queue_id
	WHERE s.topic_id = $1
	  AND t.tenant_id = $2
	  AND q.tenant_id = $2
	  AND (NOT $3::boolean OR (
	      t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')
	      AND q.created_by_kind = 'system' AND q.created_by_id IN ('migration', 'legacy-v1')
	  ))
	ORDER BY s.created_at, s.subscription_id;`

	captureTopicSubscriptionsQuery = `SELECT s.subscription_id, s.topic_id, s.queue_id, COALESCE(q.queue_name, ''), s.created_at
	FROM topic_subscriptions s
	JOIN topic_properties t ON t.topic_id = s.topic_id
	JOIN queue_properties q ON q.queue_id = s.queue_id
	WHERE s.topic_id = $1
	  AND t.tenant_id = $2
	  AND q.tenant_id = $2
	  AND (NOT $3::boolean OR (
	      t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')
	      AND q.created_by_kind = 'system' AND q.created_by_id IN ('migration', 'legacy-v1')
	  ))
	ORDER BY s.created_at, s.subscription_id
	FOR UPDATE OF s;`

	captureQueueSubscriptionsQuery = `SELECT s.subscription_id, s.topic_id, s.queue_id, COALESCE(q.queue_name, ''), s.created_at
	FROM topic_subscriptions s
	JOIN topic_properties t ON t.topic_id = s.topic_id
	JOIN queue_properties q ON q.queue_id = s.queue_id
	WHERE s.queue_id = $1
	  AND t.tenant_id = $2
	  AND q.tenant_id = $2
	  AND (NOT $3::boolean OR (
	      t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')
	      AND q.created_by_kind = 'system' AND q.created_by_id IN ('migration', 'legacy-v1')
	  ))
	ORDER BY s.topic_id, s.created_at, s.subscription_id
	FOR UPDATE OF s;`
)

var _ queue.Storage = (*Storage)(nil)

func (s *Storage) ListTopics(ctx context.Context) (*queue.ListTopicsResponse, error) {
	scope := queue.ScopeFromContext(ctx)

	rows, err := s.pool.Query(ctx, `
		SELECT topic_id, topic_name, created_at
		FROM topic_properties
		WHERE tenant_id = $1
		  AND (NOT $2::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))
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

		topic.Subscriptions, err = listSubscriptions(ctx, s.pool, topic.TopicID, pubSubListTopics)
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

	if mutation, ok := postgresQueueMutation(ctx); ok {
		output, err := s.createTopicWithPolicy(ctx, id, input, scope, mutation)
		if err != nil {
			return nil, fmt.Errorf("create topic with policy: %w", normalizePubSubError(err, pubSubCreateTopic))
		}

		return output, nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin create topic: %w", normalizePubSubError(err, pubSubCreateTopic))
	}
	defer func() { sErr = joinPostgresRollback(ctx, sErr, tx, pubSubCreateTopic, "create topic") }()

	tag, err := tx.Exec(
		ctx,
		`INSERT INTO topic_properties (
			topic_id, topic_name, created_at, tenant_id, created_by_kind, created_by_id
		) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING;`,
		id,
		input.TopicName,
		queue.WriteTime(ctx),
		scope.TenantID,
		scope.CreatorKind,
		scope.CreatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("create topic: %w", normalizePubSubError(err, pubSubCreateTopic))
	}

	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("create topic: %w", pqerr.ErrAlreadyExists)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create topic: %w", normalizePubSubError(err, pubSubCreateTopic))
	}

	return &queue.CreateTopicResponse{TopicID: id}, nil
}

func (s *Storage) DeleteTopic(ctx context.Context, topicID string) (_ *queue.DeleteTopicResult, sErr error) {
	scope := queue.ScopeFromContext(ctx)
	if mutation, ok := postgresQueueMutation(ctx); ok {
		result, err := s.deleteTopicWithPolicy(ctx, topicID, scope, mutation)
		if err != nil {
			return nil, fmt.Errorf("delete topic with policy: %w", normalizePubSubError(err, pubSubDeleteTopic))
		}

		return result, nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin delete topic: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}
	defer func() { sErr = joinPostgresRollback(ctx, sErr, tx, pubSubDeleteTopic, "delete topic") }()

	if err := lockTopicForDeleteInScope(ctx, tx, topicID, scope); err != nil {
		return nil, err
	}

	removed, err := querySubscriptions(
		ctx,
		tx,
		captureTopicSubscriptionsQuery,
		pubSubDeleteTopic,
		topicID,
		scope.TenantID,
		scope.Compatibility,
	)
	if err != nil {
		return nil, fmt.Errorf("capture topic subscriptions: %w", err)
	}

	deleteResult := &queue.DeleteTopicResult{RemovedSubscriptions: removed}

	tag, err := tx.Exec(ctx, `DELETE FROM topic_properties
		WHERE topic_id = $1 AND tenant_id = $2
		  AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')));`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("delete topic: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("delete topic: %w", pqerr.ErrNotFound)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit delete topic: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}

	return deleteResult, nil
}

//nolint:cyclop // Validation, policy delegation, scoped checks, duplicate handling, and commit form one atomic operation.
func (s *Storage) Subscribe(
	ctx context.Context,
	topicID string,
	input *queue.SubscribeRequest,
) (_ *queue.SubscribeResponse, sErr error) {
	if input == nil {
		return nil, fmt.Errorf("subscribe queue: %w", pqerr.ErrInvalidInput)
	}

	id := queue.NextID(ctx, idkit.XID)
	if mutation, ok := postgresQueueMutation(ctx); ok {
		output, err := s.subscribeWithPolicy(ctx, id, topicID, input, mutation)
		if err != nil {
			return nil, fmt.Errorf("subscribe with policy: %w", normalizePubSubError(err, pubSubSubscribe))
		}

		return output, nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin subscribe: %w", normalizePubSubError(err, pubSubSubscribe))
	}
	defer func() { sErr = joinPostgresRollback(ctx, sErr, tx, pubSubSubscribe, "subscribe") }()

	scope := queue.ScopeFromContext(ctx)

	topicExists, err := pgExists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM topic_properties
		WHERE topic_id = $1 AND tenant_id = $2
		  AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1'))));`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("check subscription topic: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	queueExists, err := pgExists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM queue_properties
		WHERE queue_id = $1 AND tenant_id = $2
		  AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1'))));`,
		input.QueueID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("check subscription queue: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	if !topicExists || !queueExists {
		return nil, fmt.Errorf("subscribe queue: %w", pqerr.ErrNotFound)
	}

	tag, err := tx.Exec(
		ctx,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id, created_at)
		 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING;`,
		id,
		topicID,
		input.QueueID,
		queue.WriteTime(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("subscribe queue: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("subscribe queue: %w", pqerr.ErrAlreadyExists)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit subscribe: %w", normalizePubSubError(err, pubSubSubscribe))
	}

	return &queue.SubscribeResponse{SubscriptionID: id}, nil
}

func (s *Storage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	scope := queue.ScopeFromContext(ctx)
	if mutation, ok := postgresQueueMutation(ctx); ok {
		if err := s.unsubscribeWithPolicy(ctx, topicID, subscriptionID, scope, mutation); err != nil {
			return fmt.Errorf("unsubscribe with policy: %w", normalizePubSubError(err, pubSubUnsubscribe))
		}

		return nil
	}

	tag, err := s.pool.Exec(
		ctx,
		`DELETE FROM topic_subscriptions
		 WHERE topic_id = $1
		   AND subscription_id = $2
		   AND EXISTS (
		       SELECT 1
		       FROM topic_properties t
		       WHERE t.topic_id = topic_subscriptions.topic_id
		         AND t.tenant_id = $3
		         AND (NOT $4::boolean OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')))
		   );`,
		topicID,
		subscriptionID,
		scope.TenantID,
		scope.Compatibility,
	)
	if err != nil {
		return fmt.Errorf("unsubscribe queue: %w", normalizePubSubError(err, pubSubUnsubscribe))
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("unsubscribe queue: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) Publish(ctx context.Context, topicID string, input *queue.PublishRequest) (*queue.PublishResponse, error) {
	if input == nil || len(input.Messages) == 0 {
		return nil, fmt.Errorf("%w: messages are empty", pqerr.ErrInvalidInput)
	}

	if mutation, ok := postgresQueueMutation(ctx); ok {
		output, err := s.publishWithPolicy(ctx, topicID, input, mutation)
		if err != nil {
			return output, fmt.Errorf("publish with policy: %w", normalizePubSubError(err, pubSubPublish))
		}

		return output, nil
	}

	if err := s.ensureTopicExists(ctx, topicID); err != nil {
		return nil, err
	}

	subscriptions, err := listSubscriptions(ctx, s.pool, topicID, pubSubPublish)
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

	rows, err := s.pool.Query(ctx, topicInventoryQuery, scope.TenantID, scope.Compatibility)
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

type pgQueryRunner interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

type pgQueryRower interface {
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

func lockTopicForDeleteInScope(
	ctx context.Context,
	db pgQueryRower,
	topicID string,
	scope queue.AccessScope,
) error {
	return lockParentForDelete(
		ctx,
		db,
		`SELECT topic_id FROM topic_properties
		 WHERE topic_id = $1 AND tenant_id = $2
		   AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))
		 FOR UPDATE;`,
		pubSubDeleteTopic,
		"topic",
		topicID,
		scope.TenantID,
		scope.Compatibility,
	)
}

func lockQueueForDeleteInScope(
	ctx context.Context,
	db pgQueryRower,
	queueID string,
	scope queue.AccessScope,
) error {
	return lockParentForDelete(
		ctx,
		db,
		`SELECT queue_id FROM queue_properties
		 WHERE queue_id = $1 AND tenant_id = $2
		   AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))
		 FOR UPDATE;`,
		pubSubDeleteQueue,
		"queue",
		queueID,
		scope.TenantID,
		scope.Compatibility,
	)
}

func lockQueueTableForDelete(ctx context.Context, db pgQueryRunner, queueID string) error {
	if _, err := db.Exec(ctx, `LOCK TABLE `+quoteIdent(queueID)+` IN ACCESS EXCLUSIVE MODE;`); err != nil {
		return fmt.Errorf("lock queue %q table for delete: %w", queueID, normalizePubSubError(err, pubSubDeleteQueue))
	}

	return nil
}

func lockParentForDelete(
	ctx context.Context,
	db pgQueryRower,
	query string,
	operation pubSubErrorContext,
	parentName string,
	args ...any,
) error {
	var lockedID string
	if err := db.QueryRow(ctx, query, args...).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("lock %s for delete: %w", parentName, pqerr.ErrNotFound)
		}

		return fmt.Errorf("lock %s for delete: %w", parentName, normalizePubSubError(err, operation))
	}

	return nil
}

func (s *Storage) ensureTopicExists(ctx context.Context, topicID string) error {
	scope := queue.ScopeFromContext(ctx)

	ok, err := pgExists(ctx, s.pool, `SELECT EXISTS(SELECT 1 FROM topic_properties
		WHERE topic_id = $1 AND tenant_id = $2
		  AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1'))));`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("check topic exists: %w", normalizePubSubError(err, pubSubPublish))
	}

	if !ok {
		return fmt.Errorf("check topic exists: %w", pqerr.ErrNotFound)
	}

	return nil
}

func pgExists(ctx context.Context, db pgQueryRunner, query string, args ...any) (bool, error) {
	var ok bool

	if err := db.QueryRow(ctx, query, args...).Scan(&ok); err != nil {
		return false, fmt.Errorf("scan existence query: %w", err)
	}

	return ok, nil
}

func listSubscriptions(
	ctx context.Context,
	db pgQueryRunner,
	topicID string,
	operation pubSubErrorContext,
) ([]queue.Subscription, error) {
	scope := queue.ScopeFromContext(ctx)

	return querySubscriptions(
		ctx,
		db,
		listTopicSubscriptionsQuery,
		operation,
		topicID,
		scope.TenantID,
		scope.Compatibility,
	)
}

func querySubscriptions(
	ctx context.Context,
	db pgQueryRunner,
	query string,
	operation pubSubErrorContext,
	args ...any,
) ([]queue.Subscription, error) {
	rows, err := db.Query(ctx, query, args...)
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

func listSubscriptionsByQueue(ctx context.Context, tx pgx.Tx, queueID string) ([]queue.Subscription, error) {
	scope := queue.ScopeFromContext(ctx)

	return querySubscriptions(
		ctx,
		tx,
		captureQueueSubscriptionsQuery,
		pubSubDeleteQueue,
		queueID,
		scope.TenantID,
		scope.Compatibility,
	)
}

func joinPostgresRollback(ctx context.Context, current error, tx pgx.Tx, operation pubSubErrorContext, label string) error {
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
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
