package pgstore

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/idkit"
)

var _ queue.Storage = (*Storage)(nil)

func (s *Storage) ListTopics(ctx context.Context) (*queue.ListTopicsResponse, error) {
	scope := queue.ScopeFromContext(ctx)

	rows, err := s.pool.Query(ctx, `
		SELECT topic_id, topic_name, created_at
		FROM topic_properties
		WHERE tenant_id = $1
		  AND (NOT $2::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))
		ORDER BY created_at DESC;
	`, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("list topics: %w", err)
	}

	defer rows.Close()

	out := &queue.ListTopicsResponse{Topics: []queue.Topic{}}

	for rows.Next() {
		var topic queue.Topic
		if err := rows.Scan(&topic.TopicID, &topic.TopicName, &topic.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan topic: %w", err)
		}

		topic.Subscriptions, err = s.listSubscriptions(ctx, topic.TopicID)
		if err != nil {
			return nil, fmt.Errorf("list subscriptions for topic %q: %w", topic.TopicID, err)
		}

		out.Topics = append(out.Topics, topic)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate topics: %w", err)
	}

	return out, nil
}

func (s *Storage) CreateTopic(ctx context.Context, input *queue.CreateTopicRequest) (*queue.CreateTopicResponse, error) {
	if strings.TrimSpace(input.TopicName) == "" {
		return nil, fmt.Errorf("%w: topic name is empty", errkit.ErrInvalidArgument)
	}

	id := idkit.XID()

	scope := queue.ScopeFromContext(ctx)
	if mutation, ok := postgresQueueMutation(ctx); ok {
		return s.createTopicWithPolicy(ctx, id, input, scope, mutation)
	}

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO topic_properties (
			topic_id, topic_name, tenant_id, created_by_kind, created_by_id
		) VALUES ($1, $2, $3, $4, $5);
	`, id, input.TopicName, scope.TenantID, scope.CreatorKind, scope.CreatorID); err != nil {
		return nil, fmt.Errorf("create topic: %w", err)
	}

	return &queue.CreateTopicResponse{TopicID: id}, nil
}

func (s *Storage) DeleteTopic(ctx context.Context, topicID string) error {
	scope := queue.ScopeFromContext(ctx)
	if mutation, ok := postgresQueueMutation(ctx); ok {
		return s.deleteTopicWithPolicy(ctx, topicID, scope, mutation)
	}

	tag, err := s.pool.Exec(ctx, `
		DELETE FROM topic_properties
		WHERE topic_id = $1
		  AND tenant_id = $2
		  AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')));
	`, topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("delete topic: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("delete topic: %w", errkit.ErrNotFound)
	}

	return nil
}

func (s *Storage) Subscribe(ctx context.Context, topicID string, input *queue.SubscribeRequest) (*queue.SubscribeResponse, error) {
	if err := s.ensureTopicExists(ctx, topicID); err != nil {
		return nil, err
	}

	if _, err := s.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: input.QueueID}); err != nil {
		return nil, fmt.Errorf("describe subscription queue: %w", err)
	}

	id := idkit.XID()
	if mutation, ok := postgresQueueMutation(ctx); ok {
		return s.subscribeWithPolicy(ctx, id, topicID, input, mutation)
	}

	if _, err := s.pool.Exec(
		ctx,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ($1, $2, $3);`,
		id,
		topicID,
		input.QueueID,
	); err != nil {
		return nil, fmt.Errorf("subscribe queue: %w", err)
	}

	return &queue.SubscribeResponse{SubscriptionID: id}, nil
}

func (s *Storage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	scope := queue.ScopeFromContext(ctx)
	if mutation, ok := postgresQueueMutation(ctx); ok {
		return s.unsubscribeWithPolicy(ctx, topicID, subscriptionID, scope, mutation)
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
		return fmt.Errorf("unsubscribe queue: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("unsubscribe queue: %w", errkit.ErrNotFound)
	}

	return nil
}

func (s *Storage) Publish(ctx context.Context, topicID string, input *queue.PublishRequest) (*queue.PublishResponse, error) {
	if len(input.Messages) == 0 {
		return nil, fmt.Errorf("%w: messages are empty", errkit.ErrInvalidArgument)
	}

	if mutation, ok := postgresQueueMutation(ctx); ok {
		return s.publishWithPolicy(ctx, topicID, input, mutation)
	}

	if err := s.ensureTopicExists(ctx, topicID); err != nil {
		return nil, err
	}

	subs, err := s.listSubscriptions(ctx, topicID)
	if err != nil {
		return nil, err
	}

	out := &queue.PublishResponse{
		TopicID:    topicID,
		QueueIDs:   []string{},
		MessageIDs: []string{},
	}

	for _, sub := range subs {
		msgs := make([]*v1.SendMessage, 0, len(input.Messages))
		for _, msg := range input.Messages {
			msgs = append(msgs, &v1.SendMessage{Body: msg.Body})
		}

		sent, err := s.Send(ctx, &v1.SendRequest{QueueId: sub.QueueID, Messages: msgs})
		if err == nil {
			// Fan-out reaches Send directly, below the layer that records
			// queue traffic, so a message delivered through a topic would
			// otherwise never appear in its destination queue's counters.
			s.observer.Sent(sub.QueueID, uint64(len(sent.MessageIds)), publishedBytes(msgs))
		}

		if err != nil {
			return nil, fmt.Errorf("publish to queue %q: %w", sub.QueueID, err)
		}

		out.QueueIDs = append(out.QueueIDs, sub.QueueID)
		out.MessageIDs = append(out.MessageIDs, sent.MessageIds...)
		out.DeliveredCount += len(sent.MessageIds)
	}

	return out, nil
}

func (s *Storage) ensureTopicExists(ctx context.Context, topicID string) error {
	var exists bool

	scope := queue.ScopeFromContext(ctx)

	if err := s.pool.QueryRow(
		ctx,
		`SELECT EXISTS(
			SELECT 1
			FROM topic_properties
			WHERE topic_id = $1
			  AND tenant_id = $2
			  AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))
		);`,
		topicID,
		scope.TenantID,
		scope.Compatibility,
	).Scan(&exists); err != nil {
		return fmt.Errorf("check topic exists: %w", err)
	}

	if !exists {
		return fmt.Errorf("check topic exists: %w", errkit.ErrNotFound)
	}

	return nil
}

func (s *Storage) listSubscriptions(ctx context.Context, topicID string) ([]queue.Subscription, error) {
	scope := queue.ScopeFromContext(ctx)

	rows, err := s.pool.Query(ctx, `
		SELECT s.subscription_id,
		       s.topic_id,
		       s.queue_id,
		       COALESCE(q.queue_name, ''),
		       s.created_at
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
		ORDER BY s.created_at DESC;
	`, topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}

	defer rows.Close()

	subs := []queue.Subscription{}

	for rows.Next() {
		var sub queue.Subscription
		if err := rows.Scan(&sub.SubscriptionID, &sub.TopicID, &sub.QueueID, &sub.QueueName, &sub.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}

		subs = append(subs, sub)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscriptions: %w", err)
	}

	return subs, nil
}

// publishedBytes totals the bodies one fan-out delivery carried.
func publishedBytes(messages []*v1.SendMessage) uint64 {
	var total uint64

	for _, message := range messages {
		total += uint64(len(message.GetBody()))
	}

	return total
}
