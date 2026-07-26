package litestore

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/idkit"
)

func (s *Storage) ListTopics(ctx context.Context) (*queue.ListTopicsResponse, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT topic_id, topic_name, created_at
		FROM topic_properties
		ORDER BY created_at DESC;
	`)
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

	// created_at is written rather than left to the column default: a default
	// reads the local clock, and two replicas applying the same CreateTopic
	// would then disagree about when the topic appeared.
	id := queue.NextID(ctx, idkit.XID)
	if _, err := s.db.ExecContext(
		ctx,
		`INSERT INTO topic_properties (topic_id, topic_name, created_at) VALUES (?, ?, ?);`,
		id,
		input.TopicName,
		writeTime(ctx),
	); err != nil {
		return nil, fmt.Errorf("create topic: %w", err)
	}

	return &queue.CreateTopicResponse{TopicID: id}, nil
}

func (s *Storage) DeleteTopic(ctx context.Context, topicID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM topic_properties WHERE topic_id = ?;`, topicID)
	if err != nil {
		return fmt.Errorf("delete topic: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete topic rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("delete topic: %w", errkit.ErrNotFound)
	}

	return nil
}

func (s *Storage) Subscribe(ctx context.Context, topicID string, input *queue.SubscribeRequest) (*queue.SubscribeResponse, error) {
	if _, err := s.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: input.QueueID}); err != nil {
		return nil, fmt.Errorf("describe subscription queue: %w", err)
	}

	id := queue.NextID(ctx, idkit.XID)
	if _, err := s.db.ExecContext(
		ctx,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id, created_at) VALUES (?, ?, ?, ?);`,
		id,
		topicID,
		input.QueueID,
		writeTime(ctx),
	); err != nil {
		return nil, fmt.Errorf("subscribe queue: %w", err)
	}

	return &queue.SubscribeResponse{SubscriptionID: id}, nil
}

func (s *Storage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	res, err := s.db.ExecContext(
		ctx,
		`DELETE FROM topic_subscriptions WHERE topic_id = ? AND subscription_id = ?;`,
		topicID,
		subscriptionID,
	)
	if err != nil {
		return fmt.Errorf("unsubscribe queue: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("unsubscribe queue rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("unsubscribe queue: %w", errkit.ErrNotFound)
	}

	return nil
}

func (s *Storage) Publish(ctx context.Context, topicID string, input *queue.PublishRequest) (*queue.PublishResponse, error) {
	if len(input.Messages) == 0 {
		return nil, fmt.Errorf("%w: messages are empty", errkit.ErrInvalidArgument)
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
		if err != nil {
			return nil, fmt.Errorf("publish to queue %q: %w", sub.QueueID, err)
		}

		// Fan-out reaches Send directly, below the layer that records queue
		// traffic, so a message delivered through a topic would otherwise
		// never appear in its destination queue's counters or depth.
		s.observer.Sent(sub.QueueID, uint64(len(sent.MessageIds)), publishedBytes(msgs))

		out.QueueIDs = append(out.QueueIDs, sub.QueueID)
		out.MessageIDs = append(out.MessageIDs, sent.MessageIds...)
		out.DeliveredCount += len(sent.MessageIds)
	}

	return out, nil
}

func (s *Storage) ensureTopicExists(ctx context.Context, topicID string) error {
	var exists bool

	if err := s.db.QueryRowContext(
		ctx,
		`SELECT EXISTS(SELECT 1 FROM topic_properties WHERE topic_id = ?);`,
		topicID,
	).Scan(&exists); err != nil {
		return fmt.Errorf("check topic exists: %w", err)
	}

	if !exists {
		return fmt.Errorf("check topic exists: %w", errkit.ErrNotFound)
	}

	return nil
}

func (s *Storage) listSubscriptions(ctx context.Context, topicID string) ([]queue.Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.subscription_id,
		       s.topic_id,
		       s.queue_id,
		       COALESCE(q.queue_name, ''),
		       s.created_at
		FROM topic_subscriptions s
		LEFT JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.topic_id = ?
		ORDER BY s.created_at DESC;
	`, topicID)
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
