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
	rows, err := s.db.QueryContext(ctx, `select topic_id, topic_name, created_at from topic_properties order by created_at desc;`)
	if err != nil {
		return nil, fmt.Errorf("list topics: %w", err)
	}
	defer rows.Close()

	out := &queue.ListTopicsResponse{Topics: []queue.Topic{}}
	for rows.Next() {
		var t queue.Topic
		if err := rows.Scan(&t.TopicID, &t.TopicName, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan topic: %w", err)
		}
		t.Subscriptions, err = s.listSubscriptions(ctx, t.TopicID)
		if err != nil {
			return nil, err
		}
		out.Topics = append(out.Topics, t)
	}
	return out, rows.Err()
}

func (s *Storage) CreateTopic(ctx context.Context, input *queue.CreateTopicRequest) (*queue.CreateTopicResponse, error) {
	if strings.TrimSpace(input.TopicName) == "" {
		return nil, fmt.Errorf("%w: topic name is empty", errkit.ErrInvalidArgument)
	}
	id := idkit.XID()
	if _, err := s.db.ExecContext(ctx, `insert into topic_properties (topic_id, topic_name) values (?, ?);`, id, input.TopicName); err != nil {
		return nil, fmt.Errorf("create topic: %w", err)
	}
	return &queue.CreateTopicResponse{TopicID: id}, nil
}

func (s *Storage) DeleteTopic(ctx context.Context, topicID string) error {
	res, err := s.db.ExecContext(ctx, `delete from topic_properties where topic_id = ?;`, topicID)
	if err != nil {
		return fmt.Errorf("delete topic: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
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
	id := idkit.XID()
	if _, err := s.db.ExecContext(ctx, `insert into topic_subscriptions (subscription_id, topic_id, queue_id) values (?, ?, ?);`, id, topicID, input.QueueID); err != nil {
		return nil, fmt.Errorf("subscribe queue: %w", err)
	}
	return &queue.SubscribeResponse{SubscriptionID: id}, nil
}

func (s *Storage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	res, err := s.db.ExecContext(ctx, `delete from topic_subscriptions where topic_id = ? and subscription_id = ?;`, topicID, subscriptionID)
	if err != nil {
		return fmt.Errorf("unsubscribe queue: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
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
	subs, err := s.listSubscriptions(ctx, topicID)
	if err != nil {
		return nil, err
	}
	out := &queue.PublishResponse{TopicID: topicID, QueueIDs: []string{}, MessageIDs: []string{}}
	for _, sub := range subs {
		msgs := make([]*v1.SendMessage, 0, len(input.Messages))
		for _, m := range input.Messages {
			msgs = append(msgs, &v1.SendMessage{Body: m.Body})
		}
		sent, err := s.Send(ctx, &v1.SendRequest{QueueId: sub.QueueID, Messages: msgs})
		if err != nil {
			return nil, fmt.Errorf("publish to queue %q: %w", sub.QueueID, err)
		}
		out.QueueIDs = append(out.QueueIDs, sub.QueueID)
		out.MessageIDs = append(out.MessageIDs, sent.MessageIds...)
		out.DeliveredCount += len(sent.MessageIds)
	}
	return out, nil
}

func (s *Storage) listSubscriptions(ctx context.Context, topicID string) ([]queue.Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `select s.subscription_id, s.topic_id, s.queue_id, coalesce(q.queue_name, ''), s.created_at from topic_subscriptions s left join queue_properties q on q.queue_id = s.queue_id where s.topic_id = ? order by s.created_at desc;`, topicID)
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
	return subs, rows.Err()
}
