package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestStoragePublishMissingTopic(t *testing.T) {
	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("open litekit connection: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("close connection: %v", err)
		}
	})
	setupPubSubTables(t, ctx, conn)

	storage, err := New(conn)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	t.Cleanup(func() {
		if err := storage.Close(); err != nil {
			t.Fatalf("close storage: %v", err)
		}
	})

	_, err = storage.Publish(ctx, "missing-topic-id", &queue.PublishRequest{
		Messages: []queue.PublishMessage{{Body: []byte("hello")}},
	})
	if !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("publish missing topic error = %v, want %v", err, pqerr.ErrNotFound)
	}
}

func TestStorageTopicPubSubConformance(t *testing.T) {
	ctx := context.Background()
	storage, conn := newPubSubStorage(t)

	if _, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "   "}); !errors.Is(err, pqerr.ErrInvalidInput) {
		t.Fatalf("blank topic error = %v, want %v", err, pqerr.ErrInvalidInput)
	}

	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "events"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if _, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "events"}); !errors.Is(err, pqerr.ErrAlreadyExists) {
		t.Fatalf("duplicate topic error = %v, want %v", err, pqerr.ErrAlreadyExists)
	}

	zero, err := storage.Publish(ctx, topic.TopicID, &queue.PublishRequest{Messages: []queue.PublishMessage{{Body: []byte("hello")}}})
	if err != nil {
		t.Fatalf("publish with no subscriptions: %v", err)
	}
	if zero.DeliveredCount != 0 || len(zero.QueueIDs) != 0 {
		t.Fatalf("zero subscription publish = %#v", zero)
	}

	if _, err := storage.Subscribe(ctx, "missing", &queue.SubscribeRequest{QueueID: "missing"}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("subscribe missing topic and queue error = %v, want %v", err, pqerr.ErrNotFound)
	}

	q1 := createQueue(t, ctx, storage, "queue-one")
	q2 := createQueue(t, ctx, storage, "queue-two")
	if _, err := storage.Subscribe(ctx, "missing", &queue.SubscribeRequest{QueueID: q1}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("subscribe missing topic error = %v, want %v", err, pqerr.ErrNotFound)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: "missing"}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("subscribe missing queue error = %v, want %v", err, pqerr.ErrNotFound)
	}
	first, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: q1})
	if err != nil {
		t.Fatalf("subscribe first queue: %v", err)
	}
	second, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: q2})
	if err != nil {
		t.Fatalf("subscribe second queue: %v", err)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: q1}); !errors.Is(err, pqerr.ErrAlreadyExists) {
		t.Fatalf("duplicate subscription error = %v, want %v", err, pqerr.ErrAlreadyExists)
	}

	if err := storage.Unsubscribe(ctx, topic.TopicID, "missing"); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("missing subscription error = %v, want %v", err, pqerr.ErrNotFound)
	}

	if _, err := conn.ExecContext(ctx, queryDeleteQueueTable(q1)); err != nil {
		t.Fatalf("break first destination: %v", err)
	}
	partial, err := storage.Publish(ctx, topic.TopicID, &queue.PublishRequest{Messages: []queue.PublishMessage{{Body: []byte("payload")}}})
	var partialErr *queue.PartialPublishError
	if !errors.As(err, &partialErr) {
		t.Fatalf("partial publish error = %v, want *queue.PartialPublishError", err)
	}
	if partial == nil || partial.DeliveredCount != 1 || !reflect.DeepEqual(partial.QueueIDs, []string{q1, q2}) {
		t.Fatalf("partial publish response = %#v, want both selected queues and one delivery", partial)
	}
	received, err := storage.Receive(ctx, &v1.ReceiveRequest{QueueId: q2})
	if err != nil || len(received.Messages) != 1 {
		t.Fatalf("receive later destination = %#v, %v", received, err)
	}

	result, err := storage.DeleteTopic(ctx, topic.TopicID)
	if err != nil {
		t.Fatalf("delete topic: %v", err)
	}
	if got := subscriptionIDs(result.RemovedSubscriptions); !reflect.DeepEqual(got, []string{first.SubscriptionID, second.SubscriptionID}) {
		t.Fatalf("removed subscriptions = %v, want %v", got, []string{first.SubscriptionID, second.SubscriptionID})
	}
	if _, err := storage.DeleteTopic(ctx, topic.TopicID); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("missing topic delete error = %v, want %v", err, pqerr.ErrNotFound)
	}
}

func TestStorageDeleteQueueReturnsCascadeAndInventoryIncludesEmptyTopics(t *testing.T) {
	ctx := context.Background()
	storage, _ := newPubSubStorage(t)
	t1, _ := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "one"})
	t2, _ := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "two"})
	t3, _ := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "empty"})
	queueID := createQueue(t, ctx, storage, "shared")
	s1, _ := storage.Subscribe(ctx, t1.TopicID, &queue.SubscribeRequest{QueueID: queueID})
	s2, _ := storage.Subscribe(ctx, t2.TopicID, &queue.SubscribeRequest{QueueID: queueID})

	inventory, err := storage.TopicInventory(ctx)
	if err != nil {
		t.Fatalf("topic inventory: %v", err)
	}
	wantCounts := map[string]int64{t1.TopicID: 1, t2.TopicID: 1, t3.TopicID: 0}
	if inventory.TopicsExist != 3 || !reflect.DeepEqual(inventory.SubscriptionCounts, wantCounts) {
		t.Fatalf("topic inventory = %#v, want counts %#v", inventory, wantCounts)
	}

	result, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true})
	if err != nil {
		t.Fatalf("delete queue: %v", err)
	}
	if got := subscriptionIDs(result.RemovedSubscriptions); !reflect.DeepEqual(got, []string{s1.SubscriptionID, s2.SubscriptionID}) {
		t.Fatalf("removed queue subscriptions = %v, want %v", got, []string{s1.SubscriptionID, s2.SubscriptionID})
	}
}

func TestStorageRolledBackDeleteCascadeReturnsNoEffects(t *testing.T) {
	ctx := context.Background()
	storage, conn := newPubSubStorage(t)
	topic, _ := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "rollback-topic"})
	queueID := createQueue(t, ctx, storage, "rollback-queue")
	_, _ = storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})

	if _, err := conn.ExecContext(ctx, `CREATE TRIGGER reject_topic_delete BEFORE DELETE ON topic_properties BEGIN SELECT RAISE(ABORT, 'reject'); END;`); err != nil {
		t.Fatalf("create topic delete trigger: %v", err)
	}
	result, err := storage.DeleteTopic(ctx, topic.TopicID)
	if err == nil || result != nil {
		t.Fatalf("rolled back topic delete = %#v, %v; want nil result and error", result, err)
	}
	if _, err := conn.ExecContext(ctx, `DROP TRIGGER reject_topic_delete; CREATE TRIGGER reject_queue_delete BEFORE DELETE ON queue_properties BEGIN SELECT RAISE(ABORT, 'reject'); END;`); err != nil {
		t.Fatalf("create queue delete trigger: %v", err)
	}
	queueResult, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true})
	if err == nil || queueResult != nil {
		t.Fatalf("rolled back queue delete = %#v, %v; want nil result and error", queueResult, err)
	}
	inventory, err := storage.TopicInventory(ctx)
	if err != nil || inventory.SubscriptionCounts[topic.TopicID] != 1 {
		t.Fatalf("inventory after rollbacks = %#v, %v", inventory, err)
	}
}

func newPubSubStorage(t *testing.T) (*Storage, *litekit.Conn) {
	t.Helper()
	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("open litekit connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	setupPubSubTables(t, ctx, conn)
	storage, err := New(conn)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	return storage, conn
}

func createQueue(t *testing.T, ctx context.Context, storage *Storage, name string) string {
	t.Helper()
	created, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: name})
	if err != nil {
		t.Fatalf("create queue %q: %v", name, err)
	}
	return created.QueueId
}

func subscriptionIDs(subscriptions []queue.Subscription) []string {
	ids := make([]string, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		ids = append(ids, subscription.SubscriptionID)
	}
	return ids
}

func setupPubSubTables(t *testing.T, ctx context.Context, conn *litekit.Conn) {
	t.Helper()

	const schema = `
create table if not exists "queue_properties"
(
    queue_id                   varchar(26)                         not null,
    queue_name                 text                                not null,
    created_at                 timestamp default current_timestamp not null,
    gc_at                      timestamp default current_timestamp not null,
    retention_period_seconds   integer                             not null,
    visibility_timeout_seconds integer                             not null,
    max_receive_attempts       integer                             not null,
    drop_policy                integer   default 0                 not null,
    dead_letter_queue_id       varchar(26),

    constraint queue_pk primary key (queue_id)
);

create table if not exists "topic_properties"
(
    topic_id   varchar(26)                         not null,
    topic_name text                                not null,
    created_at timestamp default current_timestamp not null,

    constraint topic_pk primary key (topic_id),
    constraint topic_name_unique unique (topic_name)
);

create table if not exists "topic_subscriptions"
(
    subscription_id varchar(26)                         not null,
    topic_id        varchar(26)                         not null,
    queue_id        varchar(26)                         not null,
    created_at      timestamp default current_timestamp not null,

    constraint topic_subscription_pk primary key (subscription_id),
    constraint topic_subscription_topic_fk foreign key (topic_id) references topic_properties (topic_id) on delete cascade,
    constraint topic_subscription_queue_fk foreign key (queue_id) references queue_properties (queue_id) on delete cascade,
    constraint topic_subscription_unique unique (topic_id, queue_id)
);
`

	if _, err := conn.ExecContext(ctx, schema); err != nil {
		t.Fatalf("setup pubsub tables: %v", err)
	}
}
