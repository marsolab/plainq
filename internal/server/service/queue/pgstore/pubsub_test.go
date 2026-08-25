package pgstore

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
)

func TestPostgresTopicConformance(t *testing.T) {
	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set PLAINQ_TEST_POSTGRES_DSN to run PostgreSQL pub/sub integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bootstrap, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open bootstrap PostgreSQL pool: %v", err)
	}
	defer bootstrap.Close()

	schema := "plainq_pubsub_" + idkit.XID()
	if _, err := bootstrap.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = bootstrap.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open test PostgreSQL pool: %v", err)
	}
	t.Cleanup(pool.Close)
	setupPostgresPubSub(t, ctx, pool)

	storage, err := New(pool)
	if err != nil {
		t.Fatalf("create PostgreSQL storage: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	if _, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: " "}); !errors.Is(err, pqerr.ErrInvalidInput) {
		t.Fatalf("blank topic error = %v, want %v", err, pqerr.ErrInvalidInput)
	}
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "events"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if _, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "events"}); !errors.Is(err, pqerr.ErrAlreadyExists) {
		t.Fatalf("duplicate topic error = %v, want %v", err, pqerr.ErrAlreadyExists)
	}
	zero, err := storage.Publish(ctx, topic.TopicID, &queue.PublishRequest{Messages: []queue.PublishMessage{{Body: []byte("zero")}}})
	if err != nil || zero.DeliveredCount != 0 {
		t.Fatalf("zero-subscription publish = %#v, %v", zero, err)
	}

	q1 := createPostgresQueue(t, ctx, storage, "one")
	q2 := createPostgresQueue(t, ctx, storage, "two")
	if _, err := storage.Subscribe(ctx, "missing", &queue.SubscribeRequest{QueueID: q1}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("subscribe missing topic error = %v, want %v", err, pqerr.ErrNotFound)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: "missing"}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("subscribe missing queue error = %v, want %v", err, pqerr.ErrNotFound)
	}
	s1, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: q1})
	if err != nil {
		t.Fatalf("subscribe first queue: %v", err)
	}
	s2, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: q2})
	if err != nil {
		t.Fatalf("subscribe second queue: %v", err)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: q1}); !errors.Is(err, pqerr.ErrAlreadyExists) {
		t.Fatalf("duplicate subscription error = %v, want %v", err, pqerr.ErrAlreadyExists)
	}
	if err := storage.Unsubscribe(ctx, topic.TopicID, "missing"); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("missing subscription error = %v, want %v", err, pqerr.ErrNotFound)
	}
	multi, err := storage.Publish(ctx, topic.TopicID, &queue.PublishRequest{Messages: []queue.PublishMessage{{Body: []byte("all")}}})
	if err != nil || multi.DeliveredCount != 2 {
		t.Fatalf("multi-subscription publish = %#v, %v", multi, err)
	}

	if _, err := pool.Exec(ctx, queryDeleteQueueTable(q1)); err != nil {
		t.Fatalf("break first destination: %v", err)
	}
	partial, err := storage.Publish(ctx, topic.TopicID, &queue.PublishRequest{Messages: []queue.PublishMessage{{Body: []byte("payload")}}})
	var partialErr *queue.PartialPublishError
	if !errors.As(err, &partialErr) || partial == nil || partial.DeliveredCount != 1 {
		t.Fatalf("partial publish = %#v, %v", partial, err)
	}

	deleted, err := storage.DeleteTopic(ctx, topic.TopicID)
	if err != nil {
		t.Fatalf("delete topic: %v", err)
	}
	gotIDs := []string{deleted.RemovedSubscriptions[0].SubscriptionID, deleted.RemovedSubscriptions[1].SubscriptionID}
	if !reflect.DeepEqual(gotIDs, []string{s1.SubscriptionID, s2.SubscriptionID}) {
		t.Fatalf("removed subscriptions = %v", gotIDs)
	}
	if _, err := storage.DeleteTopic(ctx, topic.TopicID); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("missing topic delete error = %v, want %v", err, pqerr.ErrNotFound)
	}

	firstTopic, _ := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "first-cascade"})
	secondTopic, _ := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "second-cascade"})
	emptyTopic, _ := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "empty"})
	shared := createPostgresQueue(t, ctx, storage, "shared")
	firstSub, _ := storage.Subscribe(ctx, firstTopic.TopicID, &queue.SubscribeRequest{QueueID: shared})
	secondSub, _ := storage.Subscribe(ctx, secondTopic.TopicID, &queue.SubscribeRequest{QueueID: shared})
	inventory, err := storage.TopicInventory(ctx)
	wantInventory := map[string]int64{firstTopic.TopicID: 1, secondTopic.TopicID: 1, emptyTopic.TopicID: 0}
	if err != nil || inventory.TopicsExist != 3 || !reflect.DeepEqual(inventory.SubscriptionCounts, wantInventory) {
		t.Fatalf("topic inventory = %#v, %v; want %#v", inventory, err, wantInventory)
	}
	queueResult, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: shared, Force: true})
	if err != nil {
		t.Fatalf("delete shared queue: %v", err)
	}
	queueIDs := []string{queueResult.RemovedSubscriptions[0].SubscriptionID, queueResult.RemovedSubscriptions[1].SubscriptionID}
	if !reflect.DeepEqual(queueIDs, []string{firstSub.SubscriptionID, secondSub.SubscriptionID}) {
		t.Fatalf("queue cascade subscriptions = %v", queueIDs)
	}
}

func createPostgresQueue(t *testing.T, ctx context.Context, storage *Storage, name string) string {
	t.Helper()
	created, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: name})
	if err != nil {
		t.Fatalf("create queue %q: %v", name, err)
	}
	return created.QueueId
}

func setupPostgresPubSub(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const schema = `
CREATE TABLE queue_properties (
  queue_id varchar(26) PRIMARY KEY, queue_name text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now() NOT NULL, gc_at timestamptz DEFAULT now() NOT NULL,
  retention_period_seconds integer NOT NULL, visibility_timeout_seconds integer NOT NULL,
  max_receive_attempts integer NOT NULL, drop_policy integer DEFAULT 0 NOT NULL,
  dead_letter_queue_id varchar(26)
);
CREATE TABLE topic_properties (
  topic_id varchar(26) PRIMARY KEY, topic_name text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now() NOT NULL
);
CREATE TABLE topic_subscriptions (
  subscription_id varchar(26) PRIMARY KEY,
  topic_id varchar(26) NOT NULL REFERENCES topic_properties(topic_id) ON DELETE CASCADE,
  queue_id varchar(26) NOT NULL REFERENCES queue_properties(queue_id) ON DELETE CASCADE,
  created_at timestamptz DEFAULT now() NOT NULL,
  UNIQUE(topic_id, queue_id)
);`
	if _, err := pool.Exec(ctx, schema); err != nil {
		t.Fatalf("create test tables: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
}
