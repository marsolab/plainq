package pgstore

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
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
	ctx, storage, pool, _ := newPostgresPubSubStorage(t)

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

	staleQueue := createPostgresQueue(t, ctx, storage, "stale-cache")
	if _, err := pool.Exec(ctx, `DELETE FROM queue_properties WHERE queue_id = $1`, staleQueue); err != nil {
		t.Fatalf("delete queue behind cache: %v", err)
	}
	staleResult, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: staleQueue, Force: true})
	if !errors.Is(err, pqerr.ErrNotFound) || staleResult != nil {
		t.Fatalf("delete stale cached queue = %#v, %v; want nil and %v", staleResult, err, pqerr.ErrNotFound)
	}
	if _, err := pool.Exec(ctx, queryDeleteQueueTable(staleQueue)); err != nil {
		t.Fatalf("drop stale queue table: %v", err)
	}
}

func TestPostgresDeleteTopicSerializesConcurrentSubscribe(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "concurrency-topic"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "concurrency-queue")

	const advisoryKey int64 = 82620261
	if _, err := pool.Exec(ctx, `
CREATE FUNCTION block_concurrency_topic_delete() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  IF OLD.topic_name = 'concurrency-topic' THEN
    PERFORM pg_advisory_xact_lock(82620261);
  END IF;
  RETURN OLD;
END;
$function$;
CREATE TRIGGER block_concurrency_topic_delete
BEFORE DELETE ON topic_properties
FOR EACH ROW EXECUTE FUNCTION block_concurrency_topic_delete();`); err != nil {
		t.Fatalf("create blocking topic-delete trigger: %v", err)
	}

	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin advisory blocker: %v", err)
	}
	t.Cleanup(func() { _ = blocker.Rollback(context.Background()) })
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryKey); err != nil {
		t.Fatalf("acquire advisory blocker: %v", err)
	}

	type deleteOutcome struct {
		result *queue.DeleteTopicResult
		err    error
	}
	type subscribeOutcome struct {
		result *queue.SubscribeResponse
		err    error
	}
	deleteDone := make(chan deleteOutcome, 1)
	go func() {
		result, err := storage.DeleteTopic(ctx, topic.TopicID)
		deleteDone <- deleteOutcome{result: result, err: err}
	}()
	waitForPostgresAdvisoryWait(t, ctx, pool, applicationName)

	subscribeDone := make(chan subscribeOutcome, 1)
	go func() {
		result, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
		subscribeDone <- subscribeOutcome{result: result, err: err}
	}()

	var earlySubscribe *subscribeOutcome
	select {
	case outcome := <-subscribeDone:
		earlySubscribe = &outcome
	case <-time.After(500 * time.Millisecond):
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release advisory blocker: %v", err)
	}

	deleted := <-deleteDone
	if deleted.err != nil {
		t.Fatalf("delete topic: %v", deleted.err)
	}
	var subscribed subscribeOutcome
	if earlySubscribe != nil {
		subscribed = *earlySubscribe
	} else {
		subscribed = <-subscribeDone
	}
	if subscribed.err == nil {
		if subscribed.result == nil || !slices.Contains(subscriptionIDs(deleted.result.RemovedSubscriptions), subscribed.result.SubscriptionID) {
			t.Fatalf("successful concurrent subscription %#v was removed but missing from delete result %#v", subscribed.result, deleted.result)
		}
		return
	}
	if !errors.Is(subscribed.err, pqerr.ErrNotFound) {
		t.Fatalf("concurrent subscribe error = %v, want %v", subscribed.err, pqerr.ErrNotFound)
	}
}

func TestPostgresDeleteRollbackReturnsNoEffects(t *testing.T) {
	ctx, storage, pool, _ := newPostgresPubSubStorage(t)

	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "rollback-topic"})
	if err != nil {
		t.Fatalf("create rollback topic: %v", err)
	}
	topicQueue := createPostgresQueue(t, ctx, storage, "rollback-topic-queue")
	topicSubscription, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: topicQueue})
	if err != nil {
		t.Fatalf("subscribe rollback topic: %v", err)
	}

	queueTopic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "rollback-queue-topic"})
	if err != nil {
		t.Fatalf("create rollback queue topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "rollback-queue")
	queueSubscription, err := storage.Subscribe(ctx, queueTopic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
	if err != nil {
		t.Fatalf("subscribe rollback queue: %v", err)
	}

	if _, err := pool.Exec(ctx, `
CREATE FUNCTION reject_named_topic_delete() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  IF OLD.topic_name = 'rollback-topic' THEN
    RAISE EXCEPTION 'reject rollback topic delete';
  END IF;
  RETURN OLD;
END;
$function$;
CREATE TRIGGER reject_named_topic_delete
AFTER DELETE ON topic_properties
FOR EACH ROW EXECUTE FUNCTION reject_named_topic_delete();

CREATE FUNCTION reject_named_queue_delete() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  IF OLD.queue_name = 'rollback-queue' THEN
    RAISE EXCEPTION 'reject rollback queue delete';
  END IF;
  RETURN OLD;
END;
$function$;
CREATE TRIGGER reject_named_queue_delete
AFTER DELETE ON queue_properties
FOR EACH ROW EXECUTE FUNCTION reject_named_queue_delete();`); err != nil {
		t.Fatalf("create rollback triggers: %v", err)
	}

	topicResult, err := storage.DeleteTopic(ctx, topic.TopicID)
	if err == nil || topicResult != nil {
		t.Fatalf("rolled-back topic delete = %#v, %v; want nil result and error", topicResult, err)
	}
	assertPostgresParentAndSubscription(t, ctx, pool, "topic_properties", "topic_id", topic.TopicID, topicSubscription.SubscriptionID)

	queueResult, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true})
	if err == nil || queueResult != nil {
		t.Fatalf("rolled-back queue delete = %#v, %v; want nil result and error", queueResult, err)
	}
	assertPostgresParentAndSubscription(t, ctx, pool, "queue_properties", "queue_id", queueID, queueSubscription.SubscriptionID)
}

func createPostgresQueue(t *testing.T, ctx context.Context, storage *Storage, name string) string {
	t.Helper()
	created, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: name})
	if err != nil {
		t.Fatalf("create queue %q: %v", name, err)
	}
	return created.QueueId
}

func newPostgresPubSubStorage(t *testing.T) (context.Context, *Storage, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set PLAINQ_TEST_POSTGRES_DSN to run PostgreSQL pub/sub integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	bootstrap, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open bootstrap PostgreSQL pool: %v", err)
	}
	t.Cleanup(bootstrap.Close)

	schema := "plainq_pubsub_" + idkit.XID()
	if _, err := bootstrap.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := bootstrap.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop PostgreSQL test schema %q: %v", schema, err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = schema
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
	t.Cleanup(func() {
		if err := storage.Close(); err != nil {
			t.Errorf("close PostgreSQL storage: %v", err)
		}
	})
	return ctx, storage, pool, schema
}

func waitForPostgresAdvisoryWait(t *testing.T, ctx context.Context, pool *pgxpool.Pool, applicationName string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
SELECT 1 FROM pg_stat_activity
WHERE application_name = $1
  AND query LIKE 'DELETE FROM topic_properties%'
  AND wait_event_type = 'Lock'
  AND wait_event = 'advisory'
)`, applicationName).Scan(&waiting); err != nil {
			t.Fatalf("inspect PostgreSQL advisory wait: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("topic delete did not reach advisory trigger")
		case <-ctx.Done():
			t.Fatalf("wait for topic delete advisory trigger: %v", ctx.Err())
		}
	}
}

func assertPostgresParentAndSubscription(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	parentTable string,
	parentColumn string,
	parentID string,
	subscriptionID string,
) {
	t.Helper()
	parentQuery := "SELECT EXISTS(SELECT 1 FROM " + pgx.Identifier{parentTable}.Sanitize() +
		" WHERE " + pgx.Identifier{parentColumn}.Sanitize() + " = $1)"
	var parentExists bool
	if err := pool.QueryRow(ctx, parentQuery, parentID).Scan(&parentExists); err != nil {
		t.Fatalf("check rolled-back parent: %v", err)
	}
	var subscriptionExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM topic_subscriptions WHERE subscription_id = $1)`, subscriptionID).Scan(&subscriptionExists); err != nil {
		t.Fatalf("check rolled-back subscription: %v", err)
	}
	if !parentExists || !subscriptionExists {
		t.Fatalf("rollback state parent=%t subscription=%t, want both true", parentExists, subscriptionExists)
	}
}

func subscriptionIDs(subscriptions []queue.Subscription) []string {
	ids := make([]string, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		ids = append(ids, subscription.SubscriptionID)
	}
	return ids
}

func setupPostgresPubSub(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const schema = `
CREATE TABLE queue_properties (
  queue_id varchar(26), queue_name text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now() NOT NULL, gc_at timestamptz DEFAULT now() NOT NULL,
  retention_period_seconds integer NOT NULL, visibility_timeout_seconds integer NOT NULL,
  max_receive_attempts integer NOT NULL, drop_policy integer DEFAULT 0 NOT NULL,
  dead_letter_queue_id varchar(26),
  CONSTRAINT queue_pk PRIMARY KEY (queue_id)
);
CREATE TABLE topic_properties (
  topic_id varchar(26), topic_name text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now() NOT NULL,
  CONSTRAINT topic_pk PRIMARY KEY (topic_id)
);
CREATE TABLE topic_subscriptions (
  subscription_id varchar(26),
  topic_id varchar(26) NOT NULL,
  queue_id varchar(26) NOT NULL,
  created_at timestamptz DEFAULT now() NOT NULL,
  CONSTRAINT topic_subscription_pk PRIMARY KEY (subscription_id),
  CONSTRAINT topic_subscription_topic_fk FOREIGN KEY (topic_id) REFERENCES topic_properties(topic_id) ON DELETE CASCADE,
  CONSTRAINT topic_subscription_queue_fk FOREIGN KEY (queue_id) REFERENCES queue_properties(queue_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX topic_subscriptions_topic_queue_uindex ON topic_subscriptions(topic_id, queue_id);`
	if _, err := pool.Exec(ctx, schema); err != nil {
		t.Fatalf("create test tables: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
}
