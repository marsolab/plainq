package pgstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
)

func TestPostgresTestSchemaNameIsLowercase(t *testing.T) {
	got := postgresTestSchemaName("D5ABCDEF")
	if got != "plainq_pubsub_d5abcdef" {
		t.Fatalf("postgresTestSchemaName() = %q, want lowercase schema", got)
	}
}

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

func TestPostgresDeleteQueueRequiresForceForMessagesAndRollsBackEffects(t *testing.T) {
	ctx, storage, _, _ := newPostgresPubSubStorage(t)
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "force-safe"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "force-safe")
	subscription, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
	if err != nil {
		t.Fatalf("subscribe queue: %v", err)
	}
	if _, err := storage.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("must survive rejected delete")}},
	}); err != nil {
		t.Fatalf("send message: %v", err)
	}

	result, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID})
	if result != nil || !errors.Is(err, pqerr.ErrFailedPrecondition) {
		t.Fatalf("unforced non-empty delete = %#v, %v; want nil %v", result, err, pqerr.ErrFailedPrecondition)
	}
	if _, err := storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID}); err != nil {
		t.Fatalf("queue after rejected delete: %v", err)
	}
	inventory, err := storage.TopicInventory(ctx)
	if err != nil || inventory.SubscriptionCounts[topic.TopicID] != 1 {
		t.Fatalf("bindings after rejected delete = %#v, %v; want intact", inventory, err)
	}
	received, err := storage.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID})
	if err != nil || len(received.GetMessages()) != 1 {
		t.Fatalf("messages after rejected delete = %#v, %v; want one", received, err)
	}

	result, err = storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true})
	if err != nil {
		t.Fatalf("forced non-empty delete: %v", err)
	}
	if got := subscriptionIDs(result.RemovedSubscriptions); !reflect.DeepEqual(got, []string{subscription.SubscriptionID}) {
		t.Fatalf("forced delete effects = %v, want [%s]", got, subscription.SubscriptionID)
	}
}

func TestPostgresUnforcedDeleteExcludesConcurrentSend(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	queueID := createPostgresQueue(t, ctx, storage, "delete-send-race")
	const advisoryKey int64 = 82620267
	installBlockingQueueDeleteTrigger(t, ctx, pool, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	deleteDone := make(chan postgresQueueDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID})
		deleteDone <- postgresQueueDeleteOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "-- name: DeleteQueueProperties", "advisory")

	type sendOutcome struct {
		result *v1.SendResponse
		err    error
	}
	sendDone := make(chan sendOutcome, 1)
	go func() {
		result, err := storage.Send(ctx, &v1.SendRequest{
			QueueId:  queueID,
			Messages: []*v1.SendMessage{{Body: []byte("concurrent")}},
		})
		sendDone <- sendOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "INSERT INTO", "relation")
	commitPostgresBlocker(t, ctx, blocker)
	deleted := <-deleteDone
	sent := <-sendDone
	if deleted.err != nil || deleted.result == nil {
		t.Fatalf("delete that won table ownership = %#v, %v; want committed result", deleted.result, deleted.err)
	}
	if sent.result != nil || sent.err == nil {
		t.Fatalf("Send after committed queue delete = %#v, %v; want failure", sent.result, sent.err)
	}
}

func TestPostgresUnforcedDeleteSeesSendCommittedBeforeTableLock(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	queueID := createPostgresQueue(t, ctx, storage, "send-first-delete-race")

	sender, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin sender transaction: %v", err)
	}
	t.Cleanup(func() {
		if err := sender.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback sender transaction: %v", err)
		}
	})
	if _, err := sender.Exec(ctx, queryInsertMessagesBatch(queueID, 1), "send-first-message", []byte("message")); err != nil {
		t.Fatalf("insert uncommitted send: %v", err)
	}

	deleteDone := make(chan postgresQueueDeleteOutcome, 1)
	go func() {
		result, deleteErr := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID})
		deleteDone <- postgresQueueDeleteOutcome{result: result, err: deleteErr}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "LOCK TABLE", "relation")

	if err := sender.Commit(ctx); err != nil {
		t.Fatalf("commit sender transaction: %v", err)
	}
	deleted := <-deleteDone
	if deleted.result != nil || !errors.Is(deleted.err, pqerr.ErrFailedPrecondition) {
		t.Fatalf("delete after send-first lock drain = %#v, %v; want nil %v", deleted.result, deleted.err, pqerr.ErrFailedPrecondition)
	}
	if _, err := storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID}); err != nil {
		t.Fatalf("queue after rejected delete: %v", err)
	}
	var messageCount int64
	if err := pool.QueryRow(ctx, queryCountMessages(queueID)).Scan(&messageCount); err != nil || messageCount != 1 {
		t.Fatalf("messages after rejected delete = %d, %v; want one", messageCount, err)
	}
}

func TestPostgresDeleteTopicWaitsForUncommittedSubscribeBeforeCapture(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "topic-subscribe-race"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "topic-subscribe-race")
	const advisoryKey int64 = 82620261
	installBlockingSubscriptionTrigger(t, ctx, pool, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	subscribeDone := make(chan postgresSubscribeOutcome, 1)
	go func() {
		result, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
		subscribeDone <- postgresSubscribeOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "INSERT INTO topic_subscriptions", "advisory")

	deleteDone := make(chan postgresTopicDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteTopic(ctx, topic.TopicID)
		deleteDone <- postgresTopicDeleteOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "SELECT topic_id FROM topic_properties", "")
	commitPostgresBlocker(t, ctx, blocker)

	subscribed := <-subscribeDone
	if subscribed.err != nil {
		t.Fatalf("commit concurrent subscription: %v", subscribed.err)
	}
	deleted := <-deleteDone
	if deleted.err != nil {
		t.Fatalf("delete topic after subscription commit: %v", deleted.err)
	}
	if !slices.Contains(subscriptionIDs(deleted.result.RemovedSubscriptions), subscribed.result.SubscriptionID) {
		t.Fatalf("delete result %#v omitted committed subscription %q", deleted.result, subscribed.result.SubscriptionID)
	}
}

func TestPostgresDeleteQueueWaitsForUncommittedSubscribeBeforeCapture(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "queue-subscribe-race"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "queue-subscribe-race")
	const advisoryKey int64 = 82620262
	installBlockingSubscriptionTrigger(t, ctx, pool, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	subscribeDone := make(chan postgresSubscribeOutcome, 1)
	go func() {
		result, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
		subscribeDone <- postgresSubscribeOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "INSERT INTO topic_subscriptions", "advisory")

	deleteDone := make(chan postgresQueueDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true})
		deleteDone <- postgresQueueDeleteOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "SELECT queue_id FROM queue_properties", "")
	commitPostgresBlocker(t, ctx, blocker)

	subscribed := <-subscribeDone
	if subscribed.err != nil {
		t.Fatalf("commit concurrent subscription: %v", subscribed.err)
	}
	deleted := <-deleteDone
	if deleted.err != nil {
		if deleted.result != nil || !errors.Is(deleted.err, pqerr.ErrUnavailable) {
			t.Fatalf("aborted queue delete = %#v, %v; want nil result and %v", deleted.result, deleted.err, pqerr.ErrUnavailable)
		}
		assertPostgresParentAndSubscription(t, ctx, pool, "queue_properties", "queue_id", queueID, subscribed.result.SubscriptionID)
		return
	}
	if !slices.Contains(subscriptionIDs(deleted.result.RemovedSubscriptions), subscribed.result.SubscriptionID) {
		t.Fatalf("queue delete result %#v omitted committed subscription %q", deleted.result, subscribed.result.SubscriptionID)
	}
}

func TestPostgresTopicAndQueueDeleteOwnBindingEffectOnce(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "competing-deletes"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "competing-deletes")
	subscription, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	const advisoryKey int64 = 82620263
	installBlockingTopicDeleteTrigger(t, ctx, pool, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	topicDone := make(chan postgresTopicDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteTopic(ctx, topic.TopicID)
		topicDone <- postgresTopicDeleteOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "DELETE FROM topic_properties", "advisory")

	queueDone := make(chan postgresQueueDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true})
		queueDone <- postgresQueueDeleteOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "SELECT s.subscription_id", "")
	commitPostgresBlocker(t, ctx, blocker)

	topicDeleted := <-topicDone
	if topicDeleted.err != nil {
		t.Fatalf("delete topic: %v", topicDeleted.err)
	}
	queueDeleted := <-queueDone
	owned := subscriptionIDs(topicDeleted.result.RemovedSubscriptions)
	if queueDeleted.err != nil {
		if queueDeleted.result != nil || !errors.Is(queueDeleted.err, pqerr.ErrUnavailable) {
			t.Fatalf("aborted queue delete = %#v, %v; want nil result and %v", queueDeleted.result, queueDeleted.err, pqerr.ErrUnavailable)
		}
	} else {
		owned = append(owned, subscriptionIDs(queueDeleted.result.RemovedSubscriptions)...)
	}
	if countOccurrences(owned, subscription.SubscriptionID) != 1 {
		t.Fatalf("binding %q ownership across delete results = %v, want exactly once", subscription.SubscriptionID, owned)
	}
}

func TestPostgresDeleteAndUnsubscribeOwnBindingEffectOnce(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "delete-unsubscribe"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "delete-unsubscribe")
	subscription, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	const advisoryKey int64 = 82620264
	installBlockingTopicDeleteTrigger(t, ctx, pool, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	deleteDone := make(chan postgresTopicDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteTopic(ctx, topic.TopicID)
		deleteDone <- postgresTopicDeleteOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "DELETE FROM topic_properties", "advisory")

	unsubscribeDone := make(chan error, 1)
	go func() { unsubscribeDone <- storage.Unsubscribe(ctx, topic.TopicID, subscription.SubscriptionID) }()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "DELETE FROM topic_subscriptions", "")
	commitPostgresBlocker(t, ctx, blocker)

	deleted := <-deleteDone
	if deleted.err != nil {
		t.Fatalf("delete topic: %v", deleted.err)
	}
	if countOccurrences(subscriptionIDs(deleted.result.RemovedSubscriptions), subscription.SubscriptionID) != 1 {
		t.Fatalf("delete result %#v does not own binding exactly once", deleted.result)
	}
	if err := <-unsubscribeDone; !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("concurrent unsubscribe error = %v, want %v after delete owns effect", err, pqerr.ErrNotFound)
	}
}

func TestPostgresDeleteQueueAndUnsubscribeOwnBindingEffectOnce(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "queue-delete-unsubscribe"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	queueID := createPostgresQueue(t, ctx, storage, "queue-delete-unsubscribe")
	subscription, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	const advisoryKey int64 = 82620265
	installBlockingQueueDeleteTrigger(t, ctx, pool, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	deleteDone := make(chan postgresQueueDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true})
		deleteDone <- postgresQueueDeleteOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "-- name: DeleteQueueProperties", "advisory")

	unsubscribeDone := make(chan error, 1)
	go func() { unsubscribeDone <- storage.Unsubscribe(ctx, topic.TopicID, subscription.SubscriptionID) }()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "DELETE FROM topic_subscriptions", "")
	commitPostgresBlocker(t, ctx, blocker)

	deleted := <-deleteDone
	if deleted.err != nil {
		t.Fatalf("delete queue: %v", deleted.err)
	}
	if countOccurrences(subscriptionIDs(deleted.result.RemovedSubscriptions), subscription.SubscriptionID) != 1 {
		t.Fatalf("delete result %#v does not own binding exactly once", deleted.result)
	}
	if err := <-unsubscribeDone; !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("concurrent unsubscribe error = %v, want %v after queue delete owns effect", err, pqerr.ErrNotFound)
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

func TestPostgresStandaloneDeleteIsNotBoundByPeerEnvelope(t *testing.T) {
	ctx, storage, pool, _ := newPostgresPubSubStorage(t)

	queueName := strings.Repeat("q", 2000)
	createdQueue, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: queueName})
	if err != nil {
		t.Fatalf("create oversized-name queue: %v", err)
	}

	const subscriptionCount = 34_000
	if _, err := pool.Exec(ctx, `INSERT INTO topic_properties (topic_id, topic_name, created_at)
SELECT 'topic-' || lpad(i::text, 20, '0'), 'standalone-topic-' || i, TIMESTAMPTZ '2026-08-26 00:00:00Z' + i * INTERVAL '1 microsecond'
FROM generate_series(1, $1) AS i;`, subscriptionCount); err != nil {
		t.Fatalf("bulk-create standalone topics: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id, created_at)
SELECT 'sub-' || lpad(i::text, 22, '0'), 'topic-' || lpad(i::text, 20, '0'), $1, TIMESTAMPTZ '2026-08-26 00:00:00Z' + i * INTERVAL '1 microsecond'
FROM generate_series(1, $2) AS i;`, createdQueue.QueueId, subscriptionCount); err != nil {
		t.Fatalf("bulk-create standalone subscriptions: %v", err)
	}
	queueResult, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: createdQueue.QueueId, Force: true})
	if err != nil {
		t.Fatalf("standalone oversized queue delete: %v", err)
	}
	if len(queueResult.RemovedSubscriptions) != subscriptionCount {
		t.Fatalf("standalone queue delete returned %d subscriptions, want %d", len(queueResult.RemovedSubscriptions), subscriptionCount)
	}
	_, err = deleteresult.Marshal(queueResult, deleteresult.MaxEnvelopeBytes)
	var capacityErr *deleteresult.CapacityError
	if !errors.As(err, &capacityErr) {
		t.Fatalf("standalone queue delete result size check = %v, want over peer envelope", err)
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

	schema := postgresTestSchemaName(idkit.XID())
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

func postgresTestSchemaName(id string) string {
	return "plainq_pubsub_" + strings.ToLower(id)
}

type postgresSubscribeOutcome struct {
	result *queue.SubscribeResponse
	err    error
}

type postgresTopicDeleteOutcome struct {
	result *queue.DeleteTopicResult
	err    error
}

type postgresQueueDeleteOutcome struct {
	result *queue.DeleteQueueResult
	err    error
}

func installBlockingSubscriptionTrigger(t *testing.T, ctx context.Context, pool *pgxpool.Pool, advisoryKey int64) {
	t.Helper()
	query := fmt.Sprintf(`
CREATE FUNCTION block_subscription_insert() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  PERFORM pg_advisory_xact_lock(%d);
  RETURN NEW;
END;
$function$;
CREATE TRIGGER block_subscription_insert
AFTER INSERT ON topic_subscriptions
FOR EACH ROW EXECUTE FUNCTION block_subscription_insert();`, advisoryKey)
	if _, err := pool.Exec(ctx, query); err != nil {
		t.Fatalf("create blocking subscription trigger: %v", err)
	}
}

func installBlockingTopicDeleteTrigger(t *testing.T, ctx context.Context, pool *pgxpool.Pool, advisoryKey int64) {
	t.Helper()
	query := fmt.Sprintf(`
CREATE FUNCTION block_topic_delete() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  PERFORM pg_advisory_xact_lock(%d);
  RETURN OLD;
END;
$function$;
CREATE TRIGGER block_topic_delete
BEFORE DELETE ON topic_properties
FOR EACH ROW EXECUTE FUNCTION block_topic_delete();`, advisoryKey)
	if _, err := pool.Exec(ctx, query); err != nil {
		t.Fatalf("create blocking topic-delete trigger: %v", err)
	}
}

func installBlockingQueueDeleteTrigger(t *testing.T, ctx context.Context, pool *pgxpool.Pool, advisoryKey int64) {
	t.Helper()
	query := fmt.Sprintf(`
CREATE FUNCTION block_queue_delete() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  PERFORM pg_advisory_xact_lock(%d);
  RETURN OLD;
END;
$function$;
CREATE TRIGGER block_queue_delete
BEFORE DELETE ON queue_properties
FOR EACH ROW EXECUTE FUNCTION block_queue_delete();`, advisoryKey)
	if _, err := pool.Exec(ctx, query); err != nil {
		t.Fatalf("create blocking queue-delete trigger: %v", err)
	}
}

func holdPostgresAdvisoryLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, advisoryKey int64) pgx.Tx {
	t.Helper()
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin advisory blocker: %v", err)
	}
	t.Cleanup(func() {
		if err := blocker.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback advisory blocker: %v", err)
		}
	})
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryKey); err != nil {
		t.Fatalf("acquire advisory blocker: %v", err)
	}
	return blocker
}

func commitPostgresBlocker(t *testing.T, ctx context.Context, blocker pgx.Tx) {
	t.Helper()
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release advisory blocker: %v", err)
	}
}

func waitForPostgresQueryWait(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	applicationName string,
	queryPrefix string,
	waitEvent string,
) {
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
  AND left(query, length($2)) = $2
  AND wait_event_type = 'Lock'
  AND ($3 = '' OR wait_event = $3)
)`, applicationName, queryPrefix, waitEvent).Scan(&waiting); err != nil {
			t.Fatalf("inspect PostgreSQL query wait: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("PostgreSQL query %q did not reach expected lock wait", queryPrefix)
		case <-ctx.Done():
			t.Fatalf("wait for topic delete advisory trigger: %v", ctx.Err())
		}
	}
}

func countOccurrences(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
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
CREATE UNIQUE INDEX topic_subscriptions_topic_queue_uindex ON topic_subscriptions(topic_id, queue_id);
CREATE INDEX topic_subscriptions_queue_id_index ON topic_subscriptions(queue_id);`
	if _, err := pool.Exec(ctx, schema); err != nil {
		t.Fatalf("create test tables: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
}
