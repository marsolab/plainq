package litestore

import (
	"context"
	"errors"
	"strings"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestDeletePreflightMatchesCanonicalTopicAndQueueEnvelopeBoundaries(t *testing.T) {
	ctx := context.Background()
	storage, _ := newPubSubStorage(t)
	queueID := createQueue(t, ctx, storage, "escaped-<>&-\"-\\-\u2028-\u2029-\ufffd")
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "preflight-boundary"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID}); err != nil {
		t.Fatalf("subscribe queue: %v", err)
	}
	subscriptions, err := listSubscriptions(ctx, storage.db, topic.TopicID, pubSubListTopics)
	if err != nil {
		t.Fatalf("list canonical subscriptions: %v", err)
	}

	topicEnvelope, err := deleteresult.Marshal(&queue.DeleteTopicResult{RemovedSubscriptions: subscriptions}, deleteresult.MaxEnvelopeBytes)
	if err != nil {
		t.Fatalf("marshal topic result: %v", err)
	}
	if err := storage.PreflightDeleteTopic(ctx, topic.TopicID, len(topicEnvelope)); err != nil {
		t.Fatalf("topic exact-boundary preflight: %v", err)
	}
	assertExactCapacityError(t, storage.PreflightDeleteTopic(ctx, topic.TopicID, len(topicEnvelope)-1))

	queueEnvelope, err := deleteresult.Marshal(&queue.DeleteQueueResult{RemovedSubscriptions: subscriptions}, deleteresult.MaxEnvelopeBytes)
	if err != nil {
		t.Fatalf("marshal queue result: %v", err)
	}
	request := &v1.DeleteQueueRequest{QueueId: queueID, Force: true}
	if err := storage.PreflightDeleteQueue(ctx, request, len(queueEnvelope)); err != nil {
		t.Fatalf("queue exact-boundary preflight: %v", err)
	}
	assertExactCapacityError(t, storage.PreflightDeleteQueue(ctx, request, len(queueEnvelope)-1))
}

func TestDeletePreflightStreamsWithoutOrderingSort(t *testing.T) {
	ctx := context.Background()
	storage, conn := newPubSubStorage(t)
	queueID := createQueue(t, ctx, storage, "stream-plan")
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "stream-plan"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID}); err != nil {
		t.Fatalf("subscribe queue: %v", err)
	}

	for name, test := range map[string]struct {
		query string
		arg   string
	}{
		"topic rows":        {query: topicDeleteRowsQuery, arg: topic.TopicID},
		"queue lower bound": {query: queueDeleteLowerBoundQuery, arg: queueID},
		"queue rows":        {query: queueDeleteRowsQuery, arg: queueID},
	} {
		t.Run(name, func(t *testing.T) {
			rows, err := conn.QueryContext(ctx, "EXPLAIN QUERY PLAN "+test.query, test.arg)
			if err != nil {
				t.Fatalf("explain preflight query: %v", err)
			}
			defer rows.Close()
			usesQueueIndex := false
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatalf("scan preflight query plan: %v", err)
				}
				if strings.Contains(strings.ToUpper(detail), "TEMP B-TREE") {
					t.Fatalf("preflight query materializes an ordering sort: %s", detail)
				}
				if strings.Contains(detail, "topic_subscriptions_queue_id_index") {
					usesQueueIndex = true
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("iterate preflight query plan: %v", err)
			}
			if strings.HasPrefix(name, "queue ") && !usesQueueIndex {
				t.Fatal("queue preflight query does not use topic_subscriptions_queue_id_index")
			}
		})
	}
}

func TestDeletePreflightLowerBoundRejectsBeforeMaterializingRows(t *testing.T) {
	ctx := context.Background()
	storage, conn := newPubSubStorage(t)
	queueID := createQueue(t, ctx, storage, strings.Repeat("large", 1_000))
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "lower-bound"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID}); err != nil {
		t.Fatalf("subscribe queue: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE topic_subscriptions SET created_at = X'FF' WHERE topic_id = ?;`, topic.TopicID); err != nil {
		t.Fatalf("corrupt timestamp behind lower-bound fixture: %v", err)
	}

	err = storage.PreflightDeleteTopic(ctx, topic.TopicID, 128)
	var capacityErr *deleteresult.CapacityError
	if !errors.As(err, &capacityErr) || !capacityErr.LowerBound {
		t.Fatalf("lower-bound preflight error = %#v, want lower-bound CapacityError", err)
	}
	err = storage.PreflightDeleteTopic(ctx, topic.TopicID, deleteresult.MaxEnvelopeBytes)
	if err == nil || errors.As(err, &capacityErr) {
		t.Fatalf("materializing preflight error = %#v, want timestamp scan error", err)
	}
}

func TestDeletePreflightExactEscapingRejectsRawFitPayload(t *testing.T) {
	ctx := context.Background()
	storage, conn := newPubSubStorage(t)
	queueID := createQueue(t, ctx, storage, strings.Repeat("<>&", 40))
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "escape-expansion"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID}); err != nil {
		t.Fatalf("subscribe queue: %v", err)
	}

	var count, rawBytes, named int64
	if err := conn.QueryRowContext(ctx, topicDeleteLowerBoundQuery, topic.TopicID).Scan(&count, &rawBytes, &named); err != nil {
		t.Fatalf("read test lower bound: %v", err)
	}
	lowerPayload := deleteresult.MinimumPayloadBytes(count, rawBytes, named)
	err = deleteresult.CheckPayloadLimit(lowerPayload, 0, true)
	var lower *deleteresult.CapacityError
	if !errors.As(err, &lower) {
		t.Fatalf("derive lower envelope error = %v", err)
	}

	err = storage.PreflightDeleteTopic(ctx, topic.TopicID, int(lower.EncodedBytes))
	var capacityErr *deleteresult.CapacityError
	if !errors.As(err, &capacityErr) || capacityErr.LowerBound || capacityErr.EncodedBytes <= lower.EncodedBytes {
		t.Fatalf("escaping preflight error = %#v, want exact size above raw lower bound %d", err, lower.EncodedBytes)
	}
}

func TestQueueDeletePreflightFailedPreconditionPrecedesCapacity(t *testing.T) {
	ctx := context.Background()
	storage, _ := newPubSubStorage(t)
	queueID := createQueue(t, ctx, storage, strings.Repeat("oversized", 100))
	topic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "force-precedence"})
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}
	if _, err := storage.Subscribe(ctx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID}); err != nil {
		t.Fatalf("subscribe queue: %v", err)
	}
	if _, err := storage.Send(ctx, &v1.SendRequest{QueueId: queueID, Messages: []*v1.SendMessage{{Body: []byte("message")}}}); err != nil {
		t.Fatalf("send message: %v", err)
	}

	err = storage.PreflightDeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID}, 1)
	var capacityErr *deleteresult.CapacityError
	if !errors.Is(err, pqerr.ErrFailedPrecondition) || errors.As(err, &capacityErr) {
		t.Fatalf("unforced preflight error = %#v, want failed precondition before capacity", err)
	}
	if err := storage.PreflightDeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true}, 1); !errors.As(err, &capacityErr) {
		t.Fatalf("forced preflight error = %#v, want capacity error", err)
	}
}

func assertExactCapacityError(t *testing.T, err error) {
	t.Helper()
	var capacityErr *deleteresult.CapacityError
	if !errors.As(err, &capacityErr) || capacityErr.LowerBound {
		t.Fatalf("preflight error = %#v, want exact CapacityError", err)
	}
}
