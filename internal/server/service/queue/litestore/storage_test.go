package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/maxatome/go-testdeep/td"
)

func TestStorageListQueuesHandlesNullableDeadLetterQueue(t *testing.T) {
	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	td.Require(t).CmpNoError(err, "open database")
	t.Cleanup(func() {
		td.CmpNoError(t, conn.Close(), "close database")
	})
	setupPubSubTables(t, ctx, conn)

	storage, err := New(conn)
	td.Require(t).CmpNoError(err, "create storage")
	t.Cleanup(func() {
		td.CmpNoError(t, storage.Close(), "close storage")
	})

	_, err = storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:      "drop-queue",
		EvictionPolicy: v1.EvictionPolicy_EVICTION_POLICY_DROP,
	})
	td.Require(t).CmpNoError(err, "create DROP queue")

	listed, err := storage.ListQueues(ctx, &v1.ListQueuesRequest{})
	td.Require(t).CmpNoError(err, "list queue with NULL dead-letter target")
	td.Require(t).Cmp(listed.GetQueues(), td.Len(1), "DROP queue is listed")
	td.Cmp(t, listed.GetQueues()[0].GetDeadLetterQueueId(), "", "DROP queue has no dead-letter target")

	dlq, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName: "dead-letter-queue",
	})
	td.Require(t).CmpNoError(err, "create dead-letter queue")

	parent, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:         "parent-queue",
		EvictionPolicy:    v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER,
		DeadLetterQueueId: dlq.GetQueueId(),
	})
	td.Require(t).CmpNoError(err, "create parent queue")

	listed, err = storage.ListQueues(ctx, &v1.ListQueuesRequest{})
	td.Require(t).CmpNoError(err, "list queues with dead-letter target")

	var foundParent *v1.DescribeQueueResponse
	for _, queue := range listed.GetQueues() {
		if queue.GetQueueId() == parent.GetQueueId() {
			foundParent = queue
			break
		}
	}
	td.Require(t).Cmp(foundParent, td.NotNil(), "parent queue is listed")
	td.Cmp(t, foundParent.GetDeadLetterQueueId(), dlq.GetQueueId(), "dead-letter target round-trips")
}

func TestStorageDescribeQueueByNameAndMissingQueue(t *testing.T) {
	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	td.Require(t).CmpNoError(err, "open database")
	t.Cleanup(func() {
		td.CmpNoError(t, conn.Close(), "close database")
	})
	setupPubSubTables(t, ctx, conn)

	storage, err := New(conn)
	td.Require(t).CmpNoError(err, "create storage")
	t.Cleanup(func() {
		td.CmpNoError(t, storage.Close(), "close storage")
	})

	created, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "platform.events"})
	td.Require(t).CmpNoError(err, "create queue")

	described, err := storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueName: "platform.events"})
	td.Require(t).CmpNoError(err, "describe queue by name")
	td.Cmp(t, described.GetQueueId(), created.GetQueueId())
	td.Cmp(t, described.GetQueueName(), "platform.events")

	_, err = storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueName: "not-created"})
	td.Cmp(t, errors.Is(err, pqerr.ErrNotFound), true, "missing queue maps to the domain not-found error")
}
