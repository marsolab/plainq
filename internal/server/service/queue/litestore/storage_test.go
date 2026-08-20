package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

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

func TestListQueuesCursorIsOpaqueAndStable(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t, newMigratedConn(t))

	for _, name := range []string{"alpha", "alpha-2", "omega"} {
		if _, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: name}); err != nil {
			t.Fatalf("create queue %q: %v", name, err)
		}
	}

	for _, orderBy := range []v1.ListQueuesRequest_OrderBy{
		v1.ListQueuesRequest_ORDER_BY_NAME,
		v1.ListQueuesRequest_ORDER_BY_CREATED_AT,
	} {
		t.Run(orderBy.String(), func(t *testing.T) {
			_, err := store.ListQueues(ctx, &v1.ListQueuesRequest{
				Limit:   2,
				OrderBy: orderBy,
				SortBy:  v1.ListQueuesRequest_SORT_BY_ASC,
				Cursor:  "x' OR 1=1 --",
			})
			if !errors.Is(err, pqerr.ErrInvalidInput) {
				t.Fatalf("injected cursor error = %v, want invalid input", err)
			}

			first, err := store.ListQueues(ctx, &v1.ListQueuesRequest{
				Limit: 2, OrderBy: orderBy, SortBy: v1.ListQueuesRequest_SORT_BY_ASC,
			})
			if err != nil {
				t.Fatalf("first page: %v", err)
			}

			if len(first.GetQueues()) != 2 || first.GetNextCursor() == "" {
				t.Fatalf("first page = %#v, want two queues and a cursor", first)
			}
			second, err := store.ListQueues(ctx, &v1.ListQueuesRequest{
				Limit: 2, OrderBy: orderBy, SortBy: v1.ListQueuesRequest_SORT_BY_ASC, Cursor: first.GetNextCursor(),
			})
			if err != nil {
				t.Fatalf("second page: %v", err)
			}

			if len(second.GetQueues()) != 1 {
				t.Fatalf("second page queues = %d, want 1", len(second.GetQueues()))
			}

			seen := map[string]bool{}
			for _, queue := range append(first.GetQueues(), second.GetQueues()...) {
				if seen[queue.GetQueueId()] {
					t.Fatalf("duplicate queue %q across pages", queue.GetQueueId())
				}
				seen[queue.GetQueueId()] = true
			}
		})
	}
}

func TestDeleteQueueRequiresForceWhenNonEmpty(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t, newMigratedConn(t))

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "not-empty"})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	queueID := created.GetQueueId()
	if _, err := store.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("payload")}},
	}); err != nil {
		t.Fatalf("send message: %v", err)
	}

	if _, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID}); !errors.Is(err, pqerr.ErrFailedPrecondition) {
		t.Fatalf("delete without force error = %v, want failed precondition", err)
	}

	if _, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true}); err != nil {
		t.Fatalf("delete with force: %v", err)
	}
}

func TestReceiveDeliversExactlyMaxReceiveAttempts(t *testing.T) {
	ctx := context.Background()
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:                "one-attempt",
		MaxReceiveAttempts:       1,
		VisibilityTimeoutSeconds: 1,
	})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	queueID := created.GetQueueId()
	if _, err := store.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("payload")}},
	}); err != nil {
		t.Fatalf("send message: %v", err)
	}

	first, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil {
		t.Fatalf("first receive: %v", err)
	}
	if len(first.GetMessages()) != 1 {
		t.Fatalf("first receive messages = %d, want 1", len(first.GetMessages()))
	}

	if _, err := conn.ExecContext(ctx, "update "+queueID+" set visible_at = ?", sqliteTime(time.Now().Add(-time.Second))); err != nil {
		t.Fatalf("make message visible: %v", err)
	}

	second, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil {
		t.Fatalf("second receive: %v", err)
	}
	if len(second.GetMessages()) != 0 {
		t.Fatalf("second receive messages = %d, want 0", len(second.GetMessages()))
	}
}

func TestListQueuesAppliesPrefixToPageAndTotal(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t, newMigratedConn(t))

	for _, name := range []string{"agent-alpha", "agent-omega", "billing"} {
		if _, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: name}); err != nil {
			t.Fatalf("create queue %q: %v", name, err)
		}
	}

	listed, err := store.ListQueues(ctx, &v1.ListQueuesRequest{
		QueuePrefix: "agent-",
		OrderBy:     v1.ListQueuesRequest_ORDER_BY_NAME,
		SortBy:      v1.ListQueuesRequest_SORT_BY_ASC,
	})
	if err != nil {
		t.Fatalf("list queues: %v", err)
	}

	if len(listed.GetQueues()) != 2 || listed.GetTotalCount() != 2 {
		t.Fatalf("list result queues=%d total=%d, want 2 and 2", len(listed.GetQueues()), listed.GetTotalCount())
	}
}
