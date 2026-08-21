package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	queueservice "github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/errkit"
	"github.com/maxatome/go-testdeep/td"
)

func TestTenantScopedQueuesAndLegacyCompatibility(t *testing.T) {
	ctx := context.Background()
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)
	if _, err := conn.ExecContext(ctx, `
INSERT INTO organizations (org_id, org_code, org_name, is_active)
VALUES ('tenant-b', 'tenant-b', 'Tenant B', TRUE)`); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	legacyCtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindSystem, ID: "legacy-v1", TenantID: principal.LegacyTenantID,
	})
	humanACtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindHuman, ID: "human-a", TenantID: principal.LegacyTenantID,
	})
	humanBCtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindHuman, ID: "human-b", TenantID: "tenant-b",
	})

	legacyQueue, err := store.CreateQueue(legacyCtx, &v1.CreateQueueRequest{QueueName: "shared"})
	if err != nil {
		t.Fatalf("create legacy queue: %v", err)
	}
	privateQueue, err := store.CreateQueue(humanACtx, &v1.CreateQueueRequest{QueueName: "private-a"})
	if err != nil {
		t.Fatalf("create human A queue: %v", err)
	}
	if _, err := store.CreateQueue(humanBCtx, &v1.CreateQueueRequest{QueueName: "shared"}); err != nil {
		t.Fatalf("same queue name in another tenant: %v", err)
	}

	legacyList, err := store.ListQueues(legacyCtx, &v1.ListQueuesRequest{Limit: 10})
	if err != nil {
		t.Fatalf("list legacy queues: %v", err)
	}
	if len(legacyList.GetQueues()) != 1 || legacyList.GetQueues()[0].GetQueueId() != legacyQueue.GetQueueId() {
		t.Fatalf("legacy queues = %#v, want only migration/legacy rows", legacyList.GetQueues())
	}
	if _, err := store.DescribeQueue(legacyCtx, &v1.DescribeQueueRequest{QueueId: privateQueue.GetQueueId()}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("legacy describe private queue error = %v, want not found", err)
	}
	if _, err := store.Send(humanBCtx, &v1.SendRequest{
		QueueId: privateQueue.GetQueueId(), Messages: []*v1.SendMessage{{Body: []byte("cross tenant")}},
	}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("cross-tenant send error = %v, want not found", err)
	}
}

func TestTenantScopedTopicsAndSubscriptions(t *testing.T) {
	ctx := context.Background()
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)
	if _, err := conn.ExecContext(ctx, `
INSERT INTO organizations (org_id, org_code, org_name, is_active)
VALUES ('tenant-b', 'tenant-b', 'Tenant B', TRUE)`); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	legacyCtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindSystem, ID: "legacy-v1", TenantID: principal.LegacyTenantID,
	})
	humanACtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindHuman, ID: "human-a", TenantID: principal.LegacyTenantID,
	})
	humanBCtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindHuman, ID: "human-b", TenantID: "tenant-b",
	})

	legacyQueue, err := store.CreateQueue(legacyCtx, &v1.CreateQueueRequest{QueueName: "legacy-destination"})
	if err != nil {
		t.Fatalf("create legacy queue: %v", err)
	}
	privateQueue, err := store.CreateQueue(humanACtx, &v1.CreateQueueRequest{QueueName: "private-destination"})
	if err != nil {
		t.Fatalf("create human A queue: %v", err)
	}
	legacyTopic, err := store.CreateTopic(legacyCtx, &queueservice.CreateTopicRequest{TopicName: "shared"})
	if err != nil {
		t.Fatalf("create legacy topic: %v", err)
	}
	privateTopic, err := store.CreateTopic(humanACtx, &queueservice.CreateTopicRequest{TopicName: "private-a"})
	if err != nil {
		t.Fatalf("create human A topic: %v", err)
	}
	if _, err := store.CreateTopic(humanBCtx, &queueservice.CreateTopicRequest{TopicName: "shared"}); err != nil {
		t.Fatalf("same topic name in another tenant: %v", err)
	}
	if _, err := store.Subscribe(legacyCtx, legacyTopic.TopicID, &queueservice.SubscribeRequest{QueueID: legacyQueue.GetQueueId()}); err != nil {
		t.Fatalf("subscribe legacy destination: %v", err)
	}

	legacyList, err := store.ListTopics(legacyCtx)
	if err != nil {
		t.Fatalf("list legacy topics: %v", err)
	}
	if len(legacyList.Topics) != 1 || legacyList.Topics[0].TopicID != legacyTopic.TopicID {
		t.Fatalf("legacy topics = %#v, want only migration/legacy rows", legacyList.Topics)
	}
	if _, err := store.Publish(humanBCtx, privateTopic.TopicID, &queueservice.PublishRequest{
		Messages: []queueservice.PublishMessage{{Body: []byte("cross tenant")}},
	}); !errors.Is(err, errkit.ErrNotFound) {
		t.Fatalf("cross-tenant publish error = %v, want not found", err)
	}
	if _, err := store.Subscribe(humanBCtx, privateTopic.TopicID, &queueservice.SubscribeRequest{
		QueueID: privateQueue.GetQueueId(),
	}); !errors.Is(err, errkit.ErrNotFound) {
		t.Fatalf("cross-tenant subscribe error = %v, want not found", err)
	}
}

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

func TestListQueuesTreatsPrefixAsLiteral(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t, newMigratedConn(t))

	for _, name := range []string{"literal%queue", "literalXqueue", "literal_queue", "literalAqueue"} {
		if _, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: name}); err != nil {
			t.Fatalf("create queue %q: %v", name, err)
		}
	}

	for _, prefix := range []string{"literal%", "literal_"} {
		t.Run(prefix, func(t *testing.T) {
			listed, err := store.ListQueues(ctx, &v1.ListQueuesRequest{QueuePrefix: prefix})
			if err != nil {
				t.Fatalf("list queues: %v", err)
			}

			if len(listed.GetQueues()) != 1 || listed.GetTotalCount() != 1 {
				t.Fatalf("prefix %q queues=%d total=%d, want 1 and 1", prefix, len(listed.GetQueues()), listed.GetTotalCount())
			}
		})
	}
}

func TestListQueuesTreatsPrefixAsCaseSensitive(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t, newMigratedConn(t))

	for _, name := range []string{"CaseQueue", "caseQueue"} {
		if _, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: name}); err != nil {
			t.Fatalf("create queue %q: %v", name, err)
		}
	}

	listed, err := store.ListQueues(ctx, &v1.ListQueuesRequest{QueuePrefix: "Case"})
	if err != nil {
		t.Fatalf("list queues: %v", err)
	}
	if len(listed.GetQueues()) != 1 || listed.GetTotalCount() != 1 || listed.GetQueues()[0].GetQueueName() != "CaseQueue" {
		t.Fatalf("case-sensitive prefix queues=%v total=%d, want CaseQueue only", listed.GetQueues(), listed.GetTotalCount())
	}
}
