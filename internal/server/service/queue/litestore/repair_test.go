package litestore

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/marsolab/plainq/internal/server/mutations"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/dbkit/litekit"
)

// legacyCreateQueueTable is queryCreateQueueTable as it shipped before
// updated_at was declared: the trigger maintains a column the table does not
// have, so any update against the table fails.
func legacyCreateQueueTable(queueID string) string {
	return `create table ` + queueID + `(
			msg_id     text not null,
			msg_body   blob not null,
			created_at int  default current_timestamp not null,
			visible_at int  default current_timestamp not null,
			retries    int  default 0 not null,

			constraint ` + queueID + `_queue_pk primary key (msg_id)
		);

		create trigger if not exists ` + queueID + `_update_msg_updated_at
			after update on ` + queueID + `
			for each row
		begin
			update ` + queueID + ` set updated_at = current_timestamp where msg_id = old.msg_id;
		end;
	`
}

func newTestStorage(t *testing.T, conn *litekit.Conn) *Storage {
	t.Helper()

	store, err := New(conn)
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}

	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close storage: %v", err)
		}
	})

	return store
}

func newMigratedConn(t *testing.T) *litekit.Conn {
	t.Helper()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}

	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close sqlite connection: %v", err)
		}
	})

	evolver, err := litekit.NewEvolver(conn, mutations.SqliteStorageMutations())
	if err != nil {
		t.Fatalf("new evolver: %v", err)
	}

	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("mutate schema: %v", err)
	}

	return conn
}

// TestSendReceiveDeleteRoundTrip covers the path that had no coverage and was
// broken twice over: the per-queue trigger referenced a column that did not
// exist, and Delete parsed message ids in a format Send never mints.
func TestSendReceiveDeleteRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStorage(t, newMigratedConn(t))

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "round-trip"})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	queueID := created.GetQueueId()
	body := []byte("payload")

	if _, err := store.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: body}},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	received, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil {
		t.Fatalf("receive: %v", err)
	}

	messages := received.GetMessages()
	if len(messages) != 1 {
		t.Fatalf("received messages: got %d, want 1", len(messages))
	}

	if !bytes.Equal(messages[0].GetBody(), body) {
		t.Errorf("body: got %q, want %q", messages[0].GetBody(), body)
	}

	deleted, err := store.Delete(ctx, &v1.DeleteRequest{
		QueueId:    queueID,
		MessageIds: []string{messages[0].GetId()},
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	if got := deleted.GetSuccessful(); len(got) != 1 {
		t.Errorf("successful deletes: got %v, want 1 entry", got)
	}

	if got := deleted.GetFailed(); len(got) != 0 {
		t.Errorf("failed deletes: got %v, want none", got)
	}
}

// TestStorageReopensWithExistingQueues covers restart: opening the storage
// fills its cache from queue_properties, which failed on any queue with no
// dead-letter queue — the common case — and took server startup with it.
func TestStorageReopensWithExistingQueues(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn := newMigratedConn(t)

	first := newTestStorage(t, conn)

	if _, err := first.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "no-dlq"}); err != nil {
		t.Fatalf("create queue: %v", err)
	}

	second := newTestStorage(t, conn)

	listed, err := second.ListQueues(ctx, &v1.ListQueuesRequest{})
	if err != nil {
		t.Fatalf("list queues after reopen: %v", err)
	}

	if got := listed.GetQueues(); len(got) != 1 {
		t.Fatalf("queues after reopen: got %d, want 1", len(got))
	}

	if got := listed.GetQueues()[0].GetDeadLetterQueueId(); got != "" {
		t.Errorf("dead letter queue id: got %q, want empty", got)
	}
}

// TestRepairQueueTablesHealsLegacyTable builds a queue table in the old shape
// and checks that opening the storage makes it usable again.
func TestRepairQueueTablesHealsLegacyTable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn := newMigratedConn(t)

	// Create a queue, then swap its table for one in the pre-fix shape.
	store := newTestStorage(t, conn)

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "legacy"})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	queueID := created.GetQueueId()

	if _, err := conn.ExecContext(ctx, queryDeleteQueueTable(queueID)); err != nil {
		t.Fatalf("drop queue table: %v", err)
	}

	if _, err := conn.ExecContext(ctx, legacyCreateQueueTable(queueID)); err != nil {
		t.Fatalf("create legacy queue table: %v", err)
	}

	// Sanity check: the legacy table really is broken for receives.
	if _, err := conn.ExecContext(ctx,
		`insert into `+queueID+` (msg_id, msg_body) values ('01ARZ3NDEKTSV4RRFFQ69G5FAV', x'00')`,
	); err != nil {
		t.Fatalf("seed legacy table: %v", err)
	}

	if _, err := conn.ExecContext(ctx, queryUpdateMessagesVisibility(queueID, 1), 1, "01ARZ3NDEKTSV4RRFFQ69G5FAV"); err == nil {
		t.Fatal("update on legacy table: want error before repair, got nil")
	}

	// Opening the storage again runs the repair.
	repaired := newTestStorage(t, conn)

	got, err := repaired.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil {
		t.Fatalf("receive after repair: %v", err)
	}

	if len(got.GetMessages()) != 1 {
		t.Fatalf("received messages after repair: got %d, want 1", len(got.GetMessages()))
	}
}
