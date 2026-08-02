package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/marsolab/plainq/internal/server/config"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	queuestore "github.com/marsolab/plainq/internal/server/service/queue/litestore"
	"github.com/marsolab/servekit/logkit"
)

// tursoURLEnv points the integration test at a libSQL server. Any sqld will
// do, including a local container:
//
//	docker run -d -p 8080:8080 -e SQLD_NODE=primary ghcr.io/tursodatabase/libsql-server:latest
//	PLAINQ_TEST_TURSO_URL=http://127.0.0.1:8080 go test ./cmd/...
//
// The test is skipped when the variable is unset, so it stays out of the way
// of a plain `go test ./...`.
const (
	tursoURLEnv   = "PLAINQ_TEST_TURSO_URL"
	tursoTokenEnv = "PLAINQ_TEST_TURSO_AUTH_TOKEN"
)

// TestTursoBackendIntegration drives a real libSQL server through the same
// code path the server uses: open the backend, migrate the schema, then run
// queue operations against the litestore. It covers what unit tests against
// local SQLite cannot — the hrana wire protocol, batched multi-statement
// migrations, and the TIMESTAMP-to-time.Time round-trip.
func TestTursoBackendIntegration(t *testing.T) {
	t.Parallel()

	dbURL := os.Getenv(tursoURLEnv)
	if dbURL == "" {
		t.Skipf("%s is not set", tursoURLEnv)
	}

	cfg := config.Config{
		StorageDriver:         storageDriverTurso,
		StorageTursoURL:       dbURL,
		StorageTursoAuthToken: os.Getenv(tursoTokenEnv),
	}

	logger := logkit.NewNop()

	backend, err := initStorageBackend(&cfg, logger)
	if err != nil {
		t.Fatalf("init turso backend: %v", err)
	}

	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close backend: %v", err)
		}
	})

	if backend.driver != storageDriverTurso {
		t.Fatalf("driver: got %q, want %q", backend.driver, storageDriverTurso)
	}

	if got, want := schemaVersion(t, backend.turso), lastMutationVersion(t); got != want {
		t.Errorf("schema version: got %d, want %d", got, want)
	}

	ctx := context.Background()

	store, err := queuestore.New(backend.lite(), queuestore.WithLogger(slog.New(slog.DiscardHandler)))
	if err != nil {
		t.Fatalf("create queue storage: %v", err)
	}

	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close queue storage: %v", err)
		}
	})

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "integration"})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	queueID := created.GetQueueId()

	t.Cleanup(func() {
		if _, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID}); err != nil {
			t.Errorf("delete queue: %v", err)
		}
	})

	// DescribeQueue reads created_at out of a TIMESTAMP column, which is the
	// conversion that only works when the driver reports declared types.
	if _, err := store.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID}); err != nil {
		t.Fatalf("describe queue: %v", err)
	}

	body := []byte("hello from turso")

	if _, err := store.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: body}},
	}); err != nil {
		t.Fatalf("send message: %v", err)
	}

	received, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil {
		t.Fatalf("receive message: %v", err)
	}

	messages := received.GetMessages()
	if len(messages) != 1 {
		t.Fatalf("received messages: got %d, want 1", len(messages))
	}

	if !bytes.Equal(messages[0].GetBody(), body) {
		t.Errorf("message body: got %q, want %q", messages[0].GetBody(), body)
	}

	if _, err := store.Delete(ctx, &v1.DeleteRequest{
		QueueId:    queueID,
		MessageIds: []string{messages[0].GetId()},
	}); err != nil {
		t.Fatalf("delete message: %v", err)
	}

	// Opening a second storage over the same database exercises what only
	// happens on restart: filling the cache from queue_properties, and the
	// correlated pragma_table_info the queue-table repair runs. Both are
	// worth proving against the real wire protocol rather than local SQLite.
	reopened, err := queuestore.New(backend.lite(), queuestore.WithLogger(slog.New(slog.DiscardHandler)))
	if err != nil {
		t.Fatalf("reopen queue storage: %v", err)
	}

	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened queue storage: %v", err)
		}
	})

	listed, err := reopened.ListQueues(ctx, &v1.ListQueuesRequest{})
	if err != nil {
		t.Fatalf("list queues after reopen: %v", err)
	}

	if len(listed.GetQueues()) == 0 {
		t.Error("queues after reopen: got none, want the queue created above")
	}
}
