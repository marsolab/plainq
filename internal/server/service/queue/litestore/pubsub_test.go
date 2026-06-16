package litestore

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/errkit"
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
	applyStorageMutations(t, ctx, conn, "1_schema.sql", "4_pubsub.sql")

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
	if !errors.Is(err, errkit.ErrNotFound) {
		t.Fatalf("publish missing topic error = %v, want %v", err, errkit.ErrNotFound)
	}
}

func applyStorageMutations(t *testing.T, ctx context.Context, conn *litekit.Conn, names ...string) {
	t.Helper()

	storageMutations := mutations.StorageMutations()
	for _, name := range names {
		changes, err := fs.ReadFile(storageMutations, name)
		if err != nil {
			t.Fatalf("read storage mutation %s: %v", name, err)
		}
		if _, err := conn.ExecContext(ctx, string(changes)); err != nil {
			t.Fatalf("apply storage mutation %s: %v", name, err)
		}
	}
}
