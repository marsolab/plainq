package litestore

import (
	"context"
	"errors"
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

	evolver, err := litekit.NewEvolver(conn, mutations.StorageMutations())
	if err != nil {
		t.Fatalf("create schema evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("mutate schema: %v", err)
	}

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
