package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestStorageReserveIsAtomicAndIdempotent(t *testing.T) {
	store := newQuotaStorage(t)
	ctx := context.Background()
	window := time.Unix(10, 0).UTC()

	first, err := store.Reserve(ctx, "tenant-a", authz.ActionAgentSend, 2, 2, "key-a", window)
	if err != nil {
		t.Fatalf("first Reserve() error = %v", err)
	}
	if first.Used != 2 || first.AlreadyConsumed {
		t.Fatalf("first Reserve() = %#v", first)
	}

	replay, err := store.Reserve(ctx, "tenant-a", authz.ActionAgentSend, 2, 2, "key-a", window)
	if err != nil {
		t.Fatalf("replay Reserve() error = %v", err)
	}
	if replay.Used != 2 || !replay.AlreadyConsumed {
		t.Fatalf("replay Reserve() = %#v", replay)
	}

	if _, err := store.Reserve(ctx, "tenant-a", authz.ActionAgentSend, 2, 1, "key-b", window); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("exhausted Reserve() error = %v", err)
	}
}

func newQuotaStorage(t *testing.T) *Storage {
	t.Helper()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "quota.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})

	storageFS, err := mutations.ValidatedStorageFS(mutations.SqliteStorageMutations())
	if err != nil {
		t.Fatalf("validate migrations: %v", err)
	}
	evolver, err := litekit.NewEvolver(conn, storageFS)
	if err != nil {
		t.Fatalf("create evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}

	if _, err := conn.ExecContext(context.Background(), `
		INSERT INTO organizations (org_id, org_code, org_name) VALUES (?, ?, ?)
	`, "tenant-a", "tenant-a", "Tenant A"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	store, err := NewStorage(conn)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	return store
}
