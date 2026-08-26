package pgstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/service/quota"
)

func TestStorageReserveIsAtomicAndIdempotent(t *testing.T) {
	store, pool := newPostgresQuotaStorage(t)
	ctx := context.Background()
	window := time.Unix(10, 0).UTC()

	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (org_id, org_code, org_name) VALUES ($1, $2, $3)
	`, "tenant-a", "tenant-a", "Tenant A"); err != nil {
		t.Fatalf("seed quota tenant: %v", err)
	}

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

func newPostgresQuotaStorage(t *testing.T) (*Storage, *pgxpool.Pool) {
	t.Helper()

	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PLAINQ_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres quota admin pool: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := fmt.Sprintf("quota_store_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatalf("create postgres quota schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop postgres quota schema: %v", err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse postgres quota DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open postgres quota pool: %v", err)
	}
	t.Cleanup(pool.Close)

	storageFS, err := mutations.ValidatedStorageFS(mutations.PostgresStorageMutations())
	if err != nil {
		t.Fatalf("validate postgres quota migrations: %v", err)
	}
	entries, err := fs.ReadDir(storageFS, ".")
	if err != nil {
		t.Fatalf("read postgres quota migrations: %v", err)
	}
	for _, entry := range entries {
		changes, err := fs.ReadFile(storageFS, entry.Name())
		if err != nil {
			t.Fatalf("read postgres quota migration %s: %v", entry.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(changes)); err != nil {
			t.Fatalf("apply postgres quota migration %s: %v", entry.Name(), err)
		}
	}

	store, err := NewStorage(pool)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	return store, pool
}
