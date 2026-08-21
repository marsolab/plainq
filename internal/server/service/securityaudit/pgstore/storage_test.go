package pgstore

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

func TestStorageAppendAndListIsTenantScopedAndKeysetOrdered(t *testing.T) {
	store := newPostgresAuditStorage(t)
	ctx := context.Background()
	createdAt := time.Unix(100, 0).UTC()

	for _, event := range []securityaudit.Event{
		{EventID: "event-b", TenantID: "tenant-a", ActorKind: principal.KindHuman, ActorID: "admin-a", Action: "agent.create", ResourceType: "agent", ResourceID: "agent-b", Outcome: "success", CreatedAt: createdAt},
		{EventID: "event-a", TenantID: "tenant-a", ActorKind: principal.KindHuman, ActorID: "admin-a", Action: "agent.create", ResourceType: "agent", ResourceID: "agent-a", Outcome: "success", Metadata: map[string]string{"status": "active"}, CreatedAt: createdAt},
		{EventID: "event-c", TenantID: "tenant-b", ActorKind: principal.KindHuman, ActorID: "admin-b", Action: "agent.create", ResourceType: "agent", ResourceID: "agent-c", Outcome: "success", CreatedAt: createdAt},
	} {
		if err := store.Append(ctx, event); err != nil {
			t.Fatalf("Append(%q) error = %v", event.EventID, err)
		}
	}

	page, err := store.List(ctx, securityaudit.Query{TenantID: "tenant-a", Limit: 1})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].EventID != "event-a" || !page.HasMore {
		t.Fatalf("first page = %#v", page)
	}

	page, err = store.List(ctx, securityaudit.Query{
		TenantID: "tenant-a", AfterTime: createdAt.Format(time.RFC3339Nano), AfterID: "event-a", Limit: 10,
	})
	if err != nil {
		t.Fatalf("List(after) error = %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].EventID != "event-b" || page.HasMore {
		t.Fatalf("second page = %#v", page)
	}
}

func newPostgresAuditStorage(t *testing.T) *Storage {
	t.Helper()

	pool := newPostgresAuditPool(t)
	store, err := NewStorage(pool)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	return store
}

func newPostgresAuditPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PLAINQ_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres audit admin pool: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := fmt.Sprintf("security_audit_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatalf("create postgres audit schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop postgres audit schema: %v", err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse postgres audit DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open postgres audit pool: %v", err)
	}
	t.Cleanup(pool.Close)

	storageFS, err := mutations.ValidatedStorageFS(mutations.PostgresStorageMutations())
	if err != nil {
		t.Fatalf("validate postgres audit migrations: %v", err)
	}
	entries, err := fs.ReadDir(storageFS, ".")
	if err != nil {
		t.Fatalf("read postgres audit migrations: %v", err)
	}
	for _, entry := range entries {
		changes, err := fs.ReadFile(storageFS, entry.Name())
		if err != nil {
			t.Fatalf("read postgres audit migration %s: %v", entry.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(changes)); err != nil {
			t.Fatalf("apply postgres audit migration %s: %v", entry.Name(), err)
		}
	}

	return pool
}
