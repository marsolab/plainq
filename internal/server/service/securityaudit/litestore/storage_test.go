package litestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestStorageAppendAndListIsTenantScopedAndKeysetOrdered(t *testing.T) {
	store := newAuditStorage(t)
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

func newAuditStorage(t *testing.T) *Storage {
	t.Helper()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "audit.db"))
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

	store, err := NewStorage(conn)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	return store
}
