package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
)

func newBootstrapStorage(t *testing.T) (*Storage, *litekit.Conn) {
	t.Helper()

	db, err := litekit.New(filepath.Join(t.TempDir(), "bootstrap.db"))
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close SQLite: %v", err)
		}
	})

	if err := mutations.ApplySQLiteStorage(context.Background(), db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	store, err := NewStorage(db, nil)
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}

	return store, db
}

func bootstrapRecord(id string) onboarding.BootstrapRecord {
	now := time.Now().UTC()

	return onboarding.BootstrapRecord{
		Admin: onboarding.InitialAdmin{
			UserID: id, Email: id + "@example.com", Password: "$2a$10$hash",
			Verified: true, CreatedAt: now, TenantID: principal.LegacyTenantID,
			AuthVersion: 1, Status: "active",
		},
		RefreshToken: onboarding.RefreshTokenRecord{
			ID: id + "-session", AccountID: id, TokenHash: []byte("01234567890123456789012345678901"),
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastUsedAt: now,
		},
		Audit: onboarding.AuditEvent{
			ID: id + "-audit", TenantID: principal.LegacyTenantID,
			PrincipalKind: "human", PrincipalID: id, Action: "onboarding.bootstrap",
			ResourceKind: "tenant", ResourceID: principal.LegacyTenantID,
			Outcome: "success", MetadataJSON: []byte(`{}`), CreatedAt: now,
		},
	}
}

func TestBootstrapIsSerializedAndAtomic(t *testing.T) {
	store, db := newBootstrapStorage(t)
	ctx := context.Background()

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"admin-a", "admin-b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			errs <- store.Bootstrap(ctx, bootstrapRecord(id))
		}(id)
	}
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, rejected int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, pqerr.ErrAlreadyExists):
			rejected++
		default:
			t.Fatalf("unexpected bootstrap result: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("bootstrap outcomes = (%d success, %d rejected), want (1, 1)", succeeded, rejected)
	}

	for table, want := range map[string]int{
		"users": 1, "user_roles": 1, "security_principals": 1,
		"refresh_tokens": 1, "security_audit_events": 1,
	} {
		var got int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if got != want {
			t.Fatalf("%s count = %d, want %d", table, got, want)
		}
	}
}

func TestBootstrapRollsBackEverySideEffect(t *testing.T) {
	store, db := newBootstrapStorage(t)
	ctx := context.Background()

	record := bootstrapRecord("admin-a")
	record.RefreshToken.TokenHash = []byte("not-a-sha256-digest")
	if err := store.Bootstrap(ctx, record); err == nil {
		t.Fatal("Bootstrap() unexpectedly succeeded with an invalid session digest")
	}

	for _, table := range []string{
		"users", "user_roles", "security_principals", "refresh_tokens", "security_audit_events",
	} {
		var got int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if got != 0 {
			t.Fatalf("%s count after rollback = %d, want 0", table, got)
		}
	}
}
