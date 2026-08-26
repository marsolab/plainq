package litestore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestSyncOAuthUserUpsertsHumanSecurityPrincipal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db, err := litekit.New(filepath.Join(t.TempDir(), "oauth-security.db"))
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close SQLite: %v", err)
		}
	})

	if err := mutations.ApplySQLiteStorage(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	store, err := NewStorage(db, nil)
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}

	user := oauth.OAuthUser{Subject: "subject-1", Email: "oauth@example.com"}
	if err := store.SyncOAuthUser(ctx, user, "example", principal.LegacyTenantID); err != nil {
		t.Fatalf("sync OAuth user: %v", err)
	}

	synced, err := store.GetUserByOAuthSub(ctx, "example", user.Subject)
	if err != nil {
		t.Fatalf("get synchronized user: %v", err)
	}

	var tenantID, kind, status, rolesJSON string
	var authVersion int64
	if err := db.QueryRowContext(ctx, `
		SELECT tenant_id, principal_kind, status, roles_json, auth_version
		FROM security_principals
		WHERE principal_id = ?`, synced.UserID,
	).Scan(&tenantID, &kind, &status, &rolesJSON, &authVersion); err != nil {
		t.Fatalf("get human security principal: %v", err)
	}

	if tenantID != principal.LegacyTenantID || kind != "human" || status != "active" ||
		rolesJSON != "[]" || authVersion != 1 {
		t.Fatalf(
			"security principal = (%q, %q, %q, %s, %d), want (%q, human, active, [], 1)",
			tenantID, kind, status, rolesJSON, authVersion, principal.LegacyTenantID,
		)
	}

	const tenantB = "01J0000000000000000000000B"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO organizations (org_id, org_code, org_name)
		VALUES (?, 'tenant-b', 'Tenant B')`, tenantB); err != nil {
		t.Fatalf("create reassignment tenant: %v", err)
	}
	if err := store.SyncOAuthUser(ctx, user, "example", tenantB); err != nil {
		t.Fatalf("reassign OAuth user: %v", err)
	}

	var currentTenant string
	var currentVersion, oldProjectionCount, newProjectionCount int64
	if err := db.QueryRowContext(ctx, `
		SELECT org_id, auth_version FROM users WHERE user_id = ?`, synced.UserID,
	).Scan(&currentTenant, &currentVersion); err != nil {
		t.Fatalf("get reassigned OAuth user: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM security_principals
		WHERE tenant_id = ? AND principal_kind = 'human' AND principal_id = ?`,
		principal.LegacyTenantID, synced.UserID,
	).Scan(&oldProjectionCount); err != nil {
		t.Fatalf("count old human projection: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM security_principals
		WHERE tenant_id = ? AND principal_kind = 'human' AND principal_id = ? AND auth_version = 2`,
		tenantB, synced.UserID,
	).Scan(&newProjectionCount); err != nil {
		t.Fatalf("count new human projection: %v", err)
	}

	if currentTenant != tenantB || currentVersion != 2 || oldProjectionCount != 0 || newProjectionCount != 1 {
		t.Fatalf(
			"reassignment = tenant %q version %d old projections %d new projections %d, want %q/2/0/1",
			currentTenant, currentVersion, oldProjectionCount, newProjectionCount, tenantB,
		)
	}
}
