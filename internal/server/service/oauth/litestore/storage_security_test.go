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
}
