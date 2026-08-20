package litestore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/service/agent/conformance"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/dbkit/litekit"
)

type registryFixture struct {
	*Storage
}

func (f *registryFixture) SeedOrganization(ctx context.Context, tenantID string) error {
	return pqlite.WithWriteTx(ctx, f.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO organizations (org_id, org_code, org_name)
			VALUES (?, ?, ?)`, tenantID, tenantID, tenantID)
		return err
	})
}

func (f *registryFixture) SeedAgentPrincipal(ctx context.Context, tenantID, agentID string) error {
	return pqlite.WithWriteTx(ctx, f.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO security_principals (
				tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
			) VALUES (?, 'agent', ?, 'active', '["agent"]', 1, 0)`, tenantID, agentID)
		return err
	})
}

func (f *registryFixture) AgentPrincipal(ctx context.Context, tenantID, agentID string) (string, uint64, error) {
	var status string
	var authVersion int64
	err := f.db.QueryRowContext(ctx, `
		SELECT status, auth_version
		FROM security_principals
		WHERE tenant_id = ? AND principal_kind = 'agent' AND principal_id = ?`, tenantID, agentID,
	).Scan(&status, &authVersion)
	return status, uint64(authVersion), err
}

func newRegistryFixture(t *testing.T) conformance.RegistryFixture {
	t.Helper()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
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
		t.Fatalf("validate sqlite migrations: %v", err)
	}
	evolver, err := litekit.NewEvolver(conn, storageFS)
	if err != nil {
		t.Fatalf("create sqlite evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}

	store, err := NewStorage(conn)
	if err != nil {
		t.Fatalf("new sqlite registry storage: %v", err)
	}

	return &registryFixture{Storage: store}
}

func TestRegistry(t *testing.T) {
	conformance.Registry(t, newRegistryFixture)
}
