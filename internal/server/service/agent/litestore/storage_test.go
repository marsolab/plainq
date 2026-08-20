package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/service/agent"
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

func (f *registryFixture) SetAgentPrincipalProjection(
	ctx context.Context,
	tenantID string,
	agentID string,
	status agentv1.AgentStatus,
	authVersion uint64,
) error {
	storedStatus := "active"
	if status == agentv1.AgentStatus_AGENT_STATUS_DISABLED {
		storedStatus = "disabled"
	}

	return pqlite.WithWriteTx(ctx, f.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE security_principals
			SET status = ?, auth_version = ?
			WHERE tenant_id = ? AND principal_kind = 'agent' AND principal_id = ?`,
			storedStatus, int64(authVersion), tenantID, agentID)
		return err
	})
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

func TestCredentials(t *testing.T) {
	conformance.Credentials(t, newRegistryFixture)
}

func TestAuthorizationStoreScopesAgentAndGrantByTenant(t *testing.T) {
	t.Parallel()

	fixture, ok := newRegistryFixture(t).(*registryFixture)
	if !ok {
		t.Fatal("newRegistryFixture returned unexpected type")
	}
	ctx := context.Background()
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		if err := fixture.SeedOrganization(ctx, tenantID); err != nil {
			t.Fatalf("seed organization %q: %v", tenantID, err)
		}
	}

	createdAt := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	_, err := fixture.CreateAgent(ctx, agent.CreateAgentInput{
		AgentID: "agent-a", TenantID: "tenant-a", Name: "worker-a",
		Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, AuthVersion: 1,
		CreatedBy: principal.Ref{Kind: principal.KindHuman, ID: "admin-a"},
		CreatedAt: createdAt, UpdatedAt: createdAt,
	})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}

	resource, err := fixture.ResolveAuthorizationResource(ctx, "tenant-a", agent.AuthorizationResourceSelector{
		Kind: agent.AuthorizationResourceAgent, Name: "worker-a",
	})
	if err != nil {
		t.Fatalf("ResolveAuthorizationResource() error = %v", err)
	}
	if resource.ID != "agent-a" || resource.OwnerAgentID != "agent-a" {
		t.Fatalf("resource = %#v", resource)
	}

	_, err = fixture.ResolveAuthorizationResource(ctx, "tenant-b", agent.AuthorizationResourceSelector{
		Kind: agent.AuthorizationResourceAgent, ID: "agent-a",
	})
	if !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("cross-tenant ResolveAuthorizationResource() error = %v, want NotFound", err)
	}

	_, err = fixture.db.ExecContext(ctx, `
		INSERT INTO agent_resource_grants (
			grant_id, tenant_id, subject_kind, subject_id, resource_kind, resource_id, action, created_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"grant-a", "tenant-a", "agent", "agent-sender", "agent", "agent-a", "send", createdAt.UnixNano(),
	)
	if err != nil {
		t.Fatalf("insert grant: %v", err)
	}

	granted, err := fixture.HasResourceGrant(ctx, agent.ResourceGrantCheck{
		TenantID: "tenant-a", SubjectKind: principal.KindAgent, SubjectID: "agent-sender",
		ResourceKind: agent.AuthorizationResourceAgent, ResourceID: "agent-a", Action: "send",
	})
	if err != nil {
		t.Fatalf("HasResourceGrant() error = %v", err)
	}
	if !granted {
		t.Fatal("HasResourceGrant() = false, want true")
	}

	granted, err = fixture.HasResourceGrant(ctx, agent.ResourceGrantCheck{
		TenantID: "tenant-b", SubjectKind: principal.KindAgent, SubjectID: "agent-sender",
		ResourceKind: agent.AuthorizationResourceAgent, ResourceID: "agent-a", Action: "send",
	})
	if err != nil {
		t.Fatalf("cross-tenant HasResourceGrant() error = %v", err)
	}
	if granted {
		t.Fatal("cross-tenant HasResourceGrant() = true, want false")
	}
}
