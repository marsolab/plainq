package litestore

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/service/agent"
	"github.com/marsolab/plainq/internal/server/service/agent/conformance"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/dbkit/litekit"
)

type registryFixture struct {
	*Storage
}

func (f *registryFixture) SeedOrganization(ctx context.Context, tenantID string) error {
	return pqlite.WithWriteTx(ctx, f.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO organizations (org_id, org_code, org_name)
			VALUES (?, ?, ?)`, tenantID, tenantID, tenantID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_quotas (
				tenant_id, max_agents, max_credentials_per_agent, max_queues, max_topics,
				max_subscriptions, max_message_bytes, max_stored_bytes, send_per_second,
				publish_per_second, updated_at_ns
			) VALUES (?, 10000, 2, 10000, 1000, 1000, 1048576, 10737418240, 1000, 1000, 0)`,
			tenantID,
		); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_resource_usage (
				tenant_id, agent_count, queue_count, topic_count, subscription_count,
				stored_messaging_bytes, updated_at_ns
			) VALUES (?, 0, 0, 0, 0, 0, 0)`, tenantID)

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

func TestCreateAgentAuditFailureRollsBackEveryPolicySideEffect(t *testing.T) {
	fixture, ok := newRegistryFixture(t).(*registryFixture)
	if !ok {
		t.Fatal("newRegistryFixture returned unexpected type")
	}
	ctx := context.Background()
	if err := fixture.SeedOrganization(ctx, "tenant-a"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	if _, err := fixture.db.ExecContext(ctx, `
		CREATE TRIGGER reject_agent_audit
		BEFORE INSERT ON security_audit_events
		BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END
	`); err != nil {
		t.Fatalf("create audit failure trigger: %v", err)
	}

	now := time.Unix(100, 0).UTC()
	_, err := fixture.CreateAgent(ctx, agent.CreateAgentInput{
		AgentID: "agent-a", TenantID: "tenant-a", Name: "worker-a",
		Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, AuthVersion: 1,
		CreatedBy: principal.Ref{Kind: principal.KindHuman, ID: "admin-a"},
		CreatedAt: now, UpdatedAt: now,
		Policy: testMutation("tenant-a", "admin-a", authz.ActionAgentCreate, authz.ResourceAgent, "agent-a", "create-a", now),
	})
	if err == nil {
		t.Fatal("CreateAgent() error = nil, want injected audit failure")
	}

	for table := range map[string]struct{}{
		"agents": {}, "security_principals": {}, "quota_windows": {}, "agent_idempotency": {}, "security_audit_events": {},
	} {
		var count int
		if err := fixture.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id = ?", "tenant-a").Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s count = %d, want 0", table, count)
		}
	}

	var agents int64
	if err := fixture.db.QueryRowContext(ctx, `
		SELECT agent_count FROM tenant_resource_usage WHERE tenant_id = ?
	`, "tenant-a").Scan(&agents); err != nil {
		t.Fatalf("read tenant usage: %v", err)
	}
	if agents != 0 {
		t.Fatalf("agent_count = %d, want 0", agents)
	}
}

func TestRegisterCredentialAuditFailureRollsBackEveryPolicySideEffect(t *testing.T) {
	fixture, ok := newRegistryFixture(t).(*registryFixture)
	if !ok {
		t.Fatal("newRegistryFixture returned unexpected type")
	}
	ctx := context.Background()
	if err := fixture.SeedOrganization(ctx, "tenant-a"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	createdAt := time.Unix(100, 0).UTC()
	if _, err := fixture.CreateAgent(ctx, agent.CreateAgentInput{
		AgentID: "agent-a", TenantID: "tenant-a", Name: "worker-a",
		Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, AuthVersion: 1,
		CreatedBy: principal.Ref{Kind: principal.KindHuman, ID: "admin-a"},
		CreatedAt: createdAt, UpdatedAt: createdAt,
		Policy: testMutation(
			"tenant-a", "admin-a", authz.ActionAgentCreate,
			authz.ResourceAgent, "agent-a", "create-agent-a", createdAt,
		),
	}); err != nil {
		t.Fatalf("create prerequisite agent: %v", err)
	}

	if _, err := fixture.db.ExecContext(ctx, `
		CREATE TRIGGER reject_credential_audit
		BEFORE INSERT ON security_audit_events
		WHEN NEW.action = 'credential.register'
		BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END
	`); err != nil {
		t.Fatalf("create credential audit failure trigger: %v", err)
	}

	registeredAt := createdAt.Add(2 * time.Second)
	hash := sha256.Sum256([]byte("credential-secret"))
	_, err := fixture.RegisterCredential(ctx, agent.RegisterCredentialInput{
		CredentialID: "credential-a", TenantID: "tenant-a", AgentID: "agent-a",
		Name: "primary", Prefix: "prefix-a", SecretHash: hash, CreatedAt: registeredAt,
		Policy: testMutation(
			"tenant-a", "admin-a", authz.ActionCredentialRegister,
			authz.ResourceAgent, "agent-a", "register-credential-a", registeredAt,
		),
	})
	if err == nil {
		t.Fatal("RegisterCredential() error = nil, want injected audit failure")
	}

	assertSQLiteCount(t, fixture.db, `
		SELECT count(*) FROM agent_credentials
		WHERE tenant_id = ? AND agent_id = ?`, 0, "tenant-a", "agent-a")
	assertSQLiteCount(t, fixture.db, `
		SELECT count(*) FROM quota_windows
		WHERE tenant_id = ? AND action = 'credential.register'`, 0, "tenant-a")
	assertSQLiteCount(t, fixture.db, `
		SELECT count(*) FROM agent_idempotency
		WHERE tenant_id = ? AND operation = 'credential.register'`, 0, "tenant-a")
	assertSQLiteCount(t, fixture.db, `
		SELECT count(*) FROM security_audit_events
		WHERE tenant_id = ? AND action = 'credential.register'`, 0, "tenant-a")
	assertSQLiteCount(t, fixture.db, `
		SELECT active_credential_count FROM agent_resource_usage
		WHERE tenant_id = ? AND agent_id = ?`, 0, "tenant-a", "agent-a")
}

func assertSQLiteCount(
	t *testing.T,
	db pqlite.DB,
	query string,
	want int,
	args ...any,
) {
	t.Helper()

	var got int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatalf("read sqlite count: %v", err)
	}
	if got != want {
		t.Fatalf("sqlite count = %d, want %d", got, want)
	}
}

func testMutation(
	tenantID, actorID string,
	action authz.Action,
	resourceType authz.ResourceType,
	resourceID, key string,
	now time.Time,
) policytx.Mutation {
	hash := sha256.Sum256([]byte(key))

	return policytx.Mutation{
		TenantID: tenantID, Actor: principal.Ref{Kind: principal.KindHuman, ID: actorID},
		Action: action, Resource: authz.Resource{Type: resourceType, TenantID: tenantID, ID: resourceID},
		IdempotencyKey: key, RequestHash: hash, RateUnits: 1,
		Audit: securityaudit.Event{
			EventID: "audit-" + key, TenantID: tenantID, ActorKind: principal.KindHuman, ActorID: actorID,
			Action: string(action), ResourceType: string(resourceType), ResourceID: resourceID,
			Outcome: "success", CreatedAt: now,
		},
	}
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
		Policy: testMutation(
			"tenant-a", "admin-a", authz.ActionAgentCreate,
			authz.ResourceAgent, "agent-a", "create-authorization-agent", createdAt,
		),
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

func TestGrantCRUDIsTenantScopedAndPolicyTransactional(t *testing.T) {
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

	now := time.Unix(1_000, 0).UTC()
	for index, input := range []struct {
		tenantID string
		agentID  string
		name     string
	}{
		{tenantID: "tenant-a", agentID: "agent-sender", name: "sender"},
		{tenantID: "tenant-a", agentID: "agent-target", name: "target"},
		{tenantID: "tenant-b", agentID: "agent-foreign", name: "foreign"},
	} {
		createdAt := now.Add(time.Duration(index) * time.Second)
		if _, err := fixture.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID: input.agentID, TenantID: input.tenantID, Name: input.name,
			Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, AuthVersion: 1,
			CreatedBy: principal.Ref{Kind: principal.KindHuman, ID: "admin"},
			CreatedAt: createdAt, UpdatedAt: createdAt,
			Policy: testMutation(
				input.tenantID, "admin", authz.ActionAgentCreate, authz.ResourceAgent,
				input.agentID, "create-grant-agent-"+input.agentID, createdAt,
			),
		}); err != nil {
			t.Fatalf("create grant fixture agent %q: %v", input.agentID, err)
		}
	}

	grantAt := now.Add(10 * time.Second)
	created, err := fixture.CreateGrant(ctx, agent.CreateGrantInput{
		GrantID: "grant-send", TenantID: "tenant-a", SubjectKind: principal.KindAgent,
		SubjectID: "agent-sender", ResourceKind: authz.ResourceAgent,
		ResourceID: "agent-target", Action: string(authz.ActionAgentSend), CreatedAt: grantAt,
		Policy: testMutation(
			"tenant-a", "admin", authz.ActionGrantManage, authz.ResourceTenant,
			"tenant-a", "create-grant-send", grantAt,
		),
	})
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if created.GrantID != "grant-send" || created.Action != string(authz.ActionAgentSend) {
		t.Fatalf("CreateGrant() = %#v", created)
	}

	page, err := fixture.ListGrants(ctx, agent.ListGrantsInput{TenantID: "tenant-a", Limit: 10})
	if err != nil || len(page.Grants) != 1 || page.Grants[0].GrantID != created.GrantID {
		t.Fatalf("ListGrants() = %#v, %v", page, err)
	}
	granted, err := fixture.HasGrant(ctx, principal.Principal{
		Kind: principal.KindAgent, ID: "agent-sender", TenantID: "tenant-a",
	}, authz.ActionAgentSend, authz.Resource{
		Type: authz.ResourceAgent, TenantID: "tenant-a", ID: "agent-target",
	})
	if err != nil || !granted {
		t.Fatalf("HasGrant() = %v, %v", granted, err)
	}

	for name, input := range map[string]agent.CreateGrantInput{
		"foreign subject": {
			GrantID: "grant-foreign-subject", TenantID: "tenant-a", SubjectKind: principal.KindAgent,
			SubjectID: "agent-foreign", ResourceKind: authz.ResourceAgent,
			ResourceID: "agent-target", Action: string(authz.ActionAgentSend), CreatedAt: grantAt,
			Policy: testMutation(
				"tenant-a", "admin", authz.ActionGrantManage, authz.ResourceTenant,
				"tenant-a", "grant-foreign-subject", grantAt,
			),
		},
		"foreign resource": {
			GrantID: "grant-foreign-resource", TenantID: "tenant-a", SubjectKind: principal.KindAgent,
			SubjectID: "agent-sender", ResourceKind: authz.ResourceAgent,
			ResourceID: "agent-foreign", Action: string(authz.ActionAgentSend), CreatedAt: grantAt,
			Policy: testMutation(
				"tenant-a", "admin", authz.ActionGrantManage, authz.ResourceTenant,
				"tenant-a", "grant-foreign-resource", grantAt,
			),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.CreateGrant(ctx, input); !errors.Is(err, agent.ErrNotFound) {
				t.Fatalf("CreateGrant() error = %v, want NotFound", err)
			}
		})
	}

	deleteAt := grantAt.Add(time.Second)
	deleteInput := agent.DeleteGrantInput{
		TenantID: "tenant-a", GrantID: "grant-send",
		Policy: testMutation(
			"tenant-a", "admin", authz.ActionGrantManage, authz.ResourceTenant,
			"tenant-a", "delete-grant-send", deleteAt,
		),
	}
	if err := fixture.DeleteGrant(ctx, deleteInput); err != nil {
		t.Fatalf("DeleteGrant() error = %v", err)
	}
	if err := fixture.DeleteGrant(ctx, deleteInput); err != nil {
		t.Fatalf("idempotent DeleteGrant() error = %v", err)
	}
	page, err = fixture.ListGrants(ctx, agent.ListGrantsInput{TenantID: "tenant-a", Limit: 10})
	if err != nil || len(page.Grants) != 0 {
		t.Fatalf("ListGrants() after delete = %#v, %v", page, err)
	}
}

func TestGrantAuditFailureRollsBackGrantAndPolicyRows(t *testing.T) {
	fixture, ok := newRegistryFixture(t).(*registryFixture)
	if !ok {
		t.Fatal("newRegistryFixture returned unexpected type")
	}
	ctx := context.Background()
	if err := fixture.SeedOrganization(ctx, "tenant-a"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	now := time.Unix(2_000, 0).UTC()
	if _, err := fixture.CreateAgent(ctx, agent.CreateAgentInput{
		AgentID: "agent-a", TenantID: "tenant-a", Name: "agent-a",
		Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, AuthVersion: 1,
		CreatedBy: principal.Ref{Kind: principal.KindHuman, ID: "admin"},
		CreatedAt: now, UpdatedAt: now,
		Policy: testMutation(
			"tenant-a", "admin", authz.ActionAgentCreate, authz.ResourceAgent,
			"agent-a", "create-grant-rollback-agent", now,
		),
	}); err != nil {
		t.Fatalf("create grant fixture agent: %v", err)
	}
	if _, err := fixture.db.ExecContext(ctx, `
		CREATE TRIGGER reject_grant_audit
		BEFORE INSERT ON security_audit_events
		WHEN NEW.action = 'grant.manage'
		BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END
	`); err != nil {
		t.Fatalf("create grant audit failure trigger: %v", err)
	}

	_, err := fixture.CreateGrant(ctx, agent.CreateGrantInput{
		GrantID: "grant-a", TenantID: "tenant-a", SubjectKind: principal.KindAgent,
		SubjectID: "agent-a", ResourceKind: authz.ResourceAgent,
		ResourceID: "agent-a", Action: string(authz.ActionAgentSend), CreatedAt: now.Add(time.Second),
		Policy: testMutation(
			"tenant-a", "admin", authz.ActionGrantManage, authz.ResourceTenant,
			"tenant-a", "create-grant-rollback", now.Add(time.Second),
		),
	})
	if err == nil {
		t.Fatal("CreateGrant() error = nil, want injected audit failure")
	}
	assertSQLiteCount(t, fixture.db, `
		SELECT count(*) FROM agent_resource_grants WHERE tenant_id = ?`, 0, "tenant-a")
	assertSQLiteCount(t, fixture.db, `
		SELECT count(*) FROM quota_windows
		WHERE tenant_id = ? AND action = 'grant.manage'`, 0, "tenant-a")
	assertSQLiteCount(t, fixture.db, `
		SELECT count(*) FROM agent_idempotency
		WHERE tenant_id = ? AND operation = 'grant.manage'`, 0, "tenant-a")
}
