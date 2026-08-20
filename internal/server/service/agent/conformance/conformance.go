// Package conformance defines backend-neutral registry storage tests.
package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/service/agent"
)

const (
	tenantA                = "tenant-a"
	tenantB                = "tenant-b"
	plannerName            = "planner"
	alphaName              = "alpha"
	conformancePrincipalID = "conformance"
)

// RegistryFixture is the store surface shared by each backend fixture.
type RegistryFixture interface {
	agent.RegistryStore
	SeedOrganization(ctx context.Context, tenantID string) error
	SeedAgentPrincipal(ctx context.Context, tenantID, agentID string) error
	AgentPrincipal(ctx context.Context, tenantID, agentID string) (string, uint64, error)
}

// Factory constructs an isolated registry fixture for a conformance test.
type Factory func(*testing.T) RegistryFixture

// Registry exercises the registry contract against a storage backend.
//
//nolint:cyclop,funlen,gocognit,gocyclo,wsl_v5 // One shared suite intentionally holds all backend contract scenarios.
func Registry(t *testing.T, newStore Factory) {
	t.Helper()

	t.Run("same name is unique only inside tenant", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)

		if err := store.SeedOrganization(ctx, tenantA); err != nil {
			t.Fatalf("seed tenant-a: %v", err)
		}
		if err := store.SeedOrganization(ctx, tenantB); err != nil {
			t.Fatalf("seed tenant-b: %v", err)
		}

		_, err := store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000001",
			TenantID:    tenantA,
			Name:        plannerName,
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 1,
			CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
			CreatedAt:   time.Unix(100, 0).UTC(),
			UpdatedAt:   time.Unix(100, 0).UTC(),
		})
		if err != nil {
			t.Fatalf("create first tenant-a agent: %v", err)
		}

		_, err = store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000002",
			TenantID:    tenantA,
			Name:        plannerName,
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 1,
			CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
			CreatedAt:   time.Unix(101, 0).UTC(),
			UpdatedAt:   time.Unix(101, 0).UTC(),
		})
		if !errors.Is(err, agent.ErrAlreadyExists) {
			t.Fatalf("create duplicate tenant-a agent: got %v, want %v", err, agent.ErrAlreadyExists)
		}

		_, err = store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000003",
			TenantID:    tenantB,
			Name:        plannerName,
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 1,
			CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
			CreatedAt:   time.Unix(102, 0).UTC(),
			UpdatedAt:   time.Unix(102, 0).UTC(),
		})
		if err != nil {
			t.Fatalf("create tenant-b agent: %v", err)
		}
	})

	t.Run("create projects an active principal atomically", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		if err := store.SeedOrganization(ctx, tenantA); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}

		createdAt := time.Unix(200, 123).UTC()
		created, err := store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000011",
			TenantID:    tenantA,
			Name:        "builder",
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 7,
			CreatedBy:   principal.Ref{Kind: principal.KindHuman, ID: "admin-1"},
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		})
		if err != nil {
			t.Fatalf("create agent: %v", err)
		}
		if created.AgentID != "01J00000000000000000000011" || created.TenantID != tenantA ||
			created.Name != "builder" || created.Status != agentv1.AgentStatus_AGENT_STATUS_ACTIVE ||
			created.AuthVersion != 7 || !created.CreatedAt.Equal(createdAt) || !created.UpdatedAt.Equal(createdAt) {
			t.Fatalf("created agent = %#v, want deterministic input fields", created)
		}

		status, authVersion, err := store.AgentPrincipal(ctx, tenantA, created.AgentID)
		if err != nil {
			t.Fatalf("read principal projection: %v", err)
		}
		if status != "active" || authVersion != 7 {
			t.Fatalf("principal projection = (%q, %d), want (active, 7)", status, authVersion)
		}

		if err := store.SeedAgentPrincipal(ctx, tenantA, "01J00000000000000000000012"); err != nil {
			t.Fatalf("seed conflicting principal: %v", err)
		}
		_, err = store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000012",
			TenantID:    tenantA,
			Name:        "conflict",
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 1,
			CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		})
		if !errors.Is(err, agent.ErrAlreadyExists) {
			t.Fatalf("create with conflicting principal error = %v, want %v", err, agent.ErrAlreadyExists)
		}
		if _, err := store.GetAgent(ctx, tenantA, "01J00000000000000000000012"); !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("agent half persisted after projection conflict: %v", err)
		}
	})

	t.Run("lookups and status changes stay tenant scoped", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		if err := store.SeedOrganization(ctx, tenantA); err != nil {
			t.Fatalf("seed tenant-a: %v", err)
		}
		if err := store.SeedOrganization(ctx, tenantB); err != nil {
			t.Fatalf("seed tenant-b: %v", err)
		}

		createdAt := time.Unix(300, 0).UTC()
		created, err := store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000021",
			TenantID:    tenantA,
			Name:        plannerName,
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 1,
			CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		})
		if err != nil {
			t.Fatalf("create agent: %v", err)
		}

		byID, err := store.GetAgent(ctx, tenantA, created.AgentID)
		if err != nil || byID.Name != plannerName {
			t.Fatalf("get by ID = %#v, %v", byID, err)
		}
		byName, err := store.GetAgentByName(ctx, tenantA, plannerName)
		if err != nil || byName.AgentID != created.AgentID {
			t.Fatalf("get by name = %#v, %v", byName, err)
		}
		if _, err := store.GetAgent(ctx, tenantB, created.AgentID); !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("cross-tenant get error = %v, want %v", err, agent.ErrNotFound)
		}

		disabledAt := time.Unix(301, 0).UTC()
		disabled, err := store.SetAgentStatus(ctx, agent.SetAgentStatusInput{
			TenantID: tenantA, AgentID: created.AgentID,
			Status: agentv1.AgentStatus_AGENT_STATUS_DISABLED, UpdatedAt: disabledAt,
		})
		if err != nil {
			t.Fatalf("disable agent: %v", err)
		}
		if disabled.DisabledAt == nil || !disabled.DisabledAt.Equal(disabledAt) {
			t.Fatalf("disabled_at = %v, want %v", disabled.DisabledAt, disabledAt)
		}
		status, _, err := store.AgentPrincipal(ctx, tenantA, created.AgentID)
		if err != nil || status != "disabled" {
			t.Fatalf("disabled principal status = %q, %v", status, err)
		}

		reenabled, err := store.SetAgentStatus(ctx, agent.SetAgentStatusInput{
			TenantID: tenantA, AgentID: created.AgentID,
			Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, UpdatedAt: time.Unix(302, 0).UTC(),
		})
		if err != nil || reenabled.DisabledAt != nil {
			t.Fatalf("reenable agent = %#v, %v", reenabled, err)
		}
		if _, err := store.SetAgentStatus(ctx, agent.SetAgentStatusInput{
			TenantID: tenantB, AgentID: created.AgentID,
			Status: agentv1.AgentStatus_AGENT_STATUS_DISABLED, UpdatedAt: time.Unix(303, 0).UTC(),
		}); !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("cross-tenant status error = %v, want %v", err, agent.ErrNotFound)
		}
	})

	t.Run("list uses tenant prefix and name ID keyset", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		if err := store.SeedOrganization(ctx, tenantA); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}

		for index, name := range []string{alphaName, "alpha-two", "beta"} {
			_, err := store.CreateAgent(ctx, agent.CreateAgentInput{
				AgentID:     []string{"01J00000000000000000000031", "01J00000000000000000000032", "01J00000000000000000000033"}[index],
				TenantID:    tenantA,
				Name:        name,
				Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
				AuthVersion: 1,
				CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
				CreatedAt:   time.Unix(int64(400+index), 0).UTC(),
				UpdatedAt:   time.Unix(int64(400+index), 0).UTC(),
			})
			if err != nil {
				t.Fatalf("create %s: %v", name, err)
			}
		}

		first, err := store.ListAgents(ctx, agent.ListAgentsInput{
			TenantID: tenantA, NamePrefix: alphaName, Limit: 1,
		})
		if err != nil {
			t.Fatalf("first page: %v", err)
		}
		if len(first.Agents) != 1 || first.Agents[0].Name != alphaName ||
			!first.HasMore || first.NextCursor == "" || first.TotalCount != 2 {
			t.Fatalf("first page = %#v, want alpha plus next cursor and total 2", first)
		}

		second, err := store.ListAgents(ctx, agent.ListAgentsInput{
			TenantID: tenantA, NamePrefix: alphaName,
			AfterName: first.Agents[0].Name, AfterID: first.Agents[0].AgentID, Limit: 2,
		})
		if err != nil {
			t.Fatalf("second page: %v", err)
		}
		if len(second.Agents) != 1 || second.Agents[0].Name != "alpha-two" ||
			second.HasMore || second.NextCursor != "" || second.TotalCount != 2 {
			t.Fatalf("second page = %#v, want alpha-two and no cursor", second)
		}
	})

	t.Run("missing tenant is not mistaken for uniqueness", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		_, err := store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000041",
			TenantID:    "tenant-missing",
			Name:        "orphan",
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 1,
			CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
			CreatedAt:   time.Unix(500, 0).UTC(),
			UpdatedAt:   time.Unix(500, 0).UTC(),
		})
		if !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("create without tenant error = %v, want %v", err, agent.ErrNotFound)
		}
	})
}
