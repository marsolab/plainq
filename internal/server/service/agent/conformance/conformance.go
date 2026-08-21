// Package conformance defines backend-neutral registry storage tests.
package conformance

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/plainq/internal/server/service/agent"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
	"github.com/marsolab/plainq/internal/shared/pqerr"
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

// CredentialFixture is the store surface shared by credential backend fixtures.
type CredentialFixture interface {
	RegistryFixture
	agent.CredentialStore
	agent.PrincipalStore
	SetAgentPrincipalProjection(
		ctx context.Context,
		tenantID string,
		agentID string,
		status agentv1.AgentStatus,
		authVersion uint64,
	) error
}

// Factory constructs an isolated registry fixture for a conformance test.
type Factory func(*testing.T) RegistryFixture

// Credentials exercises credential persistence and idempotency against a storage backend.
//
//nolint:gocognit,funlen,cyclop,gocyclo,wsl_v5 // One shared suite intentionally holds all backend credential scenarios.
func Credentials(t *testing.T, newStore Factory) {
	t.Helper()

	t.Run("create lookup list touch and revoke stay tenant scoped", func(t *testing.T) {
		ctx := context.Background()
		store := requireCredentialFixture(t, newStore(t))
		createdAt := time.Unix(1_000, 0).UTC()
		agentA := seedCredentialAgent(t, ctx, store, tenantA, "01J00000000000000000000101", "credential-a", createdAt)
		_ = seedCredentialAgent(t, ctx, store, tenantB, "01J00000000000000000000102", "credential-b", createdAt)

		hash := [32]byte{1, 2, 3}
		expiresAt := createdAt.Add(time.Hour)

		created, err := store.CreateCredential(ctx, agent.CreateCredentialInput{
			CredentialID: "01J00000000000000000000111", TenantID: tenantA, AgentID: agentA.AgentID,
			Name: "runtime", Prefix: "pqac_01J00000000000000000000111", SecretHash: hash,
			CreatedAt: createdAt, ExpiresAt: &expiresAt,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialCreate,
				agentA.AgentID, "create-credential-111", createdAt,
			),
		})
		if err != nil {
			t.Fatalf("create credential: %v", err)
		}

		if created.CredentialID != "01J00000000000000000000111" || created.TenantID != tenantA ||
			created.AgentID != agentA.AgentID || created.Name != "runtime" || created.Prefix == "" ||
			len(created.SecretHash) != 32 || created.ExpiresAt == nil || !created.ExpiresAt.Equal(expiresAt) {
			t.Fatalf("created credential = %#v", created)
		}

		byPrefix, err := store.GetCredentialByPrefix(ctx, created.Prefix)
		if err != nil || byPrefix.CredentialID != created.CredentialID {
			t.Fatalf("get by prefix = %#v, %v", byPrefix, err)
		}
		if _, err := store.GetCredentialByPrefix(ctx, "pqac_missing"); !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("missing prefix error = %v, want %v", err, agent.ErrNotFound)
		}

		usedAt := createdAt.Add(time.Minute)
		if err := store.TouchCredential(ctx, agent.TouchCredentialInput{
			TenantID: tenantA, AgentID: agentA.AgentID, CredentialID: created.CredentialID, UsedAt: usedAt,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialExchange,
				agentA.AgentID, "touch-credential-111", usedAt,
			),
		}); err != nil {
			t.Fatalf("touch credential: %v", err)
		}
		page, err := store.ListCredentials(ctx, agent.ListCredentialsInput{
			TenantID: tenantA, AgentID: agentA.AgentID, Limit: 1,
		})
		if err != nil || len(page.Credentials) != 1 || page.Credentials[0].LastUsedAt == nil ||
			!page.Credentials[0].LastUsedAt.Equal(usedAt) {
			t.Fatalf("list touched credential = %#v, %v", page, err)
		}

		crossTenant, err := store.ListCredentials(ctx, agent.ListCredentialsInput{
			TenantID: tenantB, AgentID: agentA.AgentID, Limit: 10,
		})
		if err != nil || len(crossTenant.Credentials) != 0 {
			t.Fatalf("cross-tenant list = %#v, %v", crossTenant, err)
		}

		revokedAt := createdAt.Add(2 * time.Minute)
		if err := store.RevokeCredential(ctx, agent.RevokeCredentialInput{
			TenantID: tenantB, AgentID: agentA.AgentID, CredentialID: created.CredentialID, RevokedAt: revokedAt,
			Policy: agentMutation(
				tenantB, conformanceActor(), authz.ActionCredentialRevoke,
				agentA.AgentID, "cross-revoke-credential-111", revokedAt,
			),
		}); !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("cross-tenant revoke error = %v, want %v", err, agent.ErrNotFound)
		}

		if err := store.RevokeCredential(ctx, agent.RevokeCredentialInput{
			TenantID: tenantA, AgentID: agentA.AgentID, CredentialID: created.CredentialID, RevokedAt: revokedAt,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialRevoke,
				agentA.AgentID, "revoke-credential-111", revokedAt,
			),
		}); err != nil {
			t.Fatalf("revoke credential: %v", err)
		}
		if err := store.RevokeCredential(ctx, agent.RevokeCredentialInput{
			TenantID: tenantA, AgentID: agentA.AgentID, CredentialID: created.CredentialID, RevokedAt: revokedAt.Add(time.Minute),
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialRevoke,
				agentA.AgentID, "repeat-revoke-credential-111", revokedAt.Add(time.Minute),
			),
		}); err != nil {
			t.Fatalf("repeat revoke credential: %v", err)
		}

		revoked, err := store.GetCredentialByPrefix(ctx, created.Prefix)
		if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
			t.Fatalf("revoked credential = %#v, %v", revoked, err)
		}
		if err := store.TouchCredential(ctx, agent.TouchCredentialInput{
			TenantID: tenantA, AgentID: agentA.AgentID, CredentialID: created.CredentialID,
			UsedAt: revokedAt.Add(time.Minute),
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialExchange,
				agentA.AgentID, "touch-revoked-credential-111", revokedAt.Add(time.Minute),
			),
		}); !errors.Is(err, agent.ErrUnauthenticated) {
			t.Fatalf("touch revoked credential error = %v, want %v", err, agent.ErrUnauthenticated)
		}
	})

	t.Run("register is canonical and idempotent", func(t *testing.T) {
		ctx := context.Background()
		store := requireCredentialFixture(t, newStore(t))
		createdAt := time.Unix(2_000, 0).UTC()
		createdAgent := seedCredentialAgent(t, ctx, store, tenantA, "01J00000000000000000000121", "register", createdAt)
		expiresAt := createdAt.Add(2 * time.Hour)
		input := agent.RegisterCredentialInput{
			CredentialID: "01J00000000000000000000122", TenantID: tenantA, AgentID: createdAgent.AgentID,
			Name: "external", Prefix: "pqac_01J00000000000000000000122", SecretHash: [32]byte{4, 5, 6},
			CreatedAt: createdAt, ExpiresAt: &expiresAt,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialRegister,
				createdAgent.AgentID, "register-credential-122", createdAt,
			),
		}

		first, err := store.RegisterCredential(ctx, input)
		if err != nil || first.AlreadyExisted {
			t.Fatalf("first register = %#v, %v", first, err)
		}

		input.CreatedAt = createdAt.Add(time.Minute)

		second, err := store.RegisterCredential(ctx, input)
		if err != nil || !second.AlreadyExisted || !second.Credential.CreatedAt.Equal(createdAt) {
			t.Fatalf("repeat register = %#v, %v", second, err)
		}

		conflicts := map[string]func(*agent.RegisterCredentialInput){
			"tenant": func(i *agent.RegisterCredentialInput) { i.TenantID = tenantB },
			"agent":  func(i *agent.RegisterCredentialInput) { i.AgentID = "01J00000000000000000000999" },
			"name":   func(i *agent.RegisterCredentialInput) { i.Name = "other" },
			"hash":   func(i *agent.RegisterCredentialInput) { i.SecretHash[0]++ },
			"expiry": func(i *agent.RegisterCredentialInput) { value := expiresAt.Add(time.Second); i.ExpiresAt = &value },
		}
		for name, mutate := range conflicts {
			t.Run(name, func(t *testing.T) {
				conflict := input
				mutate(&conflict)
				conflict.Policy = agentMutation(
					conflict.TenantID, conformanceActor(), authz.ActionCredentialRegister,
					conflict.AgentID, "register-conflict-"+name, conflict.CreatedAt,
				)
				if _, err := store.RegisterCredential(ctx, conflict); !errors.Is(err, agent.ErrAlreadyExists) {
					t.Fatalf("register conflict error = %v, want %v", err, agent.ErrAlreadyExists)
				}
			})
		}
	})

	t.Run("concurrent identical registration converges on the canonical credential", func(t *testing.T) {
		ctx := context.Background()
		store := requireCredentialFixture(t, newStore(t))
		createdAt := time.Unix(2_500, 0).UTC()
		createdAgent := seedCredentialAgent(
			t, ctx, store, tenantA, "01J00000000000000000000123", "concurrent-register", createdAt,
		)
		expiresAt := createdAt.Add(2 * time.Hour)
		input := agent.RegisterCredentialInput{
			CredentialID: "01J00000000000000000000124", TenantID: tenantA, AgentID: createdAgent.AgentID,
			Name: "concurrent-external", Prefix: "pqac_01J00000000000000000000124", SecretHash: [32]byte{7, 8, 9},
			CreatedAt: createdAt, ExpiresAt: &expiresAt,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialRegister,
				createdAgent.AgentID, "register-credential-124", createdAt,
			),
		}

		const registrations = 8
		type registrationResult struct {
			result agent.RegisterCredentialResult
			err    error
		}
		start := make(chan struct{})
		results := make(chan registrationResult, registrations)
		for range registrations {
			go func() {
				<-start
				result, err := store.RegisterCredential(ctx, input)
				results <- registrationResult{result: result, err: err}
			}()
		}
		close(start)

		fresh := 0
		var firstErr error
		var wrongCredential *agent.CredentialRecord
		for range registrations {
			registration := <-results
			if registration.err != nil {
				if firstErr == nil {
					firstErr = registration.err
				}

				continue
			}
			if registration.result.Credential.CredentialID != input.CredentialID {
				if wrongCredential == nil {
					record := registration.result.Credential
					wrongCredential = &record
				}

				continue
			}
			if !registration.result.AlreadyExisted {
				fresh++
			}
		}
		if firstErr != nil {
			t.Fatalf("concurrent register error = %v", firstErr)
		}
		if wrongCredential != nil {
			t.Fatalf("concurrent register credential = %#v", *wrongCredential)
		}
		if fresh != 1 {
			t.Fatalf("fresh concurrent registrations = %d, want 1", fresh)
		}
	})

	t.Run("authentication immediately observes principal projection changes", func(t *testing.T) {
		ctx := context.Background()
		store := requireCredentialFixture(t, newStore(t))
		now := time.Unix(2_750, 0).UTC()
		createdAgent := seedCredentialAgent(
			t, ctx, store, tenantA, "01J00000000000000000000125", "projection-auth", now,
		)
		credentialID := "01J00000000000000000000126"
		_, err := store.CreateCredential(ctx, agent.CreateCredentialInput{
			CredentialID: credentialID, TenantID: tenantA, AgentID: createdAgent.AgentID,
			Name: "projection-runtime", Prefix: "pqac_" + credentialID, SecretHash: [32]byte{1}, CreatedAt: now,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialCreate,
				createdAgent.AgentID, "create-projection-credential", now,
			),
		})
		if err != nil {
			t.Fatalf("create projection credential: %v", err)
		}

		tokens, err := security.NewAgentTokenManager(security.AgentTokenConfig{
			Issuer: "plainq-conformance", Audience: "plainq-agent",
			Secret: []byte("0123456789abcdef0123456789abcdef"),
			Clock:  func() time.Time { return now },
			NextID: func() string { return "01J00000000000000000000127" },
		})
		if err != nil {
			t.Fatalf("create token manager: %v", err)
		}
		svc, err := agent.NewService(agent.ServiceConfig{
			Registry: store, Principals: store, Credentials: store, Tokens: tokens,
			Clock: func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("create agent service: %v", err)
		}
		raw, _, err := tokens.Issue(principal.Principal{
			Kind: principal.KindAgent, ID: createdAgent.AgentID, TenantID: tenantA,
			Roles: []string{"agent"}, CredentialID: credentialID, AuthVersion: 1,
		})
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		if _, err := svc.Authenticate(ctx, raw); err != nil {
			t.Fatalf("authenticate current projection: %v", err)
		}

		if err := store.SetAgentPrincipalProjection(
			ctx, tenantA, createdAgent.AgentID, agentv1.AgentStatus_AGENT_STATUS_DISABLED, 1,
		); err != nil {
			t.Fatalf("disable principal projection: %v", err)
		}
		registryRecord, err := store.GetAgent(ctx, tenantA, createdAgent.AgentID)
		if err != nil {
			t.Fatalf("read unchanged registry record: %v", err)
		}
		if registryRecord.Status != agentv1.AgentStatus_AGENT_STATUS_ACTIVE || registryRecord.AuthVersion != 1 {
			t.Fatalf("registry changed with projection-only mutation: %#v", registryRecord)
		}
		if _, err := svc.Authenticate(ctx, raw); !errors.Is(err, agent.ErrUnauthenticated) {
			t.Fatalf("authenticate disabled projection error = %v, want %v", err, agent.ErrUnauthenticated)
		}

		if err := store.SetAgentPrincipalProjection(
			ctx, tenantA, createdAgent.AgentID, agentv1.AgentStatus_AGENT_STATUS_ACTIVE, 2,
		); err != nil {
			t.Fatalf("bump principal projection auth version: %v", err)
		}
		if _, err := svc.Authenticate(ctx, raw); !errors.Is(err, agent.ErrUnauthenticated) {
			t.Fatalf("authenticate stale projection version error = %v, want %v", err, agent.ErrUnauthenticated)
		}
	})

	t.Run("active cap allows bounded rotation and ignores revoked or expired credentials", func(t *testing.T) {
		ctx := context.Background()
		store := requireCredentialFixture(t, newStore(t))
		now := time.Unix(3_000, 0).UTC()
		createdAgent := seedCredentialAgent(t, ctx, store, tenantA, "01J00000000000000000000131", "rotation", now)

		create := func(id, name string, at time.Time, expiresAt *time.Time) error {
			_, err := store.CreateCredential(ctx, agent.CreateCredentialInput{
				CredentialID: id, TenantID: tenantA, AgentID: createdAgent.AgentID, Name: name,
				Prefix: "pqac_" + id, SecretHash: sha256.Sum256([]byte(name)), CreatedAt: at, ExpiresAt: expiresAt,
				Policy: agentMutation(
					tenantA, conformanceActor(), authz.ActionCredentialCreate,
					createdAgent.AgentID, "create-capacity-"+id, at,
				),
			})
			if err != nil {
				return fmt.Errorf("create credential in capacity scenario: %w", err)
			}

			return nil
		}

		future := now.Add(time.Hour)
		if err := create("01J00000000000000000000132", "one", now, &future); err != nil {
			t.Fatalf("create first: %v", err)
		}
		if err := create("01J00000000000000000000133", "two", now, nil); err != nil {
			t.Fatalf("create second: %v", err)
		}

		if err := create("01J00000000000000000000134", "three", now, nil); !errors.Is(err, agent.ErrFailedPrecondition) {
			t.Fatalf("create above cap error = %v, want %v", err, agent.ErrFailedPrecondition)
		}
		if err := store.RevokeCredential(ctx, agent.RevokeCredentialInput{
			TenantID: tenantA, AgentID: createdAgent.AgentID, CredentialID: "01J00000000000000000000132", RevokedAt: now,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionCredentialRevoke,
				createdAgent.AgentID, "revoke-capacity-132", now,
			),
		}); err != nil {
			t.Fatalf("revoke first: %v", err)
		}
		if err := create("01J00000000000000000000134", "three", now.Add(time.Second), &future); err != nil {
			t.Fatalf("create after revoke: %v", err)
		}

		later := future.Add(time.Second)
		if err := create("01J00000000000000000000135", "four", later, nil); err != nil {
			t.Fatalf("create after expiry: %v", err)
		}
	})

	t.Run("list uses credential ID keyset", func(t *testing.T) {
		ctx := context.Background()
		store := requireCredentialFixture(t, newStore(t))
		now := time.Unix(4_000, 0).UTC()
		createdAgent := seedCredentialAgent(t, ctx, store, tenantA, "01J00000000000000000000141", "list-creds", now)

		for index, id := range []string{"01J00000000000000000000142", "01J00000000000000000000143"} {
			_, err := store.CreateCredential(ctx, agent.CreateCredentialInput{
				CredentialID: id, TenantID: tenantA, AgentID: createdAgent.AgentID,
				Name: []string{"first", "second"}[index], Prefix: "pqac_" + id,
				SecretHash: [32]byte{byte(index + 1)}, CreatedAt: now,
				Policy: agentMutation(
					tenantA, conformanceActor(), authz.ActionCredentialCreate,
					createdAgent.AgentID, "create-list-credential-"+id, now,
				),
			})
			if err != nil {
				t.Fatalf("create credential %d: %v", index, err)
			}
		}
		first, err := store.ListCredentials(ctx, agent.ListCredentialsInput{
			TenantID: tenantA, AgentID: createdAgent.AgentID, Limit: 1,
		})
		if err != nil || len(first.Credentials) != 1 || !first.HasMore ||
			first.NextCursor != first.Credentials[0].CredentialID {
			t.Fatalf("first credential page = %#v, %v", first, err)
		}

		second, err := store.ListCredentials(ctx, agent.ListCredentialsInput{
			TenantID: tenantA, AgentID: createdAgent.AgentID, AfterID: first.NextCursor, Limit: 1,
		})
		if err != nil || len(second.Credentials) != 1 || second.HasMore || second.NextCursor != "" {
			t.Fatalf("second credential page = %#v, %v", second, err)
		}
	})
}

func requireCredentialFixture(t *testing.T, fixture RegistryFixture) CredentialFixture {
	t.Helper()

	credentialFixture, ok := fixture.(CredentialFixture)
	if !ok {
		t.Fatal("registry fixture does not implement the credential contract")
	}

	return credentialFixture
}

func seedCredentialAgent(
	t *testing.T,
	ctx context.Context,
	store CredentialFixture,
	tenantID, agentID, name string,
	createdAt time.Time,
) agent.AgentRecord {
	t.Helper()

	if err := store.SeedOrganization(ctx, tenantID); err != nil {
		t.Fatalf("seed tenant %s: %v", tenantID, err)
	}

	record, err := store.CreateAgent(ctx, agent.CreateAgentInput{
		AgentID: agentID, TenantID: tenantID, Name: name,
		Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, AuthVersion: 1,
		CreatedBy: principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
		CreatedAt: createdAt, UpdatedAt: createdAt,
		Policy: agentMutation(
			tenantID, conformanceActor(), authz.ActionAgentCreate,
			agentID, "create-agent-"+agentID, createdAt,
		),
	})
	if err != nil {
		t.Fatalf("create credential test agent: %v", err)
	}

	return record
}

func conformanceActor() principal.Ref {
	return principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID}
}

func agentMutation(
	tenantID string,
	actor principal.Ref,
	action authz.Action,
	resourceID, key string,
	now time.Time,
) policytx.Mutation {
	hash := sha256.Sum256([]byte(key))

	return policytx.Mutation{
		TenantID: tenantID,
		Actor:    actor,
		Action:   action,
		Resource: authz.Resource{
			Type: authz.ResourceAgent, TenantID: tenantID, ID: resourceID,
		},
		IdempotencyKey: key,
		RequestHash:    hash,
		RateUnits:      1,
		Audit: securityaudit.Event{
			EventID: "audit-" + key, TenantID: tenantID, ActorKind: actor.Kind, ActorID: actor.ID,
			Action: string(action), ResourceType: string(authz.ResourceAgent), ResourceID: resourceID,
			Outcome: "success", CreatedAt: now,
		},
	}
}

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
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionAgentCreate,
				"01J00000000000000000000001", "create-registry-001", time.Unix(100, 0).UTC(),
			),
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
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionAgentCreate,
				"01J00000000000000000000002", "create-registry-002", time.Unix(101, 0).UTC(),
			),
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
			Policy: agentMutation(
				tenantB, conformanceActor(), authz.ActionAgentCreate,
				"01J00000000000000000000003", "create-registry-003", time.Unix(102, 0).UTC(),
			),
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
			Policy: agentMutation(
				tenantA, principal.Ref{Kind: principal.KindHuman, ID: "admin-1"},
				authz.ActionAgentCreate, "01J00000000000000000000011", "create-registry-011", createdAt,
			),
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
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionAgentCreate,
				"01J00000000000000000000012", "create-registry-012", createdAt,
			),
		})
		if !errors.Is(err, agent.ErrAlreadyExists) {
			t.Fatalf("create with conflicting principal error = %v, want %v", err, agent.ErrAlreadyExists)
		}
		if _, err := store.GetAgent(ctx, tenantA, "01J00000000000000000000012"); !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("agent half persisted after projection conflict: %v", err)
		}
	})

	t.Run("create rejects unspecified and unknown statuses", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		if err := store.SeedOrganization(ctx, tenantA); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}

		for _, testCase := range []struct {
			name    string
			agentID string
			status  agentv1.AgentStatus
		}{
			{
				name:    "unspecified",
				agentID: "01J00000000000000000000013",
				status:  agentv1.AgentStatus_AGENT_STATUS_UNSPECIFIED,
			},
			{
				name:    "unknown",
				agentID: "01J00000000000000000000014",
				status:  agentv1.AgentStatus(99),
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				createdAt := time.Unix(250, 0).UTC()
				_, err := store.CreateAgent(ctx, agent.CreateAgentInput{
					AgentID:     testCase.agentID,
					TenantID:    tenantA,
					Name:        "invalid-" + testCase.name,
					Status:      testCase.status,
					AuthVersion: 1,
					CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
					CreatedAt:   createdAt,
					UpdatedAt:   createdAt,
				})
				if !errors.Is(err, pqerr.ErrInvalidInput) {
					t.Fatalf("create status %d error = %v, want %v", testCase.status, err, pqerr.ErrInvalidInput)
				}
				if _, err := store.GetAgent(ctx, tenantA, testCase.agentID); !errors.Is(err, agent.ErrNotFound) {
					t.Fatalf("invalid-status agent persisted: %v", err)
				}
			})
		}
	})

	t.Run("status updates reject unspecified and unknown statuses", func(t *testing.T) {
		ctx := context.Background()
		store := newStore(t)
		if err := store.SeedOrganization(ctx, tenantA); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}

		createdAt := time.Unix(275, 0).UTC()
		created, err := store.CreateAgent(ctx, agent.CreateAgentInput{
			AgentID:     "01J00000000000000000000015",
			TenantID:    tenantA,
			Name:        "status-validation",
			Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
			AuthVersion: 1,
			CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionAgentCreate,
				"01J00000000000000000000015", "create-registry-015", createdAt,
			),
		})
		if err != nil {
			t.Fatalf("create agent: %v", err)
		}

		for _, status := range []agentv1.AgentStatus{
			agentv1.AgentStatus_AGENT_STATUS_UNSPECIFIED,
			agentv1.AgentStatus(99),
		} {
			_, err := store.SetAgentStatus(ctx, agent.SetAgentStatusInput{
				TenantID:  tenantA,
				AgentID:   created.AgentID,
				Status:    status,
				UpdatedAt: time.Unix(276, 0).UTC(),
			})
			if !errors.Is(err, pqerr.ErrInvalidInput) {
				t.Fatalf("update status %d error = %v, want %v", status, err, pqerr.ErrInvalidInput)
			}
		}

		unchanged, err := store.GetAgent(ctx, tenantA, created.AgentID)
		if err != nil {
			t.Fatalf("read unchanged agent: %v", err)
		}
		if unchanged.Status != agentv1.AgentStatus_AGENT_STATUS_ACTIVE ||
			!unchanged.UpdatedAt.Equal(createdAt) || unchanged.DisabledAt != nil {
			t.Fatalf("agent changed after invalid status update: %#v", unchanged)
		}
		principalStatus, _, err := store.AgentPrincipal(ctx, tenantA, created.AgentID)
		if err != nil || principalStatus != "active" {
			t.Fatalf("principal changed after invalid status update: status %q error %v", principalStatus, err)
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
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionAgentCreate,
				"01J00000000000000000000021", "create-registry-021", createdAt,
			),
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
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionAgentStatusSet,
				created.AgentID, "disable-registry-021", disabledAt,
			),
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
			Policy: agentMutation(
				tenantA, conformanceActor(), authz.ActionAgentStatusSet,
				created.AgentID, "enable-registry-021", time.Unix(302, 0).UTC(),
			),
		})
		if err != nil || reenabled.DisabledAt != nil {
			t.Fatalf("reenable agent = %#v, %v", reenabled, err)
		}
		if _, err := store.SetAgentStatus(ctx, agent.SetAgentStatusInput{
			TenantID: tenantB, AgentID: created.AgentID,
			Status: agentv1.AgentStatus_AGENT_STATUS_DISABLED, UpdatedAt: time.Unix(303, 0).UTC(),
			Policy: agentMutation(
				tenantB, conformanceActor(), authz.ActionAgentStatusSet,
				created.AgentID, "cross-disable-registry-021", time.Unix(303, 0).UTC(),
			),
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
			agentID := []string{"01J00000000000000000000031", "01J00000000000000000000032", "01J00000000000000000000033"}[index]
			createdAt := time.Unix(int64(400+index), 0).UTC()
			_, err := store.CreateAgent(ctx, agent.CreateAgentInput{
				AgentID:     agentID,
				TenantID:    tenantA,
				Name:        name,
				Status:      agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
				AuthVersion: 1,
				CreatedBy:   principal.Ref{Kind: principal.KindSystem, ID: conformancePrincipalID},
				CreatedAt:   createdAt,
				UpdatedAt:   createdAt,
				Policy: agentMutation(
					tenantA, conformanceActor(), authz.ActionAgentCreate,
					agentID, "create-list-agent-"+agentID, createdAt,
				),
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
			Policy: agentMutation(
				"tenant-missing", conformanceActor(), authz.ActionAgentCreate,
				"01J00000000000000000000041", "create-missing-agent", time.Unix(500, 0).UTC(),
			),
		})
		if !errors.Is(err, agent.ErrNotFound) {
			t.Fatalf("create without tenant error = %v, want %v", err, agent.ErrNotFound)
		}
	})
}
