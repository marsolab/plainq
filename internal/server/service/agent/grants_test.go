package agent

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
)

func TestGrantServiceRequiresTenantAdminAndHidesCrossTenantResources(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	store := newGrantMemoryStore()
	svc.grants = store
	req := &agentv1.CreateGrantRequest{
		SubjectKind:  agentv1.PrincipalKind_PRINCIPAL_KIND_AGENT,
		SubjectId:    "agent-a",
		ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_AGENT,
		ResourceId:   "target-a",
		Action:       string(authz.ActionAgentSend),
	}
	if _, err := svc.CreateGrant(context.Background(), req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("anonymous CreateGrant() error = %v, want unauthenticated", err)
	}
	agentCtx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindAgent, ID: "agent-a", TenantID: "tenant-a", Roles: []string{"agent"},
	})
	if _, err := svc.CreateGrant(agentCtx, req); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("agent CreateGrant() error = %v, want permission denied", err)
	}

	adminCtx := metadata.NewIncomingContext(testAdminContext("tenant-a"), metadata.Pairs(
		"idempotency-key", "grant-request-1",
	))
	created, err := svc.CreateGrant(adminCtx, req)
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if created.GetGrant().GetGrantId() == "" || store.lastCreate.Policy.IdempotencyKey != "grant-request-1" ||
		store.lastCreate.Policy.Action != authz.ActionGrantManage ||
		store.lastCreate.Policy.Resource.Type != authz.ResourceTenant {
		t.Fatalf("created grant/policy = %#v / %#v", created.GetGrant(), store.lastCreate.Policy)
	}

	crossTenant := metadata.NewIncomingContext(testAdminContext("tenant-b"), metadata.Pairs(
		"idempotency-key", "grant-request-cross-tenant",
	))
	if _, err := svc.CreateGrant(crossTenant, req); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant CreateGrant() error = %v, want not found", err)
	}
	if _, err := svc.CreateGrant(adminCtx, &agentv1.CreateGrantRequest{
		SubjectKind: agentv1.PrincipalKind_PRINCIPAL_KIND_AGENT, SubjectId: "agent-a",
		ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_AGENT, ResourceId: "target-a",
		Action: "invented.action",
	}); err == nil {
		t.Fatal("CreateGrant() accepted an action outside the fixed vocabulary")
	}
}

func TestGrantServiceUsesOpaqueCursorAndAtomicDeleteInput(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	store := newGrantMemoryStore()
	svc.grants = store
	adminCtx := testAdminContext("tenant-a")
	created, err := svc.CreateGrant(adminCtx, &agentv1.CreateGrantRequest{
		SubjectKind: agentv1.PrincipalKind_PRINCIPAL_KIND_AGENT, SubjectId: "agent-a",
		ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_AGENT, ResourceId: "target-a",
		Action: string(authz.ActionAgentSend),
	})
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	page, err := svc.ListGrants(adminCtx, &agentv1.ListGrantsRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if len(page.GetGrants()) != 1 || !page.GetHasMore() || page.GetNextCursor() == "" ||
		page.GetNextCursor() == created.GetGrant().GetGrantId() {
		t.Fatalf("ListGrants() = %#v", page)
	}
	decoded, err := decodeGrantCursor(page.GetNextCursor())
	if err != nil || decoded != created.GetGrant().GetGrantId() {
		t.Fatalf("decoded cursor = %q, %v", decoded, err)
	}

	if _, err := svc.DeleteGrant(adminCtx, &agentv1.DeleteGrantRequest{
		GrantId: created.GetGrant().GetGrantId(),
	}); err != nil {
		t.Fatalf("DeleteGrant() error = %v", err)
	}
	if store.lastDelete.GrantID != created.GetGrant().GetGrantId() ||
		store.lastDelete.Policy.Resource.Type != authz.ResourceTenant {
		t.Fatalf("delete input = %#v", store.lastDelete)
	}
}

type grantMemoryStore struct {
	grants     []GrantRecord
	lastCreate CreateGrantInput
	lastDelete DeleteGrantInput
}

func newGrantMemoryStore() *grantMemoryStore {
	return &grantMemoryStore{}
}

func (s *grantMemoryStore) CreateGrant(_ context.Context, input CreateGrantInput) (GrantRecord, error) {
	s.lastCreate = input
	if input.TenantID != "tenant-a" || input.SubjectID != "agent-a" || input.ResourceID != "target-a" {
		return GrantRecord{}, ErrNotFound
	}
	record := GrantRecord{
		GrantID: input.GrantID, TenantID: input.TenantID, SubjectKind: input.SubjectKind,
		SubjectID: input.SubjectID, ResourceKind: input.ResourceKind, ResourceID: input.ResourceID,
		Action: input.Action, CreatedAt: input.CreatedAt,
	}
	s.grants = append(s.grants, record)

	return record, nil
}

func (s *grantMemoryStore) ListGrants(_ context.Context, input ListGrantsInput) (GrantPage, error) {
	if input.TenantID != "tenant-a" {
		return GrantPage{}, ErrNotFound
	}
	page := GrantPage{Grants: append([]GrantRecord(nil), s.grants...)}
	if len(page.Grants) > 0 {
		page.Grants = page.Grants[:1]
		page.HasMore = true
		page.NextCursor = page.Grants[0].GrantID
	}

	return page, nil
}

func (s *grantMemoryStore) DeleteGrant(_ context.Context, input DeleteGrantInput) error {
	s.lastDelete = input
	if input.TenantID != "tenant-a" || len(s.grants) == 0 || s.grants[0].GrantID != input.GrantID {
		return ErrNotFound
	}
	s.grants = nil

	return nil
}
