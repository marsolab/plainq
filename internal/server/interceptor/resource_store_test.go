package interceptor

import (
	"context"
	"testing"

	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/agent"
)

type authorizationStoreStub struct {
	selector agent.AuthorizationResourceSelector
	grant    agent.ResourceGrantCheck
}

func (s *authorizationStoreStub) ResolveAuthorizationResource(
	_ context.Context,
	tenantID string,
	selector agent.AuthorizationResourceSelector,
) (agent.AuthorizationResource, error) {
	if tenantID != "tenant-a" {
		return agent.AuthorizationResource{}, agent.ErrNotFound
	}
	s.selector = selector

	return agent.AuthorizationResource{ID: "agent-b", OwnerAgentID: "agent-b"}, nil
}

func (s *authorizationStoreStub) HasResourceGrant(
	_ context.Context,
	check agent.ResourceGrantCheck,
) (bool, error) {
	s.grant = check

	return true, nil
}

func TestStoreResourceAuthorizerMapsPolicyProjection(t *testing.T) {
	t.Parallel()

	store := &authorizationStoreStub{}
	authorizer, err := NewStoreResourceAuthorizer(store)
	if err != nil {
		t.Fatalf("NewStoreResourceAuthorizer() error = %v", err)
	}

	resource, err := authorizer.ResolveResource(context.Background(), "tenant-a", ResourceSelector{
		Kind: ResourceAgent, ID: "agent-b",
	})
	if err != nil {
		t.Fatalf("ResolveResource() error = %v", err)
	}
	if resource.ID != "agent-b" || store.selector.Kind != agent.AuthorizationResourceAgent {
		t.Fatalf("resource = %#v, selector = %#v", resource, store.selector)
	}

	granted, err := authorizer.HasGrant(context.Background(), GrantCheck{
		TenantID: "tenant-a", SubjectKind: principal.KindAgent, SubjectID: "agent-a",
		ResourceKind: ResourceAgent, ResourceID: "agent-b", Action: "send",
	})
	if err != nil {
		t.Fatalf("HasGrant() error = %v", err)
	}
	if !granted || store.grant.ResourceKind != agent.AuthorizationResourceAgent {
		t.Fatalf("granted = %v, grant = %#v", granted, store.grant)
	}
}
