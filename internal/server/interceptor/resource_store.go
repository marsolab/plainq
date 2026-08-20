package interceptor

import (
	"context"
	"errors"
	"fmt"

	"github.com/marsolab/plainq/internal/server/service/agent"
)

// StoreResourceAuthorizer adapts the agent persistence authorization
// projection to the transport policy seam.
type StoreResourceAuthorizer struct {
	store agent.AuthorizationStore
}

// NewStoreResourceAuthorizer constructs a persistence-backed authorizer.
func NewStoreResourceAuthorizer(store agent.AuthorizationStore) (*StoreResourceAuthorizer, error) {
	if store == nil {
		return nil, errors.New("agent authorization store is required")
	}

	return &StoreResourceAuthorizer{store: store}, nil
}

// ResolveResource implements ResourceAuthorizer.
func (a *StoreResourceAuthorizer) ResolveResource(
	ctx context.Context,
	tenantID string,
	selector ResourceSelector,
) (Resource, error) {
	kind, err := authorizationResourceKind(selector.Kind)
	if err != nil {
		return Resource{}, err
	}

	resource, err := a.store.ResolveAuthorizationResource(ctx, tenantID, agent.AuthorizationResourceSelector{
		Kind: kind, ID: selector.ID, Name: selector.Name,
	})
	if err != nil {
		return Resource{}, fmt.Errorf("resolve persisted authorization resource: %w", err)
	}

	return Resource{ID: resource.ID, OwnerAgentID: resource.OwnerAgentID}, nil
}

// HasGrant implements ResourceAuthorizer.
func (a *StoreResourceAuthorizer) HasGrant(ctx context.Context, check GrantCheck) (bool, error) {
	kind, err := authorizationResourceKind(check.ResourceKind)
	if err != nil {
		return false, err
	}

	granted, err := a.store.HasResourceGrant(ctx, agent.ResourceGrantCheck{
		TenantID: check.TenantID, SubjectKind: check.SubjectKind, SubjectID: check.SubjectID,
		ResourceKind: kind, ResourceID: check.ResourceID, Action: check.Action,
	})
	if err != nil {
		return false, fmt.Errorf("check persisted authorization grant: %w", err)
	}

	return granted, nil
}

func authorizationResourceKind(kind ResourceKind) (agent.AuthorizationResourceKind, error) {
	switch kind {
	case ResourceAgent:
		return agent.AuthorizationResourceAgent, nil

	case ResourceTopic:
		return agent.AuthorizationResourceTopic, nil

	case ResourceSubscription:
		return agent.AuthorizationResourceSubscription, nil

	default:
		return "", errors.New("unsupported authorization resource kind")
	}
}
