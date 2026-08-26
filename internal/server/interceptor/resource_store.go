package interceptor

import (
	"context"
	"errors"
	"fmt"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/agent"
)

// StoreResourceAuthorizer adapts the agent persistence authorization
// projection to the transport policy seam.
type StoreResourceAuthorizer struct {
	store      agent.AuthorizationStore
	authorizer authz.Authorizer
}

// NewStoreResourceAuthorizer constructs a persistence-backed authorizer.
func NewStoreResourceAuthorizer(store agent.AuthorizationStore) (*StoreResourceAuthorizer, error) {
	if store == nil {
		return nil, errors.New("agent authorization store is required")
	}

	policyStore, ok := store.(authz.PolicyStore)
	if !ok {
		return nil, errors.New("agent authorization store does not implement shared policy reads")
	}

	authorizer, err := authz.NewAuthorizer(policyStore)
	if err != nil {
		return nil, fmt.Errorf("create shared resource authorizer: %w", err)
	}

	return &StoreResourceAuthorizer{store: store, authorizer: authorizer}, nil
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
	resourceType, action, err := sharedGrantVocabulary(check.ResourceKind, check.Action)
	if err != nil {
		return false, err
	}

	resource := authz.Resource{Type: resourceType, TenantID: check.TenantID, ID: check.ResourceID}
	if resourceType == authz.ResourceAgent && check.SubjectKind == principal.KindAgent &&
		check.SubjectID == check.ResourceID {
		resource.OwnerKind = principal.KindAgent
		resource.OwnerID = check.ResourceID
	}

	err = a.authorizer.Authorize(ctx, principal.Principal{
		Kind: check.SubjectKind, ID: check.SubjectID, TenantID: check.TenantID,
	}, action, resource)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, authz.ErrPermissionDenied) {
		return false, nil
	}

	return false, fmt.Errorf("authorize persisted resource: %w", err)
}

func sharedGrantVocabulary(kind ResourceKind, action string) (authz.ResourceType, authz.Action, error) {
	switch {
	case kind == ResourceAgent && action == "send":
		return authz.ResourceAgent, authz.ActionAgentSend, nil
	case kind == ResourceTopic && action == "publish":
		return authz.ResourceTopic, authz.ActionTopicPublish, nil
	case kind == ResourceTopic && action == "subscribe":
		return authz.ResourceTopic, authz.ActionTopicSubscribe, nil
	default:
		return "", "", errors.New("unsupported authorization action")
	}
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
