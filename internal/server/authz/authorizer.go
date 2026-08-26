package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

var (
	// ErrNotFound hides cross-tenant resource existence.
	ErrNotFound = pqerr.ErrNotFound
	// ErrPermissionDenied reports an authenticated but unauthorized caller.
	ErrPermissionDenied = pqerr.ErrUnauthorized
	// ErrUnauthenticated reports a missing or incomplete principal.
	ErrUnauthenticated = pqerr.ErrUnauthenticated
)

// PolicyStore reads both direct grants and effective permissions retained in
// the legacy role, organization, and team model.
type PolicyStore interface {
	HasGrant(ctx context.Context, p principal.Principal, action Action, resource Resource) (bool, error)
	HasLegacyPermission(ctx context.Context, p principal.Principal, action Action, resource Resource) (bool, error)
}

// Authorizer is the one shared tenant policy path used by every transport.
type Authorizer interface {
	Authorize(ctx context.Context, p principal.Principal, action Action, resource Resource) error
}

type authorizer struct {
	store PolicyStore
}

// NewAuthorizer constructs a fail-closed policy evaluator.
func NewAuthorizer(store PolicyStore) (Authorizer, error) {
	if store == nil {
		return nil, errors.New("authorization policy store is required")
	}

	return &authorizer{store: store}, nil
}

//nolint:cyclop // Authorization is an explicit fail-closed decision tree whose branches are security-significant.
func (a *authorizer) Authorize(
	ctx context.Context,
	p principal.Principal,
	action Action,
	resource Resource,
) error {
	if p.ID == "" || p.TenantID == "" {
		return ErrUnauthenticated
	}

	if resource.TenantID == "" || resource.TenantID != p.TenantID {
		return ErrNotFound
	}

	if !ActionSupportsResource(action, resource.Type) || resource.ID == "" {
		return fmt.Errorf("invalid authorization vocabulary: %w", ErrPermissionDenied)
	}

	if legacyCompatibilityPrincipal(p) {
		return nil
	}

	if implicitSelfAccess(p, action, resource) {
		return nil
	}

	granted, err := a.directGrant(ctx, p, action, resource)
	if err != nil {
		return fmt.Errorf("check direct grant: %w", err)
	}

	if granted {
		return nil
	}

	granted, err = a.legacyGrant(ctx, p, action, resource)
	if err != nil {
		return fmt.Errorf("check retained permission: %w", err)
	}

	if granted {
		return nil
	}

	return ErrPermissionDenied
}

func (a *authorizer) directGrant(
	ctx context.Context,
	p principal.Principal,
	action Action,
	resource Resource,
) (bool, error) {
	granted, err := a.store.HasGrant(ctx, p, action, resource)
	if err != nil || granted || resource.ID == "*" {
		return granted, wrapPolicyStoreError("check direct resource grant", err)
	}

	wildcard := resource
	wildcard.ID = "*"

	granted, err = a.store.HasGrant(ctx, p, action, wildcard)

	return granted, wrapPolicyStoreError("check wildcard direct grant", err)
}

func (a *authorizer) legacyGrant(
	ctx context.Context,
	p principal.Principal,
	action Action,
	resource Resource,
) (bool, error) {
	granted, err := a.store.HasLegacyPermission(ctx, p, action, resource)
	if err != nil || granted || resource.ID == "*" {
		return granted, wrapPolicyStoreError("check retained resource permission", err)
	}

	wildcard := resource
	wildcard.ID = "*"

	granted, err = a.store.HasLegacyPermission(ctx, p, action, wildcard)

	return granted, wrapPolicyStoreError("check wildcard retained permission", err)
}

func implicitSelfAccess(p principal.Principal, action Action, resource Resource) bool {
	if p.Kind != principal.KindAgent || resource.OwnerKind != principal.KindAgent || resource.OwnerID != p.ID {
		return false
	}

	switch action { //nolint:exhaustive // Only the explicit self-service action allowlist is permitted.
	case ActionAgentSend,
		ActionInboxReceive,
		ActionInboxAck,
		ActionInboxNack,
		ActionInboxExtend,
		ActionSubscriptionRead,
		ActionSubscriptionPull,
		ActionSubscriptionListen,
		ActionSubscriptionAck,
		ActionSubscriptionNack,
		ActionSubscriptionExtend:
		return true
	default:
		return false
	}
}

func wrapPolicyStoreError(operation string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %w", operation, err)
}

func legacyCompatibilityPrincipal(p principal.Principal) bool {
	return p.Kind == principal.KindSystem && p.ID == principal.LegacyPrincipalID &&
		p.TenantID == principal.LegacyTenantID
}
