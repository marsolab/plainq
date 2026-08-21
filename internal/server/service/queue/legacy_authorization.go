package queue

import (
	"context"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/plainq/internal/server/principal"
)

// legacyServicePolicyAuthorizer keeps older injected Storage test doubles and
// third-party compatibility adapters on the Operations path. Production
// SQLite/PostgreSQL stores use authz.NewAuthorizer over durable grants.
type legacyServicePolicyAuthorizer struct {
	service *Service
}

func (a legacyServicePolicyAuthorizer) Authorize(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
) error {
	if resource.TenantID != p.TenantID {
		return authz.ErrNotFound
	}

	if resource.Type == authz.ResourceTenant || resource.Type == authz.ResourceTopic ||
		resource.Type == authz.ResourceSubscription {
		if p.HasRole("admin") {
			return nil
		}

		return authz.ErrPermissionDenied
	}

	permission, ok := legacyQueuePermissionForAction(action)
	if !ok {
		return authz.ErrPermissionDenied
	}

	allowed, err := a.service.HasQueuePermission(ctx, p.ID, resource.ID, permission)
	if err != nil {
		return err
	}

	if !allowed {
		return authz.ErrPermissionDenied
	}

	return nil
}

func legacyQueuePermissionForAction(action authz.Action) (middleware.PermissionType, bool) {
	switch action { //nolint:exhaustive // The retained RBAC adapter recognizes only legacy queue operations.
	case authz.ActionQueueRead, authz.ActionQueueReceive:
		return middleware.PermissionReceive, true
	case authz.ActionQueueSend:
		return middleware.PermissionSend, true
	case authz.ActionQueuePurge:
		return middleware.PermissionPurge, true
	case authz.ActionQueueDelete, authz.ActionQueueAck:
		return middleware.PermissionDelete, true
	default:
		return "", false
	}
}
