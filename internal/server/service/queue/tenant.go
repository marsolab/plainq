package queue

import (
	"context"

	"github.com/marsolab/plainq/internal/server/principal"
)

// AccessScope is the authoritative tenant/creator filter legacy queue and
// topic storage applies to every request. Compatibility is intentionally
// narrower than tenant membership: anonymous old clients see only rows owned
// by the migration or by the legacy-v1 compatibility principal.
type AccessScope struct {
	TenantID      string
	CreatorKind   principal.Kind
	CreatorID     string
	Compatibility bool
}

// ScopeFromContext resolves the authenticated principal. A missing principal
// is treated as the explicitly configured old-v1 compatibility identity; HTTP
// and protected gRPC paths inject a human/agent principal before storage.
func ScopeFromContext(ctx context.Context) AccessScope {
	p, ok := principal.From(ctx)
	if !ok || p.ID == "" || p.TenantID == "" {
		return AccessScope{
			TenantID: principal.LegacyTenantID, CreatorKind: principal.KindSystem,
			CreatorID: principal.LegacyPrincipalID, Compatibility: true,
		}
	}

	return AccessScope{
		TenantID: p.TenantID, CreatorKind: p.Kind, CreatorID: p.ID,
		Compatibility: p.Kind == principal.KindSystem && p.ID == principal.LegacyPrincipalID &&
			p.TenantID == principal.LegacyTenantID,
	}
}
