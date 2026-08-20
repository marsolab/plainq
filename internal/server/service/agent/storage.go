package agent

import (
	"context"

	"github.com/marsolab/plainq/internal/shared/pqerr"
)

var (
	ErrAlreadyExists       = pqerr.ErrAlreadyExists
	ErrNotFound            = pqerr.ErrNotFound
	ErrUnauthenticated     = pqerr.ErrUnauthenticated
	ErrPermissionDenied    = pqerr.ErrUnauthorized
	ErrIdempotencyConflict = pqerr.ErrAlreadyExists
	ErrFailedPrecondition  = pqerr.ErrFailedPrecondition
)

// RegistryStore persists tenant-owned agent registry state.
type RegistryStore interface {
	CreateAgent(ctx context.Context, input CreateAgentInput) (AgentRecord, error)
	GetAgent(ctx context.Context, tenantID, agentID string) (AgentRecord, error)
	GetAgentByName(ctx context.Context, tenantID, name string) (AgentRecord, error)
	ListAgents(ctx context.Context, input ListAgentsInput) (ListAgentsResult, error)
	SetAgentStatus(ctx context.Context, input SetAgentStatusInput) (AgentRecord, error)
}

// PrincipalStore reads the security projection that is authoritative for live authentication state.
type PrincipalStore interface {
	GetAgentPrincipal(ctx context.Context, tenantID, agentID string) (AgentPrincipalRecord, error)
}

// CredentialStore persists only bootstrap credential hashes and lifecycle metadata.
type CredentialStore interface {
	CreateCredential(ctx context.Context, input CreateCredentialInput) (CredentialRecord, error)
	RegisterCredential(ctx context.Context, input RegisterCredentialInput) (RegisterCredentialResult, error)
	ListCredentials(ctx context.Context, input ListCredentialsInput) (ListCredentialsResult, error)
	GetCredentialByPrefix(ctx context.Context, prefix string) (CredentialRecord, error)
	RevokeCredential(ctx context.Context, input RevokeCredentialInput) error
	TouchCredential(ctx context.Context, input TouchCredentialInput) error
}

// Store is the complete registry and credential persistence surface.
type Store interface {
	RegistryStore
	PrincipalStore
	CredentialStore
}
