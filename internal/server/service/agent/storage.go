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
)

// RegistryStore persists tenant-owned agent registry state.
type RegistryStore interface {
	CreateAgent(ctx context.Context, input CreateAgentInput) (AgentRecord, error)
	GetAgent(ctx context.Context, tenantID, agentID string) (AgentRecord, error)
	GetAgentByName(ctx context.Context, tenantID, name string) (AgentRecord, error)
	ListAgents(ctx context.Context, input ListAgentsInput) (ListAgentsResult, error)
	SetAgentStatus(ctx context.Context, input SetAgentStatusInput) (AgentRecord, error)
}
