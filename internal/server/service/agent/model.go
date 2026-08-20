package agent

import (
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
)

// DefaultMaxActiveCredentials permits one overlapping rotation credential.
const DefaultMaxActiveCredentials int64 = 2

// AgentRecord is the backend-neutral persisted agent representation.
type AgentRecord struct {
	AgentID     string
	TenantID    string
	Name        string
	Status      agentv1.AgentStatus
	AuthVersion uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DisabledAt  *time.Time
}

// CredentialRecord is the backend-neutral persisted credential representation.
// Clear bootstrap credentials are intentionally absent from this record.
type CredentialRecord struct {
	CredentialID       string
	AgentID            string
	TenantID           string
	Name               string
	Prefix             string
	SecretHash         []byte
	CreatedAt          time.Time
	ExpiresAt          *time.Time
	ExpiredAccountedAt *time.Time
	RevokedAt          *time.Time
	LastUsedAt         *time.Time
}

// CreateAgentInput carries deterministic identity and time values into storage.
type CreateAgentInput struct {
	AgentID     string
	TenantID    string
	Name        string
	Status      agentv1.AgentStatus
	AuthVersion uint64
	CreatedBy   principal.Ref
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ListAgentsInput describes a tenant-scoped name-order page.
type ListAgentsInput struct {
	TenantID   string
	NamePrefix string
	AfterName  string
	AfterID    string
	Limit      uint32
}

// ListAgentsResult is a tenant-scoped name-order page.
type ListAgentsResult struct {
	Agents     []AgentRecord
	NextCursor string
	HasMore    bool
	TotalCount uint64
}

// SetAgentStatusInput changes one tenant-owned agent's status.
type SetAgentStatusInput struct {
	TenantID  string
	AgentID   string
	Status    agentv1.AgentStatus
	UpdatedAt time.Time
}

// CreateCredentialInput carries a newly generated bootstrap credential hash into storage.
type CreateCredentialInput struct {
	CredentialID string
	TenantID     string
	AgentID      string
	Name         string
	Prefix       string
	SecretHash   [32]byte
	CreatedAt    time.Time
	ExpiresAt    *time.Time
}

// RegisterCredentialInput carries an externally generated credential hash into storage.
type RegisterCredentialInput struct {
	CredentialID string
	TenantID     string
	AgentID      string
	Name         string
	Prefix       string
	SecretHash   [32]byte
	CreatedAt    time.Time
	ExpiresAt    *time.Time
}

// RegisterCredentialResult identifies a canonical idempotent registration replay.
type RegisterCredentialResult struct {
	Credential     CredentialRecord
	AlreadyExisted bool
}

// ListCredentialsInput describes an agent-scoped credential ID page.
type ListCredentialsInput struct {
	TenantID string
	AgentID  string
	AfterID  string
	Limit    uint32
}

// ListCredentialsResult is an agent-scoped credential ID page.
type ListCredentialsResult struct {
	Credentials []CredentialRecord
	NextCursor  string
	HasMore     bool
}

// RevokeCredentialInput revokes one tenant-owned credential.
type RevokeCredentialInput struct {
	TenantID     string
	AgentID      string
	CredentialID string
	RevokedAt    time.Time
}

// TouchCredentialInput records successful credential use.
type TouchCredentialInput struct {
	TenantID     string
	AgentID      string
	CredentialID string
	UsedAt       time.Time
}
