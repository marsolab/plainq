package agent

import (
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/policytx"
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

// AgentPrincipalRecord is the security projection consulted for stateful token checks.
type AgentPrincipalRecord struct {
	AgentID     string
	TenantID    string
	Status      agentv1.AgentStatus
	AuthVersion uint64
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
	Policy      policytx.Mutation
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
	Policy    policytx.Mutation
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
	Policy       policytx.Mutation
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
	Policy       policytx.Mutation
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
	Policy       policytx.Mutation
}

// TouchCredentialInput records successful credential use.
type TouchCredentialInput struct {
	TenantID     string
	AgentID      string
	CredentialID string
	UsedAt       time.Time
	Policy       policytx.Mutation
}

// CreateGrantInput creates one fixed-vocabulary direct grant.
type CreateGrantInput struct {
	GrantID      string
	TenantID     string
	SubjectID    string
	ResourceID   string
	Action       string
	SubjectKind  principal.Kind
	ResourceKind authz.ResourceType
	CreatedAt    time.Time
	Policy       policytx.Mutation
}

// GrantRecord is one tenant-owned direct grant.
type GrantRecord struct {
	GrantID      string
	TenantID     string
	SubjectID    string
	ResourceID   string
	Action       string
	SubjectKind  principal.Kind
	ResourceKind authz.ResourceType
	CreatedAt    time.Time
}

// ListGrantsInput describes a bounded grant-ID keyset page.
type ListGrantsInput struct {
	TenantID     string
	SubjectID    string
	ResourceID   string
	AfterID      string
	SubjectKind  principal.Kind
	ResourceKind authz.ResourceType
	Limit        uint32
}

// GrantPage is one bounded direct-grant page.
type GrantPage struct {
	Grants     []GrantRecord
	NextCursor string
	HasMore    bool
}

// DeleteGrantInput removes one tenant-owned direct grant.
type DeleteGrantInput struct {
	TenantID string
	GrantID  string
	Policy   policytx.Mutation
}
