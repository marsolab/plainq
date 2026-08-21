package agent

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/marsolab/servekit/idkit"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

const defaultMaxCredentialTTL = 365 * 24 * time.Hour

// TokenManager signs and verifies stateless agent access token claims.
type TokenManager interface {
	security.AgentTokenIssuer
	security.AgentTokenVerifier
}

// ServiceConfig supplies persistence, token, time, identity, entropy, and admission dependencies.
type ServiceConfig struct {
	Registry         RegistryStore
	Principals       PrincipalStore
	Credentials      CredentialStore
	Tokens           TokenManager
	Clock            func() time.Time
	NextID           func() string
	Random           io.Reader
	MaxCredentialTTL time.Duration
	PreAuth          PreAuthConfig
}

// Service implements tenant-scoped agent registry and credential lifecycle rules.
type Service struct {
	registry         RegistryStore
	principals       PrincipalStore
	credentials      CredentialStore
	tokens           TokenManager
	clock            func() time.Time
	nextID           func() string
	random           io.Reader
	maxCredentialTTL time.Duration
	preAuth          *preAuthLimiter
}

// NewService constructs an agent registry service without enabling its server wiring.
//
//nolint:cyclop // Constructor validates each required security dependency independently.
func NewService(config ServiceConfig) (*Service, error) {
	if config.Registry == nil {
		return nil, errors.New("agent registry store is required")
	}

	if config.Credentials == nil {
		return nil, errors.New("agent credential store is required")
	}

	if config.Principals == nil {
		return nil, errors.New("agent principal store is required")
	}

	if config.Tokens == nil {
		return nil, errors.New("agent token manager is required")
	}

	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	nextID := config.NextID
	if nextID == nil {
		nextID = idkit.ULID
	}

	random := config.Random
	if random == nil {
		random = crand.Reader
	}

	maxCredentialTTL := config.MaxCredentialTTL
	if maxCredentialTTL == 0 {
		maxCredentialTTL = defaultMaxCredentialTTL
	}

	if maxCredentialTTL < time.Second {
		return nil, errors.New("maximum credential TTL must be at least one second")
	}

	preAuth, err := newPreAuthLimiter(config.PreAuth, clock)
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	return &Service{
		registry: config.Registry, principals: config.Principals, credentials: config.Credentials, tokens: config.Tokens,
		clock: clock, nextID: nextID, random: random,
		maxCredentialTTL: maxCredentialTTL, preAuth: preAuth,
	}, nil
}

// CreateAgent creates an active tenant-owned agent and its principal projection.
func (s *Service) CreateAgent(
	ctx context.Context,
	req *agentv1.CreateAgentRequest,
) (*agentv1.CreateAgentResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, invalidInput("create agent request is required")
	}

	name, err := validateAgentName(req.GetAgentName())
	if err != nil {
		return nil, err
	}

	agentID := s.nextID()
	if err := validateULID(agentID, "generated agent ID"); err != nil {
		return nil, fmt.Errorf("generate agent ID: %w", err)
	}

	now := s.clock().UTC()

	record, err := s.registry.CreateAgent(ctx, CreateAgentInput{
		AgentID: agentID, TenantID: p.TenantID, Name: name,
		Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE, AuthVersion: 1,
		CreatedBy: p.Ref(), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	return &agentv1.CreateAgentResponse{Agent: toProtoAgent(record)}, nil
}

// GetAgent returns one tenant-owned agent selected by ID or name.
func (s *Service) GetAgent(
	ctx context.Context,
	req *agentv1.GetAgentRequest,
) (*agentv1.GetAgentResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil || (req.GetAgentId() == "") == (req.GetAgentName() == "") {
		return nil, invalidInput("exactly one agent selector is required")
	}

	var record AgentRecord

	if req.GetAgentId() != "" {
		if err := validateULID(req.GetAgentId(), "agent ID"); err != nil {
			return nil, err
		}

		record, err = s.registry.GetAgent(ctx, p.TenantID, req.GetAgentId())
	} else {
		name, validateErr := validateAgentName(req.GetAgentName())
		if validateErr != nil {
			return nil, validateErr
		}

		record, err = s.registry.GetAgentByName(ctx, p.TenantID, name)
	}

	if err != nil {
		return nil, fmt.Errorf("get agent: %w", err)
	}

	return &agentv1.GetAgentResponse{Agent: toProtoAgent(record)}, nil
}

// ListAgents lists tenant-owned agents using a stable name-and-ID keyset.
func (s *Service) ListAgents(
	ctx context.Context,
	req *agentv1.ListAgentsRequest,
) (*agentv1.ListAgentsResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, invalidInput("list agents request is required")
	}

	if err := validateNamePrefix(req.GetNamePrefix()); err != nil {
		return nil, err
	}

	limit, err := pageSize(req.GetLimit())
	if err != nil {
		return nil, err
	}

	cursor, err := parseAgentCursor(req.GetCursor())
	if err != nil {
		return nil, err
	}

	page, err := s.registry.ListAgents(ctx, ListAgentsInput{
		TenantID: p.TenantID, NamePrefix: req.GetNamePrefix(), AfterName: cursor.name,
		AfterID: cursor.id, Limit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}

	agents := make([]*agentv1.Agent, 0, len(page.Agents))
	for _, record := range page.Agents {
		agents = append(agents, toProtoAgent(record))
	}

	return &agentv1.ListAgentsResponse{
		Agents: agents, NextCursor: page.NextCursor, HasMore: page.HasMore, TotalCount: page.TotalCount,
	}, nil
}

// SetAgentStatus enables or disables one tenant-owned agent.
func (s *Service) SetAgentStatus(
	ctx context.Context,
	req *agentv1.SetAgentStatusRequest,
) (*agentv1.SetAgentStatusResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, invalidInput("set agent status request is required")
	}

	if err := validateULID(req.GetAgentId(), "agent ID"); err != nil {
		return nil, err
	}

	if req.GetStatus() != agentv1.AgentStatus_AGENT_STATUS_ACTIVE &&
		req.GetStatus() != agentv1.AgentStatus_AGENT_STATUS_DISABLED {
		return nil, invalidInput("agent status must be active or disabled")
	}

	record, err := s.registry.SetAgentStatus(ctx, SetAgentStatusInput{
		TenantID: p.TenantID, AgentID: req.GetAgentId(), Status: req.GetStatus(), UpdatedAt: s.clock().UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("set agent status: %w", err)
	}

	return &agentv1.SetAgentStatusResponse{Agent: toProtoAgent(record)}, nil
}

func requireTenantAdmin(ctx context.Context) (principal.Principal, error) {
	p, ok := principal.From(ctx)
	if !ok || p.ID == "" || p.TenantID == "" {
		return principal.Principal{}, ErrUnauthenticated
	}

	if p.Kind != principal.KindHuman || !p.HasRole("admin") {
		return principal.Principal{}, ErrPermissionDenied
	}

	return p, nil
}

func toProtoAgent(record AgentRecord) *agentv1.Agent {
	return &agentv1.Agent{
		AgentId: record.AgentID, AgentName: record.Name, Status: record.Status,
		CreatedAt: timestamppb.New(record.CreatedAt), UpdatedAt: timestamppb.New(record.UpdatedAt),
	}
}

func invalidInput(message string) error {
	return fmt.Errorf("%s: %w", message, pqerr.ErrInvalidInput)
}
