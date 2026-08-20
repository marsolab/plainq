package agent

import (
	"context"
	"errors"

	"github.com/marsolab/servekit/grpckit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

// GRPCTransport maps agent service domain errors without logging request secrets.
type GRPCTransport struct {
	agentv1.UnimplementedAgentServiceServer
	service *Service
}

var _ agentv1.AgentServiceServer = (*GRPCTransport)(nil)

// NewGRPCTransport constructs the generated AgentService adapter.
func NewGRPCTransport(service *Service) (*GRPCTransport, error) {
	if service == nil {
		return nil, errors.New("agent service is required")
	}

	return &GRPCTransport{service: service}, nil
}

// Mount registers the generated AgentService on a gRPC server.
func (t *GRPCTransport) Mount(server *grpc.Server) {
	agentv1.RegisterAgentServiceServer(server, t)
}

// CreateAgent maps the registry operation onto the generated transport.
func (t *GRPCTransport) CreateAgent(
	ctx context.Context,
	req *agentv1.CreateAgentRequest,
) (*agentv1.CreateAgentResponse, error) {
	response, err := t.service.CreateAgent(ctx, req)

	return mapGRPC(ctx, response, err)
}

// GetAgent maps the registry lookup onto the generated transport.
func (t *GRPCTransport) GetAgent(
	ctx context.Context,
	req *agentv1.GetAgentRequest,
) (*agentv1.GetAgentResponse, error) {
	response, err := t.service.GetAgent(ctx, req)

	return mapGRPC(ctx, response, err)
}

// ListAgents maps the registry page onto the generated transport.
func (t *GRPCTransport) ListAgents(
	ctx context.Context,
	req *agentv1.ListAgentsRequest,
) (*agentv1.ListAgentsResponse, error) {
	response, err := t.service.ListAgents(ctx, req)

	return mapGRPC(ctx, response, err)
}

// SetAgentStatus maps the status mutation onto the generated transport.
func (t *GRPCTransport) SetAgentStatus(
	ctx context.Context,
	req *agentv1.SetAgentStatusRequest,
) (*agentv1.SetAgentStatusResponse, error) {
	response, err := t.service.SetAgentStatus(ctx, req)

	return mapGRPC(ctx, response, err)
}

// CreateAgentCredential maps one-time credential issuance onto the generated transport.
func (t *GRPCTransport) CreateAgentCredential(
	ctx context.Context,
	req *agentv1.CreateAgentCredentialRequest,
) (*agentv1.CreateAgentCredentialResponse, error) {
	response, err := t.service.CreateAgentCredential(ctx, req)

	return mapGRPC(ctx, response, err)
}

// ListAgentCredentials maps credential lifecycle metadata onto the generated transport.
func (t *GRPCTransport) ListAgentCredentials(
	ctx context.Context,
	req *agentv1.ListAgentCredentialsRequest,
) (*agentv1.ListAgentCredentialsResponse, error) {
	response, err := t.service.ListAgentCredentials(ctx, req)

	return mapGRPC(ctx, response, err)
}

// RegisterAgentCredential maps external hash registration onto the generated transport.
func (t *GRPCTransport) RegisterAgentCredential(
	ctx context.Context,
	req *agentv1.RegisterAgentCredentialRequest,
) (*agentv1.RegisterAgentCredentialResponse, error) {
	response, err := t.service.RegisterAgentCredential(ctx, req)

	return mapGRPC(ctx, response, err)
}

// RevokeAgentCredential maps immediate revocation onto the generated transport.
func (t *GRPCTransport) RevokeAgentCredential(
	ctx context.Context,
	req *agentv1.RevokeAgentCredentialRequest,
) (*agentv1.RevokeAgentCredentialResponse, error) {
	response, err := t.service.RevokeAgentCredential(ctx, req)

	return mapGRPC(ctx, response, err)
}

// ExchangeAgentCredential maps public bootstrap exchange onto the generated transport.
func (t *GRPCTransport) ExchangeAgentCredential(
	ctx context.Context,
	req *agentv1.ExchangeAgentCredentialRequest,
) (*agentv1.ExchangeAgentCredentialResponse, error) {
	response, err := t.service.ExchangeAgentCredential(ctx, req)

	return mapGRPC(ctx, response, err)
}

func mapGRPC[T any](ctx context.Context, response T, err error) (T, error) {
	if err == nil {
		return response, nil
	}

	if errors.Is(err, ErrFailedPrecondition) {
		var zero T

		//nolint:wrapcheck // This is the deliberate gRPC transport boundary.
		return zero, status.Error(codes.FailedPrecondition, codes.FailedPrecondition.String())
	}

	return grpckit.ErrorGRPC[T](ctx, pqerr.AsTransport(err))
}
