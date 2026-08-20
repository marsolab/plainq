package interceptor

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type authTestAgentServer struct {
	agentv1.UnimplementedAgentServiceServer
	seenPrincipal chan principal.Principal
}

func (s authTestAgentServer) GetAgent(
	ctx context.Context,
	_ *agentv1.GetAgentRequest,
) (*agentv1.GetAgentResponse, error) {
	if s.seenPrincipal != nil {
		p, _ := principal.From(ctx)
		s.seenPrincipal <- p
	}

	return &agentv1.GetAgentResponse{}, nil
}

func (authTestAgentServer) SendToAgent(
	context.Context,
	*agentv1.SendToAgentRequest,
) (*agentv1.SendToAgentResponse, error) {
	return &agentv1.SendToAgentResponse{}, nil
}

func (s authTestAgentServer) ListenInbox(
	_ *agentv1.ListenInboxRequest,
	stream grpc.ServerStreamingServer[agentv1.ListenInboxResponse],
) error {
	if s.seenPrincipal != nil {
		p, _ := principal.From(stream.Context())
		s.seenPrincipal <- p
	}

	<-stream.Context().Done()

	return stream.Context().Err()
}

func TestAuthBufconnRejectsMissingBearerMetadata(t *testing.T) {
	client, cleanup := newAuthBufconn(t, []grpc.UnaryServerInterceptor{
		UnaryAuth(staticAuthenticator{principal: agentPrincipal("tenant-a", "agent-a")}, PublicMethods()),
	}, nil, authTestAgentServer{})
	t.Cleanup(cleanup)

	_, err := client.GetAgent(context.Background(), &agentv1.GetAgentRequest{})
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("GetAgent() code = %s, want %s (error %v)", got, codes.Unauthenticated, err)
	}
}

func TestAuthBufconnRejectsInvalidAgentStateAndClaims(t *testing.T) {
	t.Parallel()

	secret := []byte(strings.Repeat("s", 32))
	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	basePrincipal := agentPrincipal("tenant-a", "agent-a")
	basePrincipal.CredentialID = "credential-a"
	basePrincipal.AuthVersion = 1

	newManager := func(audience string, ttl time.Duration, clock func() time.Time) *security.AgentTokenManager {
		manager, err := security.NewAgentTokenManager(security.AgentTokenConfig{
			Issuer: "plainq", Audience: audience, Secret: secret, TTL: ttl, Clock: clock,
			NextID: func() string { return "token-a" },
		})
		if err != nil {
			t.Fatalf("NewAgentTokenManager() error = %v", err)
		}

		return manager
	}

	t.Run("wrong audience", func(t *testing.T) {
		issuer := newManager("wrong-audience", time.Minute, func() time.Time { return now })
		token, _, err := issuer.Issue(basePrincipal)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		verifier := newManager("plainq-agents", time.Minute, func() time.Time { return now })
		assertBufconnTokenCode(t, liveTokenAuthenticator{verifier: verifier}, token, codes.Unauthenticated)
	})

	t.Run("expired", func(t *testing.T) {
		clock := now
		manager := newManager("plainq-agents", time.Second, func() time.Time { return clock })
		token, _, err := manager.Issue(basePrincipal)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
		clock = now.Add(2 * time.Second)

		assertBufconnTokenCode(t, liveTokenAuthenticator{verifier: manager}, token, codes.Unauthenticated)
	})

	t.Run("revoked credential", func(t *testing.T) {
		manager := newManager("plainq-agents", time.Minute, func() time.Time { return now })
		token, _, err := manager.Issue(basePrincipal)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		authenticator := liveTokenAuthenticator{verifier: manager, revoked: &atomic.Bool{}}
		authenticator.revoked.Store(true)
		assertBufconnTokenCode(t, authenticator, token, codes.Unauthenticated)
	})

	t.Run("disabled agent", func(t *testing.T) {
		manager := newManager("plainq-agents", time.Minute, func() time.Time { return now })
		token, _, err := manager.Issue(basePrincipal)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		authenticator := liveTokenAuthenticator{verifier: manager, disabled: &atomic.Bool{}}
		authenticator.disabled.Store(true)
		assertBufconnTokenCode(t, authenticator, token, codes.Unauthenticated)
	})
}

func TestStreamAuthPropagatesPrincipalAndMapsExpiry(t *testing.T) {
	t.Parallel()

	seen := make(chan principal.Principal, 1)
	p := agentPrincipal("tenant-a", "agent-a")
	p.CredentialID = "credential-a"
	p.AuthVersion = 1
	p.TokenID = "token-a"
	p.ExpiresAt = time.Now().Add(150 * time.Millisecond)

	client, cleanup := newAuthBufconn(t, nil, []grpc.StreamServerInterceptor{
		StreamAuth(staticAuthenticator{principal: p}, PublicMethods(), WithStreamAuthenticationRecheck(time.Second)),
	}, authTestAgentServer{seenPrincipal: seen})
	t.Cleanup(cleanup)

	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer token")
	stream, err := client.ListenInbox(ctx, &agentv1.ListenInboxRequest{})
	if err != nil {
		t.Fatalf("ListenInbox() error = %v", err)
	}

	select {
	case got := <-seen:
		if got.ID != p.ID || got.TenantID != p.TenantID || got.TokenID != p.TokenID {
			t.Fatalf("stream principal = %#v, want %#v", got, p)
		}
	case <-time.After(time.Second):
		t.Fatal("stream handler did not receive principal")
	}

	_, err = stream.Recv()
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("Recv() code = %s, want %s (error %v)", got, codes.Unauthenticated, err)
	}

	statusValue, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Recv() error has no status: %v", err)
	}

	foundExpiryDetail := false
	for _, detail := range statusValue.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if ok && info.GetReason() == "TOKEN_EXPIRED" && info.GetDomain() == "plainq.io" {
			foundExpiryDetail = true
		}
	}
	if !foundExpiryDetail {
		t.Fatalf("Recv() details = %#v, want TOKEN_EXPIRED ErrorInfo", statusValue.Details())
	}
}

func TestStreamAuthEndsAfterCredentialRevocation(t *testing.T) {
	t.Parallel()

	revoked := &atomic.Bool{}
	seen := make(chan principal.Principal, 1)
	p := agentPrincipal("tenant-a", "agent-a")
	p.CredentialID = "credential-a"
	p.AuthVersion = 1
	p.TokenID = "token-a"
	p.ExpiresAt = time.Now().Add(time.Minute)

	authenticator := liveTokenAuthenticator{
		staticPrincipal: p,
		revoked:         revoked,
	}
	client, cleanup := newAuthBufconn(t, nil, []grpc.StreamServerInterceptor{
		StreamAuth(authenticator, PublicMethods(), WithStreamAuthenticationRecheck(10*time.Millisecond)),
	}, authTestAgentServer{seenPrincipal: seen})
	t.Cleanup(cleanup)

	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer token")
	stream, err := client.ListenInbox(ctx, &agentv1.ListenInboxRequest{})
	if err != nil {
		t.Fatalf("ListenInbox() error = %v", err)
	}

	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("stream handler did not start")
	}

	revoked.Store(true)
	_, err = stream.Recv()
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("Recv() code = %s, want %s (error %v)", got, codes.Unauthenticated, err)
	}
}

func TestAuthzBufconnHidesCrossTenantTarget(t *testing.T) {
	t.Parallel()

	resources := &resourceAuthorizerStub{
		resolve: func(_ context.Context, tenantID string, selector ResourceSelector) (Resource, error) {
			if tenantID != "tenant-a" || selector.Kind != ResourceAgent || selector.ID != "agent-b" {
				t.Fatalf("ResolveResource(%q, %#v)", tenantID, selector)
			}

			return Resource{}, pqerr.ErrNotFound
		},
	}
	client, cleanup := newAuthBufconn(t, []grpc.UnaryServerInterceptor{
		UnaryAuth(staticAuthenticator{principal: agentPrincipal("tenant-a", "agent-a")}, PublicMethods()),
		UnaryAuthorize(resources),
	}, nil, authTestAgentServer{})
	t.Cleanup(cleanup)

	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer token")
	_, err := client.SendToAgent(ctx, &agentv1.SendToAgentRequest{TargetAgentId: "agent-b"})
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("SendToAgent() code = %s, want %s (error %v)", got, codes.NotFound, err)
	}
}

type staticAuthenticator struct {
	principal principal.Principal
}

func (a staticAuthenticator) Authenticate(context.Context, string) (principal.Principal, error) {
	return a.principal, nil
}

type tokenVerifier interface {
	Verify(string) (principal.Principal, error)
}

type liveTokenAuthenticator struct {
	verifier        tokenVerifier
	staticPrincipal principal.Principal
	revoked         *atomic.Bool
	disabled        *atomic.Bool
}

func (a liveTokenAuthenticator) Authenticate(_ context.Context, token string) (principal.Principal, error) {
	if a.revoked != nil && a.revoked.Load() {
		return principal.Principal{}, pqerr.ErrUnauthenticated
	}
	if a.disabled != nil && a.disabled.Load() {
		return principal.Principal{}, pqerr.ErrUnauthenticated
	}
	if a.verifier != nil {
		return a.verifier.Verify(token)
	}
	if a.staticPrincipal.ID == "" {
		return principal.Principal{}, errors.New("test authenticator has no principal")
	}

	return a.staticPrincipal, nil
}

func assertBufconnTokenCode(t *testing.T, authenticator Authenticator, token string, want codes.Code) {
	t.Helper()

	client, cleanup := newAuthBufconn(t, []grpc.UnaryServerInterceptor{
		UnaryAuth(authenticator, PublicMethods()),
	}, nil, authTestAgentServer{})
	t.Cleanup(cleanup)

	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
	_, err := client.GetAgent(ctx, &agentv1.GetAgentRequest{})
	if got := status.Code(err); got != want {
		t.Fatalf("GetAgent() code = %s, want %s (error %v)", got, want, err)
	}
}

func newAuthBufconn(
	t *testing.T,
	unary []grpc.UnaryServerInterceptor,
	streams []grpc.StreamServerInterceptor,
	service agentv1.AgentServiceServer,
) (agentv1.AgentServiceClient, func()) {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(streams...),
	)
	agentv1.RegisterAgentServiceServer(grpcServer, service)

	serveDone := make(chan error, 1)
	go func() { serveDone <- grpcServer.Serve(listener) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
	)
	if err != nil {
		grpcServer.Stop()
		_ = listener.Close()
		<-serveDone
		t.Fatalf("grpc.NewClient() error = %v", err)
	}

	return agentv1.NewAgentServiceClient(conn), func() {
		_ = conn.Close()
		grpcServer.Stop()
		_ = listener.Close()
		<-serveDone
	}
}
