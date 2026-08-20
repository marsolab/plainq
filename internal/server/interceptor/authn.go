package interceptor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const defaultStreamAuthenticationRecheck = time.Second

var (
	errTokenExpired       = errors.New("agent access token expired")
	errStreamAuthInvalid  = errors.New("agent access token is no longer valid")
	errInvalidAccessToken = errors.New("invalid access token")
)

// Authenticator verifies an access token and resolves its live principal.
type Authenticator interface {
	Authenticate(ctx context.Context, raw string) (principal.Principal, error)
}

// HumanTokenVerifier is the existing human-session JWT verification surface.
type HumanTokenVerifier interface {
	ParseVerify(raw string) (*jwtkit.Token, error)
}

// AccessTokenDenylist reports whether a human access token was signed out.
type AccessTokenDenylist interface {
	IsAccessTokenDenied(ctx context.Context, raw string) (bool, error)
}

// HumanTenantResolver resolves authoritative tenant membership for a user.
type HumanTenantResolver interface {
	GetAccountOrgID(ctx context.Context, userID string) (string, error)
}

// CompositeAuthenticator accepts either an agent token or an existing human
// session token. Human tenant identity is resolved from persistence rather
// than from request metadata.
type CompositeAuthenticator struct {
	agent    Authenticator
	human    HumanTokenVerifier
	denylist AccessTokenDenylist
	tenants  HumanTenantResolver
}

// NewCompositeAuthenticator constructs the shared gRPC token verifier.
func NewCompositeAuthenticator(
	agent Authenticator,
	human HumanTokenVerifier,
	denylist AccessTokenDenylist,
	tenants HumanTenantResolver,
) (*CompositeAuthenticator, error) {
	if agent == nil {
		return nil, errors.New("agent authenticator is required")
	}

	if human == nil {
		return nil, errors.New("human token verifier is required")
	}

	if tenants == nil {
		return nil, errors.New("human tenant resolver is required")
	}

	return &CompositeAuthenticator{agent: agent, human: human, denylist: denylist, tenants: tenants}, nil
}

// Authenticate implements Authenticator.
func (a *CompositeAuthenticator) Authenticate(ctx context.Context, raw string) (principal.Principal, error) {
	if p, err := a.agent.Authenticate(ctx, raw); err == nil {
		return p, nil
	}

	return a.authenticateHuman(ctx, raw)
}

func (a *CompositeAuthenticator) authenticateHuman(ctx context.Context, raw string) (principal.Principal, error) {
	token, err := a.human.ParseVerify(raw)
	if err != nil || token == nil {
		return principal.Principal{}, errInvalidAccessToken
	}

	if err := a.checkHumanDenylist(ctx, raw); err != nil {
		return principal.Principal{}, err
	}

	userID, ok := token.Meta["uid"].(string)
	if !ok || userID == "" || token.ExpiresAt == nil || token.ID == "" {
		return principal.Principal{}, errInvalidAccessToken
	}

	tenantID, err := a.tenants.GetAccountOrgID(ctx, userID)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("resolve human tenant: %w", err)
	}

	if tenantID == "" {
		return principal.Principal{}, errInvalidAccessToken
	}

	return principal.Principal{
		Kind:      principal.KindHuman,
		ID:        userID,
		TenantID:  tenantID,
		Roles:     humanTokenRoles(token.Meta["roles"]),
		TokenID:   token.ID,
		ExpiresAt: token.ExpiresAt.UTC(),
	}, nil
}

func (a *CompositeAuthenticator) checkHumanDenylist(ctx context.Context, raw string) error {
	if a.denylist == nil {
		return nil
	}

	denied, err := a.denylist.IsAccessTokenDenied(ctx, raw)
	if err != nil {
		return fmt.Errorf("check human token denylist: %w", err)
	}

	if denied {
		return errInvalidAccessToken
	}

	return nil
}

func humanTokenRoles(value any) []string {
	switch roles := value.(type) {
	case []string:
		return append([]string(nil), roles...)

	case []any:
		result := make([]string, 0, len(roles))
		for _, role := range roles {
			if text, ok := role.(string); ok {
				result = append(result, text)
			}
		}

		return result

	default:
		return nil
	}
}

//nolint:wrapcheck // gRPC status values are created at this transport boundary.
func bearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "authorization metadata is required")
	}

	values := md.Get("authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "one bearer token is required")
	}

	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || strings.TrimSpace(token) != token {
		return "", status.Error(codes.Unauthenticated, "one bearer token is required")
	}

	return token, nil
}

// UnaryAuth injects a verified principal for every protected unary route.
func UnaryAuth(a Authenticator, public map[string]struct{}) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if methodAllowsAnonymous(info.FullMethod, public) {
			return handler(ctx, req)
		}

		if a == nil {
			return nil, status.Error(codes.Unauthenticated, "access token authentication is unavailable")
		}

		token, err := bearerToken(ctx)
		if err != nil {
			return nil, err
		}

		p, err := a.Authenticate(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid access token")
		}

		return handler(principal.With(ctx, p), req)
	}
}

type principalStream struct {
	grpc.ServerStream
	ctx context.Context //nolint:containedctx // ServerStream exposes Context only through this wrapper.
}

func (s *principalStream) Context() context.Context { return s.ctx }

type streamAuthConfig struct {
	recheckInterval time.Duration
}

// StreamAuthOption configures stream authentication monitoring.
type StreamAuthOption func(*streamAuthConfig)

// WithStreamAuthenticationRecheck changes live credential revalidation cadence.
func WithStreamAuthenticationRecheck(interval time.Duration) StreamAuthOption {
	return func(config *streamAuthConfig) {
		if interval > 0 {
			config.recheckInterval = interval
		}
	}
}

// StreamAuth injects a verified principal and ends a stream no later than the
// token expiry. Stateful authenticators are re-run while the stream is live so
// credential revocation and agent disable take effect without reconnecting.
func StreamAuth(
	a Authenticator,
	public map[string]struct{},
	options ...StreamAuthOption,
) grpc.StreamServerInterceptor {
	config := streamAuthConfig{recheckInterval: defaultStreamAuthenticationRecheck}
	for _, option := range options {
		option(&config)
	}

	return func(
		srv any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if methodAllowsAnonymous(info.FullMethod, public) {
			return handler(srv, stream)
		}

		if a == nil {
			return status.Error(codes.Unauthenticated, "access token authentication is unavailable")
		}

		token, err := bearerToken(stream.Context())
		if err != nil {
			return err
		}

		p, err := a.Authenticate(stream.Context(), token)
		if err != nil {
			return status.Error(codes.Unauthenticated, "invalid access token")
		}

		ctx := stream.Context()

		deadlineCancel := func() {}
		if !p.ExpiresAt.IsZero() {
			ctx, deadlineCancel = context.WithDeadlineCause(ctx, p.ExpiresAt, errTokenExpired)
		}
		defer deadlineCancel()

		ctx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)

		monitorDone := make(chan struct{})
		go monitorStreamAuthentication(ctx, a, token, p, config.recheckInterval, cancel, monitorDone)

		handlerErr := handler(srv, &principalStream{ServerStream: stream, ctx: principal.With(ctx, p)})

		cancel(nil)
		<-monitorDone

		switch {
		case errors.Is(context.Cause(ctx), errTokenExpired):
			return tokenExpiredStatus()

		case errors.Is(context.Cause(ctx), errStreamAuthInvalid):
			return status.Error(codes.Unauthenticated, "invalid access token")

		default:
			return handlerErr
		}
	}
}

func monitorStreamAuthentication(
	ctx context.Context,
	a Authenticator,
	token string,
	want principal.Principal,
	interval time.Duration,
	cancel context.CancelCauseFunc,
	done chan<- struct{},
) {
	defer close(done)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			got, err := a.Authenticate(ctx, token)
			if err != nil || !sameAuthenticatedPrincipal(got, want) {
				cancel(errStreamAuthInvalid)

				return
			}
		}
	}
}

func sameAuthenticatedPrincipal(got, want principal.Principal) bool {
	return got.Kind == want.Kind && got.ID == want.ID && got.TenantID == want.TenantID &&
		got.CredentialID == want.CredentialID && got.AuthVersion == want.AuthVersion && got.TokenID == want.TokenID
}

//nolint:wrapcheck // gRPC status details are finalized at this transport boundary.
func tokenExpiredStatus() error {
	value := status.New(codes.Unauthenticated, "access token expired")

	withDetails, err := value.WithDetails(&errdetails.ErrorInfo{Reason: "TOKEN_EXPIRED", Domain: "plainq.io"})
	if err != nil {
		return value.Err()
	}

	return withDetails.Err()
}

func methodAllowsAnonymous(method string, public map[string]struct{}) bool {
	if _, ok := public[method]; ok {
		return true
	}

	return isLegacyCompatibilityMethod(method)
}
