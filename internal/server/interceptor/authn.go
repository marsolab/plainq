package interceptor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/security"
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
	IsAccessTokenDenied(ctx context.Context, tokenID string) (bool, error)
}

// HumanSecurityResolver resolves authoritative mutable session state.
type HumanSecurityResolver interface {
	ResolveHumanSecurity(ctx context.Context, userID string) (tenantID, status string, authVersion uint64, err error)
}

// CompositeAuthenticator accepts either an agent token or an existing human
// session token. Human tenant identity is resolved from persistence rather
// than from request metadata.
type CompositeAuthenticator struct {
	agent    Authenticator
	human    HumanTokenVerifier
	denylist AccessTokenDenylist
	security HumanSecurityResolver
	issuer   string
	audience string
}

// CompositeAuthenticatorOption configures human-token validation.
type CompositeAuthenticatorOption func(*CompositeAuthenticator)

// WithCompositeHumanTokenPolicy selects the exact configured issuer/audience.
func WithCompositeHumanTokenPolicy(issuer, audience string) CompositeAuthenticatorOption {
	return func(authenticator *CompositeAuthenticator) {
		authenticator.issuer = issuer
		authenticator.audience = audience
	}
}

// NewCompositeAuthenticator constructs the shared gRPC token verifier.
func NewCompositeAuthenticator(
	agent Authenticator,
	human HumanTokenVerifier,
	denylist AccessTokenDenylist,
	securityResolver HumanSecurityResolver,
	options ...CompositeAuthenticatorOption,
) (*CompositeAuthenticator, error) {
	if human == nil {
		return nil, errors.New("human token verifier is required")
	}

	if securityResolver == nil {
		return nil, errors.New("human security resolver is required")
	}

	authenticator := &CompositeAuthenticator{
		agent: agent, human: human, denylist: denylist, security: securityResolver,
		issuer: "plainq-server", audience: "plainq-human",
	}
	for _, option := range options {
		option(authenticator)
	}

	if authenticator.issuer == "" || authenticator.audience == "" {
		return nil, errors.New("human token issuer and audience are required")
	}

	return authenticator, nil
}

// Authenticate implements Authenticator.
func (a *CompositeAuthenticator) Authenticate(ctx context.Context, raw string) (principal.Principal, error) {
	if a.agent != nil {
		if p, err := a.agent.Authenticate(ctx, raw); err == nil {
			return p, nil
		}
	}

	return a.authenticateHuman(ctx, raw)
}

func (a *CompositeAuthenticator) authenticateHuman(ctx context.Context, raw string) (principal.Principal, error) {
	token, err := a.human.ParseVerify(raw)
	if err != nil || token == nil {
		return principal.Principal{}, errInvalidAccessToken
	}

	claims, err := a.humanClaims(token)
	if err != nil {
		return principal.Principal{}, err
	}

	if err := a.checkHumanDenylist(ctx, token.ID); err != nil {
		return principal.Principal{}, err
	}

	tenantID, accountStatus, liveAuthVersion, err := a.security.ResolveHumanSecurity(ctx, claims.userID)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("resolve human security: %w", err)
	}

	if tenantID == "" || accountStatus != "active" || tenantID != claims.tenantID ||
		liveAuthVersion != claims.authVersion {
		return principal.Principal{}, errInvalidAccessToken
	}

	return principal.Principal{
		Kind:        principal.KindHuman,
		ID:          claims.userID,
		TenantID:    tenantID,
		Roles:       humanTokenRoles(token.Meta["roles"]),
		AuthVersion: claims.authVersion,
		TokenID:     token.ID,
		ExpiresAt:   token.ExpiresAt.UTC(),
	}, nil
}

type humanAccessClaims struct {
	userID      string
	tenantID    string
	authVersion uint64
}

//nolint:cyclop // Every required access-token claim is checked explicitly and fail closed.
func (a *CompositeAuthenticator) humanClaims(token *jwtkit.Token) (humanAccessClaims, error) {
	userID, ok := token.Meta["uid"].(string)
	if !ok || userID == "" || token.Subject != userID {
		return humanAccessClaims{}, errInvalidAccessToken
	}

	if token.ExpiresAt == nil || token.ID == "" || token.Issuer != a.issuer ||
		!humanAudienceContains(token.Audience, a.audience) {
		return humanAccessClaims{}, errInvalidAccessToken
	}

	tenantID, ok := token.Meta["tenant_id"].(string)
	if !ok || tenantID == "" {
		return humanAccessClaims{}, errInvalidAccessToken
	}

	authVersion, ok := security.Uint64Claim(token.Meta["auth_version"])
	if !ok || authVersion == 0 {
		return humanAccessClaims{}, errInvalidAccessToken
	}

	tokenUse, ok := token.Meta["token_use"].(string)
	if !ok || tokenUse != "access" {
		return humanAccessClaims{}, errInvalidAccessToken
	}

	return humanAccessClaims{userID: userID, tenantID: tenantID, authVersion: authVersion}, nil
}

func (a *CompositeAuthenticator) checkHumanDenylist(ctx context.Context, tokenID string) error {
	if a.denylist == nil {
		return nil
	}

	denied, err := a.denylist.IsAccessTokenDenied(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("check human token denylist: %w", err)
	}

	if denied {
		return errInvalidAccessToken
	}

	return nil
}

func humanAudienceContains(audiences []string, want string) bool {
	for _, audience := range audiences {
		if audience == want {
			return true
		}
	}

	return false
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

// optionalBearerToken distinguishes an absent credential from a malformed
// credential. Compatibility mode may admit the former as legacy-v1, but must
// never turn a supplied invalid header into an anonymous downgrade.
//
//nolint:gocritic // Token, presence, and validation error are separate compatibility signals.
func optionalBearerToken(ctx context.Context) (string, bool, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md.Get("authorization")) == 0 {
		return "", false, nil
	}

	token, err := bearerToken(ctx)
	if err != nil {
		return "", true, err
	}

	return token, true, nil
}

type authTokenResolution struct {
	token  string
	legacy bool
}

func resolveAuthToken(ctx context.Context, method string, protectLegacy bool) (authTokenResolution, error) {
	if isLegacyCompatibilityMethod(method) && !protectLegacy {
		token, supplied, err := optionalBearerToken(ctx)
		if err != nil {
			return authTokenResolution{}, err
		}

		if !supplied {
			return authTokenResolution{legacy: true}, nil
		}

		return authTokenResolution{token: token}, nil
	}

	token, err := bearerToken(ctx)
	if err != nil {
		return authTokenResolution{}, err
	}

	return authTokenResolution{token: token}, nil
}

type unaryAuthConfig struct {
	protectLegacy bool
}

// UnaryAuthOption configures unary authentication compatibility.
type UnaryAuthOption func(*unaryAuthConfig)

// WithUnaryLegacyProtection requires a valid bearer token on schema.v1 when
// enabled. When disabled, only a truly absent credential becomes legacy-v1.
func WithUnaryLegacyProtection(enabled bool) UnaryAuthOption {
	return func(config *unaryAuthConfig) { config.protectLegacy = enabled }
}

// UnaryAuth injects a verified principal for every protected unary route.
func UnaryAuth(a Authenticator, public map[string]struct{}, options ...UnaryAuthOption) grpc.UnaryServerInterceptor {
	config := unaryAuthConfig{}
	for _, option := range options {
		option(&config)
	}

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if methodIsPublic(info.FullMethod, public) {
			return handler(ctx, req)
		}

		resolution, err := resolveAuthToken(ctx, info.FullMethod, config.protectLegacy)
		if err != nil {
			return nil, err
		}

		if resolution.legacy {
			return handler(principal.With(ctx, legacyCompatibilityPrincipal()), req)
		}

		if a == nil {
			return nil, status.Error(codes.Unauthenticated, "access token authentication is unavailable")
		}

		p, err := a.Authenticate(ctx, resolution.token)
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
	protectLegacy   bool
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

// WithStreamLegacyProtection requires bearer authentication on legacy
// schema.v1 streaming methods when enabled.
func WithStreamLegacyProtection(enabled bool) StreamAuthOption {
	return func(config *streamAuthConfig) { config.protectLegacy = enabled }
}

// StreamAuth injects a verified principal and ends a stream no later than the
// token expiry. Stateful authenticators are re-run while the stream is live so
// credential revocation and agent disable take effect without reconnecting.
//
//nolint:cyclop // Stream setup keeps public, compatibility, token, deadline, and monitor outcomes distinct.
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
		if methodIsPublic(info.FullMethod, public) {
			return handler(srv, stream)
		}

		resolution, err := resolveAuthToken(stream.Context(), info.FullMethod, config.protectLegacy)
		if err != nil {
			return err
		}

		if resolution.legacy {
			ctx := principal.With(stream.Context(), legacyCompatibilityPrincipal())

			return handler(srv, &principalStream{ServerStream: stream, ctx: ctx})
		}

		if a == nil {
			return status.Error(codes.Unauthenticated, "access token authentication is unavailable")
		}

		p, err := a.Authenticate(stream.Context(), resolution.token)
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
		go monitorStreamAuthentication(ctx, a, resolution.token, p, config.recheckInterval, cancel, monitorDone)

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
	return methodIsPublic(method, public)
}

func methodIsPublic(method string, public map[string]struct{}) bool {
	if _, ok := public[method]; ok {
		return true
	}

	return false
}

func legacyCompatibilityPrincipal() principal.Principal {
	return principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	}
}
