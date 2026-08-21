package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

// UserInfo represents authenticated user information.
type UserInfo struct {
	UserID      string
	Email       string
	Roles       []string
	TenantID    string
	AuthVersion uint64
	TokenID     string
}

// TokenDenylist reports whether an access token has been revoked (e.g. via
// sign-out) before its natural expiry. AuthenticateJWT consults it so a
// signed-out token stops working immediately instead of lingering for the
// access-token TTL.
type TokenDenylist interface {
	// IsAccessTokenDenied reports whether the given non-secret JWT ID is
	// currently denied.
	IsAccessTokenDenied(ctx context.Context, tokenID string) (bool, error)
}

// HumanSecurityResolver returns the mutable server-side account state used to
// invalidate otherwise valid signed tokens after a disable or role change.
type HumanSecurityResolver interface {
	ResolveHumanSecurity(ctx context.Context, userID string) (tenantID, status string, authVersion uint64, err error)
}

type jwtAuthConfig struct {
	issuer   string
	audience string
	security HumanSecurityResolver
}

// JWTAuthOption configures human HTTP token validation.
type JWTAuthOption func(*jwtAuthConfig)

// WithHumanSecurityResolver enables live tenant/status/version validation.
func WithHumanSecurityResolver(resolver HumanSecurityResolver) JWTAuthOption {
	return func(cfg *jwtAuthConfig) { cfg.security = resolver }
}

// WithHumanTokenPolicy selects the exact configured human issuer/audience.
func WithHumanTokenPolicy(issuer, audience string) JWTAuthOption {
	return func(cfg *jwtAuthConfig) {
		cfg.issuer = issuer
		cfg.audience = audience
	}
}

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// UserContextKey is the key used to store user info in request context.
	UserContextKey ContextKey = "user"
)

// AuthenticateJWT middleware validates JWT tokens and extracts user information.
// The denylist, when non-nil, is consulted after signature verification so a
// token that was signed out is rejected before its natural expiry.
func AuthenticateJWT(
	tokenManager jwtkit.TokenManager,
	denylist TokenDenylist,
	options ...JWTAuthOption,
) func(next http.Handler) http.Handler {
	cfg := jwtAuthConfig{issuer: "plainq-server", audience: "plainq-human"}
	for _, option := range options {
		option(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userInfo, outcome, err := authenticateJWTRequest(r.Context(), r.Header.Get("Authorization"), tokenManager, denylist, cfg)
			metrics.RecordAuthentication(metrics.SchemeJWT, outcome)

			if err != nil {
				httpkit.ErrorHTTP(w, r, err)

				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, userInfo)
			ctx = principal.With(ctx, principal.Principal{
				Kind: principal.KindHuman, ID: userInfo.UserID, TenantID: userInfo.TenantID,
				Roles: userInfo.Roles, AuthVersion: userInfo.AuthVersion, TokenID: userInfo.TokenID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authenticateJWTRequest(
	ctx context.Context,
	authHeader string,
	tokenManager jwtkit.TokenManager,
	denylist TokenDenylist,
	cfg jwtAuthConfig,
) (UserInfo, string, error) {
	tokenString, outcome, err := httpBearerToken(authHeader)
	if err != nil {
		return UserInfo{}, outcome, err
	}

	token, err := tokenManager.ParseVerify(tokenString)
	if err != nil {
		return UserInfo{}, metrics.AuthInvalidToken,
			fmt.Errorf("%w: invalid token: %s", errkit.ErrUnauthenticated, err.Error())
	}

	userInfo, err := userInfoFromToken(token, cfg)
	if err != nil {
		return UserInfo{}, metrics.AuthIncompleteClaims, err
	}

	if outcome, err := verifyTokenNotDenied(ctx, denylist, token.ID); err != nil {
		return UserInfo{}, outcome, err
	}

	if outcome, err := verifyLiveHumanSecurity(ctx, cfg.security, userInfo); err != nil {
		return UserInfo{}, outcome, err
	}

	return userInfo, metrics.AuthOK, nil
}

//nolint:gocritic // Token, metric outcome, and transport error are separate boundary results.
func httpBearerToken(authHeader string) (string, string, error) {
	if authHeader == "" {
		return "", metrics.AuthMissingCredentials, errkit.ErrUnauthenticated
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return "", metrics.AuthMalformedHeader,
			fmt.Errorf("%w: invalid authorization header format", errkit.ErrUnauthenticated)
	}

	return tokenString, "", nil
}

func verifyTokenNotDenied(ctx context.Context, denylist TokenDenylist, tokenID string) (string, error) {
	if denylist == nil {
		return "", nil
	}

	denied, err := denylist.IsAccessTokenDenied(ctx, tokenID)
	if err != nil {
		return metrics.AuthDenylistUnavailable, fmt.Errorf("check token denylist: %w", err)
	}

	if denied {
		return metrics.AuthRevokedToken, fmt.Errorf("%w: token has been revoked", errkit.ErrUnauthenticated)
	}

	return "", nil
}

func verifyLiveHumanSecurity(
	ctx context.Context,
	resolver HumanSecurityResolver,
	userInfo UserInfo,
) (string, error) {
	if resolver == nil {
		return "", nil
	}

	tenantID, status, authVersion, err := resolver.ResolveHumanSecurity(ctx, userInfo.UserID)
	if err != nil {
		return metrics.AuthDenylistUnavailable, fmt.Errorf("resolve live account security: %w", err)
	}

	if status != "active" || tenantID != userInfo.TenantID || authVersion != userInfo.AuthVersion {
		return metrics.AuthInvalidToken, fmt.Errorf("%w: stale account session", errkit.ErrUnauthenticated)
	}

	return "", nil
}

// userInfoFromToken extracts the authenticated identity from a verified token.
// Roles are optional — a token without them is still valid — but a missing user
// ID or email is not, since the rest of the stack keys authorization off them.
//
//nolint:cyclop // Every required human access-token claim is validated independently.
func userInfoFromToken(token *jwtkit.Token, cfg jwtAuthConfig) (UserInfo, error) {
	if err := validateHTTPRegisteredToken(token, cfg); err != nil {
		return UserInfo{}, err
	}

	userID, ok := token.Meta["uid"].(string)
	if !ok || userID == "" || token.Subject != userID {
		return UserInfo{}, fmt.Errorf("%w: missing user ID in token", errkit.ErrUnauthenticated)
	}

	email, ok := token.Meta["email"].(string)
	if !ok || email == "" {
		return UserInfo{}, fmt.Errorf("%w: missing email in token", errkit.ErrUnauthenticated)
	}

	if tokenUse, ok := token.Meta["token_use"].(string); !ok || tokenUse != "access" {
		return UserInfo{}, fmt.Errorf("%w: token is not an access token", errkit.ErrUnauthenticated)
	}

	tenantID, ok := token.Meta["tenant_id"].(string)
	if !ok || tenantID == "" {
		return UserInfo{}, fmt.Errorf("%w: missing tenant in token", errkit.ErrUnauthenticated)
	}

	authVersion, ok := security.Uint64Claim(token.Meta["auth_version"])
	if !ok || authVersion == 0 {
		return UserInfo{}, fmt.Errorf("%w: invalid auth version in token", errkit.ErrUnauthenticated)
	}

	return UserInfo{
		UserID: userID, Email: email, Roles: tokenRoles(token.Meta["roles"]), TenantID: tenantID,
		AuthVersion: authVersion, TokenID: token.ID,
	}, nil
}

func validateHTTPRegisteredToken(token *jwtkit.Token, cfg jwtAuthConfig) error {
	if token == nil || token.ID == "" || token.Subject == "" || token.ExpiresAt == nil || token.Issuer != cfg.issuer ||
		!containsAudience(token.Audience, cfg.audience) {
		return fmt.Errorf("%w: invalid registered token claims", errkit.ErrUnauthenticated)
	}

	return nil
}

func tokenRoles(value any) []string {
	rolesList, ok := value.([]any)
	if !ok {
		return nil
	}

	roles := make([]string, 0, len(rolesList))
	for _, role := range rolesList {
		if roleText, ok := role.(string); ok {
			roles = append(roles, roleText)
		}
	}

	return roles
}

func containsAudience(audiences []string, want string) bool {
	if want == "" {
		return false
	}

	for _, audience := range audiences {
		if audience == want {
			return true
		}
	}

	return false
}

// RequireRoles middleware ensures the authenticated user has at least one of the required roles.
func RequireRoles(requiredRoles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The check is labeled with the roles it demanded, not the roles
			// the caller had: the first is a fixed set defined by the routing
			// table, the second is unbounded user data.
			required := strings.Join(requiredRoles, "|")

			userInfo, ok := GetUserFromContext(r.Context())
			if !ok {
				metrics.RecordAuthorization(metrics.CheckRole, required, metrics.DecisionError)
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

				return
			}

			// Check if user has any of the required roles.
			hasRole := false

			for _, requiredRole := range requiredRoles {
				for _, userRole := range userInfo.Roles {
					if userRole == requiredRole {
						hasRole = true

						break
					}
				}

				if hasRole {
					break
				}
			}

			if !hasRole {
				metrics.RecordAuthorization(metrics.CheckRole, required, metrics.DecisionDeny)
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthorized)

				return
			}

			metrics.RecordAuthorization(metrics.CheckRole, required, metrics.DecisionAllow)

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin middleware ensures the authenticated user has admin role.
func RequireAdmin() func(next http.Handler) http.Handler {
	return RequireRoles("admin")
}

// GetUserFromContext extracts user information from the request context.
func GetUserFromContext(ctx context.Context) (UserInfo, bool) {
	userInfo, ok := ctx.Value(UserContextKey).(UserInfo)

	return userInfo, ok
}

// MustGetUserFromContext extracts user information from context, panics if not found.
func MustGetUserFromContext(ctx context.Context) UserInfo {
	userInfo, ok := GetUserFromContext(ctx)
	if !ok {
		panic("user not found in context")
	}

	return userInfo
}
