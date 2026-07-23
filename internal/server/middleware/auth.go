package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

// UserInfo represents authenticated user information.
type UserInfo struct {
	UserID string
	Email  string
	Roles  []string
}

// TokenDenylist reports whether an access token has been revoked (e.g. via
// sign-out) before its natural expiry. AuthenticateJWT consults it so a
// signed-out token stops working immediately instead of lingering for the
// access-token TTL.
type TokenDenylist interface {
	// IsAccessTokenDenied reports whether the given raw access token (without
	// the "Bearer " prefix) is currently denied.
	IsAccessTokenDenied(ctx context.Context, token string) (bool, error)
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
func AuthenticateJWT(tokenManager jwtkit.TokenManager, denylist TokenDenylist) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

				return
			}

			// Remove "Bearer " prefix.
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: invalid authorization header format", errkit.ErrUnauthenticated))

				return
			}

			// Parse and verify the token.
			token, err := tokenManager.ParseVerify(tokenString)
			if err != nil {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: invalid token: %s", errkit.ErrUnauthenticated, err.Error()))

				return
			}

			// A valid signature is not enough: a signed-out token stays
			// cryptographically valid until it expires, so honor the denylist.
			// Fail closed on a lookup error rather than admit an unverifiable
			// token.
			if denylist != nil {
				denied, denyErr := denylist.IsAccessTokenDenied(r.Context(), tokenString)
				if denyErr != nil {
					httpkit.ErrorHTTP(w, r, fmt.Errorf("check token denylist: %w", denyErr))

					return
				}

				if denied {
					httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: token has been revoked", errkit.ErrUnauthenticated))

					return
				}
			}

			userInfo, err := userInfoFromToken(token)
			if err != nil {
				httpkit.ErrorHTTP(w, r, err)

				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, userInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// userInfoFromToken extracts the authenticated identity from a verified token.
// Roles are optional — a token without them is still valid — but a missing user
// ID or email is not, since the rest of the stack keys authorization off them.
func userInfoFromToken(token *jwtkit.Token) (UserInfo, error) {
	userID, ok := token.Meta["uid"].(string)
	if !ok {
		return UserInfo{}, fmt.Errorf("%w: missing user ID in token", errkit.ErrUnauthenticated)
	}

	email, ok := token.Meta["email"].(string)
	if !ok {
		return UserInfo{}, fmt.Errorf("%w: missing email in token", errkit.ErrUnauthenticated)
	}

	var roles []string

	if rolesInterface, exists := token.Meta["roles"]; exists {
		if rolesList, ok := rolesInterface.([]any); ok {
			for _, role := range rolesList {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, roleStr)
				}
			}
		}
	}

	return UserInfo{
		UserID: userID,
		Email:  email,
		Roles:  roles,
	}, nil
}

// RequireRoles middleware ensures the authenticated user has at least one of the required roles.
func RequireRoles(requiredRoles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userInfo, ok := GetUserFromContext(r.Context())
			if !ok {
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
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthorized)

				return
			}

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
