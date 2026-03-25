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

// UserInfo represents authenticated user information
type UserInfo struct {
	UserID string
	Email  string
	Roles  []string
}

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// UserContextKey is the key used to store user info in request context
	UserContextKey ContextKey = "user"
)

// AuthenticateJWT middleware validates JWT tokens and extracts user information
func AuthenticateJWT(tokenManager jwtkit.TokenManager) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)
				return
			}

			// Remove "Bearer " prefix
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: invalid authorization header format", errkit.ErrUnauthenticated))
				return
			}

			// Parse and verify the token
			token, err := tokenManager.ParseVerify(tokenString)
			if err != nil {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: invalid token: %s", errkit.ErrUnauthenticated, err.Error()))
				return
			}

			// Extract user ID from token
			userID, ok := token.Meta["uid"].(string)
			if !ok {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: missing user ID in token", errkit.ErrUnauthenticated))
				return
			}

			// Extract email from token
			email, ok := token.Meta["email"].(string)
			if !ok {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: missing email in token", errkit.ErrUnauthenticated))
				return
			}

			// Extract roles from token (optional)
			var roles []string
			if rolesInterface, exists := token.Meta["roles"]; exists {
				if rolesList, ok := rolesInterface.([]interface{}); ok {
					for _, role := range rolesList {
						if roleStr, ok := role.(string); ok {
							roles = append(roles, roleStr)
						}
					}
				}
			}

			// Store user info in context
			userInfo := UserInfo{
				UserID: userID,
				Email:  email,
				Roles:  roles,
			}

			ctx := context.WithValue(r.Context(), UserContextKey, userInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRoles middleware ensures the authenticated user has at least one of the required roles
func RequireRoles(requiredRoles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userInfo, ok := GetUserFromContext(r.Context())
			if !ok {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)
				return
			}

			// Check if user has any of the required roles
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

// RequireAdmin middleware ensures the authenticated user has admin role
func RequireAdmin() func(next http.Handler) http.Handler {
	return RequireRoles("admin")
}

// GetUserFromContext extracts user information from the request context
func GetUserFromContext(ctx context.Context) (UserInfo, bool) {
	userInfo, ok := ctx.Value(UserContextKey).(UserInfo)
	return userInfo, ok
}

// MustGetUserFromContext extracts user information from context, panics if not found
func MustGetUserFromContext(ctx context.Context) UserInfo {
	userInfo, ok := GetUserFromContext(ctx)
	if !ok {
		panic("user not found in context")
	}
	return userInfo
}
