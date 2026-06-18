package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

// PermissionType represents different types of permissions.
type PermissionType string

const (
	PermissionSend    PermissionType = "send"
	PermissionReceive PermissionType = "receive"
	PermissionPurge   PermissionType = "purge"
	PermissionDelete  PermissionType = "delete"
)

// PermissionChecker interface for checking user permissions.
type PermissionChecker interface {
	HasQueuePermission(ctx context.Context, userID, queueID string, permission PermissionType) (bool, error)
}

// RequireQueuePermission middleware checks if the authenticated user has the required permission for a queue.
func RequireQueuePermission(permissionChecker PermissionChecker, permission PermissionType) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user from context.
			userInfo, ok := GetUserFromContext(r.Context())
			if !ok {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

				return
			}

			// Admin users have all permissions.
			for _, role := range userInfo.Roles {
				if role == "admin" {
					next.ServeHTTP(w, r)

					return
				}
			}

			// Get queue ID from URL parameter.
			queueID := chi.URLParam(r, "queueID")
			if queueID == "" {
				// Try alternative parameter names.
				queueID = chi.URLParam(r, "queue_id")
			}

			if queueID == "" {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID is required", errkit.ErrInvalidArgument))

				return
			}

			// Check if user has the required permission.
			hasPermission, err := permissionChecker.HasQueuePermission(r.Context(), userInfo.UserID, queueID, permission)
			if err != nil {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("check permission: %w", err))

				return
			}

			if !hasPermission {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthorized)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireQueueSendPermission is a convenience middleware for send permission.
func RequireQueueSendPermission(permissionChecker PermissionChecker) func(next http.Handler) http.Handler {
	return RequireQueuePermission(permissionChecker, PermissionSend)
}

// RequireQueueReceivePermission is a convenience middleware for receive permission.
func RequireQueueReceivePermission(permissionChecker PermissionChecker) func(next http.Handler) http.Handler {
	return RequireQueuePermission(permissionChecker, PermissionReceive)
}

// RequireQueuePurgePermission is a convenience middleware for purge permission.
func RequireQueuePurgePermission(permissionChecker PermissionChecker) func(next http.Handler) http.Handler {
	return RequireQueuePermission(permissionChecker, PermissionPurge)
}

// RequireQueueDeletePermission is a convenience middleware for delete permission.
func RequireQueueDeletePermission(permissionChecker PermissionChecker) func(next http.Handler) http.Handler {
	return RequireQueuePermission(permissionChecker, PermissionDelete)
}

// RequireAdminOrPermission allows admin users or users with specific queue permission.
func RequireAdminOrPermission(permissionChecker PermissionChecker, permission PermissionType) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user from context.
			userInfo, ok := GetUserFromContext(r.Context())
			if !ok {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

				return
			}

			// Check if user is admin.
			for _, role := range userInfo.Roles {
				if role == "admin" {
					next.ServeHTTP(w, r)

					return
				}
			}

			// Get queue ID from URL parameter.
			queueID := chi.URLParam(r, "queueID")
			if queueID == "" {
				queueID = chi.URLParam(r, "queue_id")
			}

			if queueID == "" {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID is required", errkit.ErrInvalidArgument))

				return
			}

			// Check if user has the required permission.
			hasPermission, err := permissionChecker.HasQueuePermission(r.Context(), userInfo.UserID, queueID, permission)
			if err != nil {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("check permission: %w", err))

				return
			}

			if !hasPermission {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthorized)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
