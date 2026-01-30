package auth

import (
	"context"
	"fmt"
)

// PermissionService handles queue permission checks.
type PermissionService struct {
	storage AuthStorage
}

// NewPermissionService creates a new permission service.
func NewPermissionService(storage AuthStorage) *PermissionService {
	return &PermissionService{storage: storage}
}

// CheckQueuePermission checks if a user with the given roles has permission to perform an action on a queue.
// Admins have full access to all queues regardless of specific permissions.
func (s *PermissionService) CheckQueuePermission(ctx context.Context, queueID string, roles []string, action PermissionAction) error {
	// Admin role has full access to all queues
	for _, role := range roles {
		if role == "admin" {
			return nil
		}
	}

	// Get role IDs from role names
	roleIDs := make([]string, 0, len(roles))
	for _, roleName := range roles {
		role, err := s.storage.GetRoleByName(ctx, roleName)
		if err != nil {
			continue // Skip roles that don't exist
		}
		roleIDs = append(roleIDs, role.RoleID)
	}

	if len(roleIDs) == 0 {
		return fmt.Errorf("no valid roles found")
	}

	// Get permissions for this queue and user's roles
	perm, err := s.storage.GetQueuePermissions(ctx, queueID, roleIDs)
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	// Check specific action permission
	switch action {
	case ActionSend:
		if !perm.CanSend {
			return fmt.Errorf("permission denied: cannot send to queue")
		}
	case ActionReceive:
		if !perm.CanReceive {
			return fmt.Errorf("permission denied: cannot receive from queue")
		}
	case ActionPurge:
		if !perm.CanPurge {
			return fmt.Errorf("permission denied: cannot purge queue")
		}
	case ActionDelete:
		if !perm.CanDelete {
			return fmt.Errorf("permission denied: cannot delete queue")
		}
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return nil
}

// HasRole checks if the given roles contain a specific role.
func HasRole(roles []string, targetRole string) bool {
	for _, role := range roles {
		if role == targetRole {
			return true
		}
	}
	return false
}

// IsAdmin checks if the user has admin role.
func IsAdmin(roles []string) bool {
	return HasRole(roles, "admin")
}
