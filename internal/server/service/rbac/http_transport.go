package rbac

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
	"github.com/marsolab/servekit/idkit"
)

// Role Management Handlers

func (s *Service) listRolesHandler(w http.ResponseWriter, r *http.Request) {
	roles, err := s.storage.GetAllRoles(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get all roles: %w", err))
		return
	}

	httpkit.JSON(w, r, roles)
}

func (s *Service) createRoleHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		RoleName string `json:"role_name"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("create role: close request body", slog.String("error", err.Error()))
		}
	}()

	if req.RoleName == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role name is required", errkit.ErrInvalidArgument))
		return
	}

	role := Role{
		RoleID:   idkit.ULID(),
		RoleName: req.RoleName,
	}

	if err := s.storage.CreateRole(r.Context(), role); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create role: %w", err))
		return
	}

	httpkit.JSON(w, r, role)
}

func (s *Service) getRoleHandler(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	if roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role ID is required", errkit.ErrInvalidArgument))
		return
	}

	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get role: %w", err))
		return
	}

	httpkit.JSON(w, r, role)
}

func (s *Service) updateRoleHandler(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	if roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role ID is required", errkit.ErrInvalidArgument))
		return
	}

	type request struct {
		RoleName string `json:"role_name"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("update role: close request body", slog.String("error", err.Error()))
		}
	}()

	if req.RoleName == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role name is required", errkit.ErrInvalidArgument))
		return
	}

	// Get existing role
	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get role: %w", err))
		return
	}

	// Update role name
	role.RoleName = req.RoleName

	if err := s.storage.UpdateRole(r.Context(), *role); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("update role: %w", err))
		return
	}

	httpkit.JSON(w, r, role)
}

func (s *Service) deleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	if roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role ID is required", errkit.ErrInvalidArgument))
		return
	}

	if err := s.storage.DeleteRole(r.Context(), roleID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("delete role: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// User Role Assignment Handlers

func (s *Service) getUserRolesHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID is required", errkit.ErrInvalidArgument))
		return
	}

	roles, err := s.storage.GetUserRoles(r.Context(), userID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get user roles: %w", err))
		return
	}

	httpkit.JSON(w, r, roles)
}

func (s *Service) assignRoleToUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	roleID := chi.URLParam(r, "roleID")

	if userID == "" || roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID and role ID are required", errkit.ErrInvalidArgument))
		return
	}

	if err := s.storage.AssignRoleToUser(r.Context(), userID, roleID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("assign role to user: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusCreated)
}

func (s *Service) removeRoleFromUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	roleID := chi.URLParam(r, "roleID")

	if userID == "" || roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID and role ID are required", errkit.ErrInvalidArgument))
		return
	}

	if err := s.storage.RemoveRoleFromUser(r.Context(), userID, roleID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("remove role from user: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// Queue Permission Handlers

func (s *Service) getQueuePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	if queueID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID is required", errkit.ErrInvalidArgument))
		return
	}

	// Get all roles and their permissions for this queue
	roles, err := s.storage.GetAllRoles(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get all roles: %w", err))
		return
	}

	type rolePermission struct {
		Role       Role            `json:"role"`
		Permission QueuePermission `json:"permission"`
	}

	var permissions []rolePermission

	for _, role := range roles {
		perm, err := s.storage.GetQueuePermissions(r.Context(), queueID, role.RoleID)
		if err != nil {
			// If no permission found, create default (no permissions)
			perm = &QueuePermission{
				QueueID:    queueID,
				RoleID:     role.RoleID,
				CanSend:    false,
				CanReceive: false,
				CanPurge:   false,
				CanDelete:  false,
			}
		}

		permissions = append(permissions, rolePermission{
			Role:       role,
			Permission: *perm,
		})
	}

	httpkit.JSON(w, r, permissions)
}

func (s *Service) getQueueRolePermissionHandler(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	roleID := chi.URLParam(r, "roleID")

	if queueID == "" || roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID and role ID are required", errkit.ErrInvalidArgument))
		return
	}

	permission, err := s.storage.GetQueuePermissions(r.Context(), queueID, roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get queue permission: %w", err))
		return
	}

	httpkit.JSON(w, r, permission)
}

func (s *Service) updateQueuePermissionHandler(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	roleID := chi.URLParam(r, "roleID")

	if queueID == "" || roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID and role ID are required", errkit.ErrInvalidArgument))
		return
	}

	type request struct {
		CanSend    bool `json:"can_send"`
		CanReceive bool `json:"can_receive"`
		CanPurge   bool `json:"can_purge"`
		CanDelete  bool `json:"can_delete"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("update queue permission: close request body", slog.String("error", err.Error()))
		}
	}()

	permission := QueuePermission{
		QueueID:    queueID,
		RoleID:     roleID,
		CanSend:    req.CanSend,
		CanReceive: req.CanReceive,
		CanPurge:   req.CanPurge,
		CanDelete:  req.CanDelete,
	}

	// Try to get existing permission first
	existingPerm, err := s.storage.GetQueuePermissions(r.Context(), queueID, roleID)
	if err != nil {
		// Create new permission if it doesn't exist
		if err := s.storage.CreateQueuePermission(r.Context(), permission); err != nil {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("create queue permission: %w", err))
			return
		}
	} else {
		// Update existing permission
		permission.CreatedAt = existingPerm.CreatedAt
		if err := s.storage.UpdateQueuePermission(r.Context(), permission); err != nil {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("update queue permission: %w", err))
			return
		}
	}

	httpkit.JSON(w, r, permission)
}

func (s *Service) deleteQueuePermissionHandler(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	roleID := chi.URLParam(r, "roleID")

	if queueID == "" || roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID and role ID are required", errkit.ErrInvalidArgument))
		return
	}

	if err := s.storage.DeleteQueuePermission(r.Context(), queueID, roleID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("delete queue permission: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// Permission Checking Handler

func (s *Service) checkQueuePermissionHandler(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	permissionStr := chi.URLParam(r, "permission")

	if queueID == "" || permissionStr == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID and permission are required", errkit.ErrInvalidArgument))
		return
	}

	// Get user from context
	userInfo, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)
		return
	}

	// Validate permission type
	var permission PermissionType

	switch permissionStr {
	case "send":
		permission = PermissionSend
	case "receive":
		permission = PermissionReceive
	case "purge":
		permission = PermissionPurge
	case "delete":
		permission = PermissionDelete
	default:
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: invalid permission type", errkit.ErrInvalidArgument))
		return
	}

	hasPermission, err := s.storage.HasQueuePermission(r.Context(), userInfo.UserID, queueID, permission)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("check queue permission: %w", err))
		return
	}

	type response struct {
		HasPermission bool `json:"has_permission"`
	}

	httpkit.JSON(w, r, response{HasPermission: hasPermission})
}
