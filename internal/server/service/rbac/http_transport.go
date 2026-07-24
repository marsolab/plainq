package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
	"github.com/marsolab/servekit/idkit"
)

// RoleWithUsage is a role plus the number of accounts holding it. The count is
// what makes "delete this role" answerable without a second request, and it is
// read from the database rather than inferred from a page of users.
type RoleWithUsage struct {
	Role
	UserCount int64 `json:"user_count"`
}

// Role Management Handlers.

func (s *Service) listRolesHandler(w http.ResponseWriter, r *http.Request) {
	roles, err := s.storage.GetAllRoles(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get all roles: %w", err)))

		return
	}

	counts, err := s.storage.CountUsersPerRole(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("count users per role: %w", err)))

		return
	}

	out := make([]RoleWithUsage, 0, len(roles))
	for _, role := range roles {
		out = append(out, RoleWithUsage{Role: role, UserCount: counts[role.RoleID]})
	}

	httpkit.JSON(w, r, out)
}

func (s *Service) createRoleHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		RoleName string `json:"role_name"`
	}

	var req request
	if err := s.decode(r, &req, "create role"); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	if req.RoleName == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role name is required", errkit.ErrInvalidArgument))

		return
	}

	role := Role{
		RoleID:   idkit.ULID(),
		RoleName: req.RoleName,
	}

	if err := s.storage.CreateRole(r.Context(), role); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("create role: %w", err)))

		return
	}

	httpkit.JSON(w, r, role, httpkit.WithStatus(http.StatusCreated))
}

func (s *Service) getRoleHandler(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	if roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role ID is required", errkit.ErrInvalidArgument))

		return
	}

	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role: %w", err)))

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
	if err := s.decode(r, &req, "update role"); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	if req.RoleName == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role name is required", errkit.ErrInvalidArgument))

		return
	}

	// Get existing role.
	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role: %w", err)))

		return
	}

	// Renaming the administrator role would leave the authorization middleware
	// looking for a role that no longer exists, locking every operator out.
	if role.RoleName == AdminRoleName && req.RoleName != AdminRoleName {
		httpkit.ErrorHTTP(w, r, fmt.Errorf(
			"%w: the %q role cannot be renamed — authorization checks resolve it by name",
			errkit.ErrInvalidArgument, AdminRoleName,
		))

		return
	}

	// Update role name.
	role.RoleName = req.RoleName

	if err := s.storage.UpdateRole(r.Context(), *role); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("update role: %w", err)))

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

	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role: %w", err)))

		return
	}

	if role.RoleName == AdminRoleName {
		httpkit.ErrorHTTP(w, r, fmt.Errorf(
			"%w: the %q role cannot be deleted — it is the role authorization checks resolve",
			errkit.ErrInvalidArgument, AdminRoleName,
		))

		return
	}

	// Deleting a role in use cascades its assignments away, silently reducing
	// what its holders can do. Refuse and say how many accounts are affected.
	holders, err := s.storage.CountUsersWithRole(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("count users with role: %w", err)))

		return
	}

	if holders > 0 {
		httpkit.ErrorHTTP(w, r, fmt.Errorf(
			"%w: %d account(s) still hold this role — reassign them first",
			errkit.ErrAlreadyExists, holders,
		))

		return
	}

	if err := s.storage.DeleteRole(r.Context(), roleID); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("delete role: %w", err)))

		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// User Role Assignment Handlers.

func (s *Service) getUserRolesHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID is required", errkit.ErrInvalidArgument))

		return
	}

	roles, err := s.storage.GetUserRoles(r.Context(), userID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get user roles: %w", err)))

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

	// Resolving the role first turns "no such role" into a 404 rather than a
	// foreign-key failure the caller cannot act on.
	if _, err := s.storage.GetRoleByID(r.Context(), roleID); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role: %w", err)))

		return
	}

	if err := s.storage.AssignRoleToUser(r.Context(), userID, roleID); err != nil {
		if errors.Is(err, ErrRoleAlreadyAssigned) {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user already holds this role", errkit.ErrAlreadyExists))

			return
		}

		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("assign role to user: %w", err)))

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

	if err := s.guardLastAdministrator(r, userID, roleID); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	if err := s.storage.RemoveRoleFromUser(r.Context(), userID, roleID); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("remove role from user: %w", err)))

		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// guardLastAdministrator refuses the removal that would leave the deployment
// with no administrator. The UI states this rule, but stating it is not
// enforcing it: the check has to happen where the write happens.
func (s *Service) guardLastAdministrator(r *http.Request, userID, roleID string) error {
	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		return pqerr.AsTransport(fmt.Errorf("get role: %w", err))
	}

	if role.RoleName != AdminRoleName {
		return nil
	}

	holders, err := s.storage.GetUsersWithRole(r.Context(), roleID)
	if err != nil {
		return pqerr.AsTransport(fmt.Errorf("get users with role: %w", err))
	}

	// Only the removal that empties the role is refused; removing it from
	// somebody who is one of several administrators is ordinary work.
	for _, holder := range holders {
		if holder != userID {
			return nil
		}
	}

	if len(holders) == 0 {
		return nil
	}

	return fmt.Errorf(
		"%w: this is the only account with the %q role — assign it to another account first",
		errkit.ErrAlreadyExists, AdminRoleName,
	)
}

// Queue Permission Handlers.

// QueueRolePermission pairs a role with its grants on one queue.
type QueueRolePermission struct {
	Role       Role            `json:"role"`
	UserCount  int64           `json:"user_count"`
	Permission QueuePermission `json:"permission"`

	// Granted marks a row the server actually stores. A role with no row is
	// reported with an all-false permission set and Granted false, so "nothing
	// granted" is never mistaken for "explicitly denied".
	Granted bool `json:"granted"`
}

func (s *Service) getQueuePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	if queueID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID is required", errkit.ErrInvalidArgument))

		return
	}

	roles, err := s.storage.GetAllRoles(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get all roles: %w", err)))

		return
	}

	counts, err := s.storage.CountUsersPerRole(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("count users per role: %w", err)))

		return
	}

	permissions := make([]QueueRolePermission, 0, len(roles))

	for _, role := range roles {
		row := QueueRolePermission{
			Role:      role,
			UserCount: counts[role.RoleID],
			Permission: QueuePermission{
				QueueID: queueID,
				RoleID:  role.RoleID,
			},
		}

		perm, err := s.storage.GetQueuePermissions(r.Context(), queueID, role.RoleID)

		switch {
		case err == nil:
			row.Permission = *perm
			row.Granted = true

		case errors.Is(err, pqerr.ErrNotFound):
			// No row means no grant. That is an answer, not a failure.

		default:
			// A storage failure previously read as "nothing granted", which is
			// the one answer an authorization view must never invent.
			httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get queue permission: %w", err)))

			return
		}

		permissions = append(permissions, row)
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
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get queue permission: %w", err)))

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

	var req permissionRequest
	if err := s.decode(r, &req, "update queue permission"); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	permission := QueuePermission{
		QueueID:    queueID,
		RoleID:     roleID,
		CanSend:    req.CanSend,
		CanReceive: req.CanReceive,
		CanPurge:   req.CanPurge,
		CanDelete:  req.CanDelete,
	}

	existingPerm, err := s.storage.GetQueuePermissions(r.Context(), queueID, roleID)

	switch {
	case err == nil:
		permission.CreatedAt = existingPerm.CreatedAt

		if err := s.storage.UpdateQueuePermission(r.Context(), permission); err != nil {
			httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("update queue permission: %w", err)))

			return
		}

	case errors.Is(err, pqerr.ErrNotFound):
		if err := s.storage.CreateQueuePermission(r.Context(), permission); err != nil {
			httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("create queue permission: %w", err)))

			return
		}

	default:
		// Writing a fresh row after a failed read would overwrite grants the
		// read could not see.
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get queue permission: %w", err)))

		return
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
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("delete queue permission: %w", err)))

		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// Role Permission Matrix Handlers.

type permissionRequest struct {
	CanSend    bool `json:"can_send"`
	CanReceive bool `json:"can_receive"`
	CanPurge   bool `json:"can_purge"`
	CanDelete  bool `json:"can_delete"`
}

// RolePermissions is one role's whole grant set.
type RolePermissions struct {
	Role   Role              `json:"role"`
	Grants []QueuePermission `json:"grants"`
}

func (s *Service) getRolePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	if roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role ID is required", errkit.ErrInvalidArgument))

		return
	}

	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role: %w", err)))

		return
	}

	grants, err := s.storage.GetRoleQueuePermissions(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role queue permissions: %w", err)))

		return
	}

	if grants == nil {
		grants = []QueuePermission{}
	}

	httpkit.JSON(w, r, RolePermissions{Role: *role, Grants: grants})
}

func (s *Service) replaceRolePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "roleID")
	if roleID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: role ID is required", errkit.ErrInvalidArgument))

		return
	}

	type grantRequest struct {
		QueueID string `json:"queue_id"`

		permissionRequest
	}

	type request struct {
		Grants []grantRequest `json:"grants"`
	}

	role, err := s.storage.GetRoleByID(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role: %w", err)))

		return
	}

	var req request
	if err := s.decode(r, &req, "replace role permissions"); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	seen := make(map[string]struct{}, len(req.Grants))
	permissions := make([]QueuePermission, 0, len(req.Grants))

	for _, grant := range req.Grants {
		if grant.QueueID == "" {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: every grant needs a queue ID", errkit.ErrInvalidArgument))

			return
		}

		// Two rows for one queue have no defined winner; picking one silently
		// would store grants the caller never asked for.
		if _, duplicate := seen[grant.QueueID]; duplicate {
			httpkit.ErrorHTTP(w, r, fmt.Errorf(
				"%w: queue %s appears more than once", errkit.ErrInvalidArgument, grant.QueueID,
			))

			return
		}

		seen[grant.QueueID] = struct{}{}

		permissions = append(permissions, QueuePermission{
			QueueID:    grant.QueueID,
			RoleID:     roleID,
			CanSend:    grant.CanSend,
			CanReceive: grant.CanReceive,
			CanPurge:   grant.CanPurge,
			CanDelete:  grant.CanDelete,
		})
	}

	if err := s.storage.ReplaceRoleQueuePermissions(r.Context(), roleID, permissions); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("replace role queue permissions: %w", err)))

		return
	}

	// Answer with what was stored rather than with what was sent: the response
	// is the value a reload will show.
	stored, err := s.storage.GetRoleQueuePermissions(r.Context(), roleID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get role queue permissions: %w", err)))

		return
	}

	if stored == nil {
		stored = []QueuePermission{}
	}

	httpkit.JSON(w, r, RolePermissions{Role: *role, Grants: stored})
}

// Permission Checking Handler.

func (s *Service) checkQueuePermissionHandler(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "queueID")
	permissionStr := chi.URLParam(r, "permission")

	if queueID == "" || permissionStr == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: queue ID and permission are required", errkit.ErrInvalidArgument))

		return
	}

	// Get user from context.
	userInfo, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

		return
	}

	// Validate permission type.
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
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("check queue permission: %w", err)))

		return
	}

	type response struct {
		HasPermission bool `json:"has_permission"`
	}

	httpkit.JSON(w, r, response{HasPermission: hasPermission})
}

// decode reads a JSON request body, closing it whatever happens.
func (s *Service) decode(r *http.Request, target any, op string) error {
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error(op+": close request body", slog.String("error", err.Error()))
		}
	}()

	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error())
	}

	return nil
}
