package rbac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/middleware"
)

// Storage encapsulates interaction with RBAC storage.
//
//nolint:interfacebloat // domain interface for the RBAC subsystem (roles, permissions, assignments).
type Storage interface {
	// Role management.
	CreateRole(ctx context.Context, role Role) error
	GetRoleByID(ctx context.Context, roleID string) (*Role, error)
	GetRoleByName(ctx context.Context, roleName string) (*Role, error)
	GetAllRoles(ctx context.Context) ([]Role, error)
	UpdateRole(ctx context.Context, role Role) error
	DeleteRole(ctx context.Context, roleID string) error

	// User role management.

	// AssignRoleToUser grants a role. It reports ErrRoleAlreadyAssigned when
	// the user already holds it, so a caller can tell a change from a no-op.
	AssignRoleToUser(ctx context.Context, userID, roleID string) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error

	// RemoveRoleFromUserUnlessLastHolder removes the assignment only if another
	// account still holds the role, reporting ErrLastRoleHolder when it would
	// empty it. The condition is part of the delete rather than a read before
	// it: two concurrent removals of the last two administrators would each see
	// the other and both succeed, leaving a deployment nobody can administer.
	RemoveRoleFromUserUnlessLastHolder(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
	GetUsersWithRole(ctx context.Context, roleID string) ([]string, error)
	CountUsersWithRole(ctx context.Context, roleID string) (int64, error)
	CountUsersPerRole(ctx context.Context) (map[string]int64, error)

	// Permission management.
	CreateQueuePermission(ctx context.Context, permission QueuePermission) error
	GetQueuePermissions(ctx context.Context, queueID, roleID string) (*QueuePermission, error)
	GetRoleQueuePermissions(ctx context.Context, roleID string) ([]QueuePermission, error)
	UpdateQueuePermission(ctx context.Context, permission QueuePermission) error
	DeleteQueuePermission(ctx context.Context, queueID, roleID string) error

	// ReplaceRoleQueuePermissions stores exactly the given grants for the role
	// and removes every other grant it held, in one transaction. A permission
	// matrix is saved as a whole, so a partly applied one — a role that can
	// receive but, for one failed row, can no longer send — must not be
	// reachable.
	ReplaceRoleQueuePermissions(ctx context.Context, roleID string, permissions []QueuePermission) error

	// User permission checking.
	HasQueuePermission(ctx context.Context, userID, queueID string, permission PermissionType) (bool, error)
}

// AdminRoleName is the role the authorization middleware checks for. It is
// named here because several guards exist only to keep it reachable: the last
// account holding it cannot lose it, and the role itself cannot be deleted.
const AdminRoleName = "admin"

// ErrRoleAlreadyAssigned reports that a user already holds the role, so the
// assignment changed nothing. It is distinct from success because a caller
// showing "role added" for a no-op is describing a change that did not happen.
var ErrRoleAlreadyAssigned = errors.New("role already assigned to user")

// ErrLastRoleHolder reports that the removal was refused because it would leave
// the role with no holders.
var ErrLastRoleHolder = errors.New("account is the last holder of the role")

// Role represents a role in the system.
type Role struct {
	RoleID    string    `json:"role_id"`
	RoleName  string    `json:"role_name"`
	CreatedAt time.Time `json:"created_at"`
}

// QueuePermission represents permissions for a specific queue and role.
type QueuePermission struct {
	QueueID    string    `json:"queue_id"`
	RoleID     string    `json:"role_id"`
	CanSend    bool      `json:"can_send"`
	CanReceive bool      `json:"can_receive"`
	CanPurge   bool      `json:"can_purge"`
	CanDelete  bool      `json:"can_delete"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PermissionType represents different types of permissions.
type PermissionType string

const (
	PermissionSend    PermissionType = "send"
	PermissionReceive PermissionType = "receive"
	PermissionPurge   PermissionType = "purge"
	PermissionDelete  PermissionType = "delete"
)

// UserRole represents the relationship between a user and their roles.
type UserRole struct {
	UserID    string    `json:"user_id"`
	RoleID    string    `json:"role_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Service handles RBAC operations.
type Service struct {
	cfg     *config.Config
	logger  *slog.Logger
	router  *chi.Mux
	storage Storage
}

// NewService creates a new RBAC service.
func NewService(cfg *config.Config, logger *slog.Logger, storage Storage) *Service {
	s := Service{
		cfg:     cfg,
		logger:  logger,
		router:  chi.NewRouter(),
		storage: storage,
	}

	// Reading the authorization model is available to any authenticated caller
	// so an operator console can show a truthful read-only view; changing it is
	// an administrator's operation. Without this gate any account could grant
	// itself the admin role, which is the whole model in one request.
	admin := func(r chi.Router) {
		if cfg.AuthEnable {
			r.Use(middleware.RequireAdmin())
		}
	}

	// Setup routes.
	s.router.Route("/", func(r chi.Router) {
		// Role management routes.
		r.Route("/roles", func(r chi.Router) {
			r.Get("/", s.listRolesHandler)
			r.Get("/{roleID}", s.getRoleHandler)

			r.Group(func(r chi.Router) {
				admin(r)
				r.Post("/", s.createRoleHandler)
				r.Put("/{roleID}", s.updateRoleHandler)
				r.Delete("/{roleID}", s.deleteRoleHandler)
			})
		})

		// User role assignment routes.
		r.Route("/users/{userID}/roles", func(r chi.Router) {
			r.Get("/", s.getUserRolesHandler)

			r.Group(func(r chi.Router) {
				admin(r)
				r.Post("/{roleID}", s.assignRoleToUserHandler)
				r.Delete("/{roleID}", s.removeRoleFromUserHandler)
			})
		})

		// Queue permission routes.
		r.Route("/permissions", func(r chi.Router) {
			r.Route("/queues/{queueID}", func(r chi.Router) {
				r.Get("/", s.getQueuePermissionsHandler)
				r.Route("/roles/{roleID}", func(r chi.Router) {
					r.Get("/", s.getQueueRolePermissionHandler)

					r.Group(func(r chi.Router) {
						admin(r)
						r.Put("/", s.updateQueuePermissionHandler)
						r.Delete("/", s.deleteQueuePermissionHandler)
					})
				})
			})

			// A role's whole matrix, which is how an operator edits it: one
			// read of every grant the role holds and one atomic write back.
			r.Route("/roles/{roleID}", func(r chi.Router) {
				r.Get("/", s.getRolePermissionsHandler)

				r.Group(func(r chi.Router) {
					admin(r)
					r.Put("/", s.replaceRolePermissionsHandler)
				})
			})
		})

		// Permission checking routes.
		r.Route("/check", func(r chi.Router) {
			r.Get("/queue/{queueID}/permission/{permission}", s.checkQueuePermissionHandler)
		})
	})

	return &s
}

// ServeHTTP implements the http.Handler interface.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// HasPermission checks if a user has a specific permission for a queue.
func (s *Service) HasPermission(ctx context.Context, userID, queueID string, permission PermissionType) (bool, error) {
	ok, err := s.storage.HasQueuePermission(ctx, userID, queueID, permission)
	if err != nil {
		return false, fmt.Errorf("check queue permission: %w", err)
	}

	return ok, nil
}

// GetUserRoles returns all roles assigned to a user.
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	roles, err := s.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}

	return roles, nil
}

// AssignRole assigns a role to a user.
func (s *Service) AssignRole(ctx context.Context, userID, roleID string) error {
	if err := s.storage.AssignRoleToUser(ctx, userID, roleID); err != nil {
		return fmt.Errorf("assign role to user: %w", err)
	}

	return nil
}

// RemoveRole removes a role from a user.
func (s *Service) RemoveRole(ctx context.Context, userID, roleID string) error {
	if err := s.storage.RemoveRoleFromUser(ctx, userID, roleID); err != nil {
		return fmt.Errorf("remove role from user: %w", err)
	}

	return nil
}
