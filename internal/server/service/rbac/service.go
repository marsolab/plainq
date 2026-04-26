package rbac

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/config"
)

// Storage encapsulates interaction with RBAC storage.
//
//nolint:interfacebloat // domain interface for the RBAC subsystem (roles, permissions, assignments).
type Storage interface {
	// Role management
	CreateRole(ctx context.Context, role Role) error
	GetRoleByID(ctx context.Context, roleID string) (*Role, error)
	GetRoleByName(ctx context.Context, roleName string) (*Role, error)
	GetAllRoles(ctx context.Context) ([]Role, error)
	UpdateRole(ctx context.Context, role Role) error
	DeleteRole(ctx context.Context, roleID string) error

	// User role management
	AssignRoleToUser(ctx context.Context, userID, roleID string) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
	GetUsersWithRole(ctx context.Context, roleID string) ([]string, error)

	// Permission management
	CreateQueuePermission(ctx context.Context, permission QueuePermission) error
	GetQueuePermissions(ctx context.Context, queueID, roleID string) (*QueuePermission, error)
	GetRoleQueuePermissions(ctx context.Context, roleID string) ([]QueuePermission, error)
	UpdateQueuePermission(ctx context.Context, permission QueuePermission) error
	DeleteQueuePermission(ctx context.Context, queueID, roleID string) error

	// User permission checking
	HasQueuePermission(ctx context.Context, userID, queueID string, permission PermissionType) (bool, error)
}

// Role represents a role in the system
type Role struct {
	RoleID    string    `json:"role_id"`
	RoleName  string    `json:"role_name"`
	CreatedAt time.Time `json:"created_at"`
}

// QueuePermission represents permissions for a specific queue and role
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

// PermissionType represents different types of permissions
type PermissionType string

const (
	PermissionSend    PermissionType = "send"
	PermissionReceive PermissionType = "receive"
	PermissionPurge   PermissionType = "purge"
	PermissionDelete  PermissionType = "delete"
)

// UserRole represents the relationship between a user and their roles
type UserRole struct {
	UserID    string    `json:"user_id"`
	RoleID    string    `json:"role_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Service handles RBAC operations
type Service struct {
	cfg     *config.Config
	logger  *slog.Logger
	router  *chi.Mux
	storage Storage
}

// NewService creates a new RBAC service
func NewService(cfg *config.Config, logger *slog.Logger, storage Storage) *Service {
	s := Service{
		cfg:     cfg,
		logger:  logger,
		router:  chi.NewRouter(),
		storage: storage,
	}

	// Setup routes
	s.router.Route("/", func(r chi.Router) {
		// Role management routes
		r.Route("/roles", func(r chi.Router) {
			r.Get("/", s.listRolesHandler)
			r.Post("/", s.createRoleHandler)
			r.Get("/{roleID}", s.getRoleHandler)
			r.Put("/{roleID}", s.updateRoleHandler)
			r.Delete("/{roleID}", s.deleteRoleHandler)
		})

		// User role assignment routes
		r.Route("/users/{userID}/roles", func(r chi.Router) {
			r.Get("/", s.getUserRolesHandler)
			r.Post("/{roleID}", s.assignRoleToUserHandler)
			r.Delete("/{roleID}", s.removeRoleFromUserHandler)
		})

		// Queue permission routes
		r.Route("/permissions", func(r chi.Router) {
			r.Route("/queues/{queueID}", func(r chi.Router) {
				r.Get("/", s.getQueuePermissionsHandler)
				r.Route("/roles/{roleID}", func(r chi.Router) {
					r.Get("/", s.getQueueRolePermissionHandler)
					r.Put("/", s.updateQueuePermissionHandler)
					r.Delete("/", s.deleteQueuePermissionHandler)
				})
			})
		})

		// Permission checking routes
		r.Route("/check", func(r chi.Router) {
			r.Get("/queue/{queueID}/permission/{permission}", s.checkQueuePermissionHandler)
		})
	})

	return &s
}

// ServeHTTP implements the http.Handler interface
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// HasPermission checks if a user has a specific permission for a queue
func (s *Service) HasPermission(ctx context.Context, userID, queueID string, permission PermissionType) (bool, error) {
	return s.storage.HasQueuePermission(ctx, userID, queueID, permission)
}

// GetUserRoles returns all roles assigned to a user
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	return s.storage.GetUserRoles(ctx, userID)
}

// AssignRole assigns a role to a user
func (s *Service) AssignRole(ctx context.Context, userID, roleID string) error {
	return s.storage.AssignRoleToUser(ctx, userID, roleID)
}

// RemoveRole removes a role from a user
func (s *Service) RemoveRole(ctx context.Context, userID, roleID string) error {
	return s.storage.RemoveRoleFromUser(ctx, userID, roleID)
}
