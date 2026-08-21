package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/server/service/rbac/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements rbac.Storage.
var _ rbac.Storage = (*Storage)(nil)

// Storage is the SQLite-backed implementation of rbac.Storage.
type Storage struct {
	db      pqlite.DB
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the storage's logger.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

// NewStorage creates a new SQLite-backed rbac storage.
func NewStorage(db pqlite.DB, logger *slog.Logger, opts ...Option) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	s := &Storage{
		db:      db,
		queries: sqlcgen.New(db),
		logger:  logger,
	}

	if s.logger == nil {
		s.logger = logkit.NewNop()
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

func (s *Storage) CreateRole(ctx context.Context, role rbac.Role) error {
	createdAt := role.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	if err := s.queries.CreateRole(ctx, sqlcgen.CreateRoleParams{
		RoleID:    role.RoleID,
		RoleName:  role.RoleName,
		CreatedAt: createdAt,
	}); err != nil {
		return fmt.Errorf("create role: %w", err)
	}

	return nil
}

func (s *Storage) GetRoleByID(ctx context.Context, roleID string) (*rbac.Role, error) {
	row, err := s.queries.GetRoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("role not found: %w", pqerr.ErrNotFound)
		}

		return nil, fmt.Errorf("get role by id: %w", err)
	}

	return &rbac.Role{
		RoleID:    row.RoleID,
		RoleName:  row.RoleName,
		CreatedAt: row.CreatedAt,
	}, nil
}

func (s *Storage) GetRoleByName(ctx context.Context, roleName string) (*rbac.Role, error) {
	row, err := s.queries.GetRoleByName(ctx, roleName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("role not found: %w", pqerr.ErrNotFound)
		}

		return nil, fmt.Errorf("get role by name: %w", err)
	}

	return &rbac.Role{
		RoleID:    row.RoleID,
		RoleName:  row.RoleName,
		CreatedAt: row.CreatedAt,
	}, nil
}

func (s *Storage) GetAllRoles(ctx context.Context) ([]rbac.Role, error) {
	rows, err := s.queries.GetAllRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("get all roles: %w", err)
	}

	out := make([]rbac.Role, 0, len(rows))
	for _, r := range rows {
		out = append(out, rbac.Role{
			RoleID:    r.RoleID,
			RoleName:  r.RoleName,
			CreatedAt: r.CreatedAt,
		})
	}

	return out, nil
}

func (s *Storage) UpdateRole(ctx context.Context, role rbac.Role) error {
	err := pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return errors.New("RBAC write transaction is not database/sql")
		}

		q := s.queries.WithTx(sqlTx)

		rows, err := q.UpdateRole(ctx, sqlcgen.UpdateRoleParams{RoleName: role.RoleName, RoleID: role.RoleID})
		if err != nil {
			return fmt.Errorf("update role row: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("role not found: %w", pqerr.ErrNotFound)
		}

		users, err := q.ListUsersWithRole(ctx, role.RoleID)
		if err != nil {
			return fmt.Errorf("list role holders: %w", err)
		}

		now := time.Now()
		for _, userID := range users {
			if err := bumpAndProjectHuman(ctx, q, userID, now); err != nil {
				return fmt.Errorf("refresh renamed role holder %s: %w", userID, err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("update role: %w", err)
	}

	return nil
}

func (s *Storage) DeleteRole(ctx context.Context, roleID string) error {
	rows, err := s.queries.DeleteRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("role not found: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	err := pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return errors.New("RBAC write transaction is not database/sql")
		}

		q := s.queries.WithTx(sqlTx)

		rows, err := q.AssignRoleToUser(ctx, sqlcgen.AssignRoleToUserParams{
			UserID: userID, RoleID: roleID, CreatedAt: time.Now(),
		})
		if err != nil {
			return fmt.Errorf("insert user role: %w", err)
		}

		if rows == 0 {
			return rbac.ErrRoleAlreadyAssigned
		}

		return bumpAndProjectHuman(ctx, q, userID, time.Now())
	})
	if err != nil {
		if errors.Is(err, rbac.ErrRoleAlreadyAssigned) {
			return rbac.ErrRoleAlreadyAssigned
		}

		return fmt.Errorf("assign role to user: %w", err)
	}

	return nil
}

func (s *Storage) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	err := pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return errors.New("RBAC write transaction is not database/sql")
		}

		q := s.queries.WithTx(sqlTx)

		rows, err := q.RemoveRoleFromUser(ctx, sqlcgen.RemoveRoleFromUserParams{
			UserID: userID, RoleID: roleID,
		})
		if err != nil {
			return fmt.Errorf("delete user role: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("user role not found: %w", pqerr.ErrNotFound)
		}

		return bumpAndProjectHuman(ctx, q, userID, time.Now())
	})
	if err != nil {
		return fmt.Errorf("remove role from user: %w", err)
	}

	return nil
}

func bumpAndProjectHuman(ctx context.Context, q *sqlcgen.Queries, userID string, now time.Time) error {
	rows, err := q.BumpUserAuthVersion(ctx, userID)
	if err != nil {
		return fmt.Errorf("bump human auth version: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("account not found: %w", pqerr.ErrNotFound)
	}

	if err := q.UpsertHumanSecurityPrincipal(ctx, sqlcgen.UpsertHumanSecurityPrincipalParams{
		UpdatedAtNs: now.UnixNano(), UserID: userID,
	}); err != nil {
		return fmt.Errorf("project human security principal: %w", err)
	}

	return nil
}

func (s *Storage) GetUserRoles(ctx context.Context, userID string) ([]rbac.Role, error) {
	rows, err := s.queries.ListUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}

	out := make([]rbac.Role, 0, len(rows))
	for _, r := range rows {
		out = append(out, rbac.Role{
			RoleID:    r.RoleID,
			RoleName:  r.RoleName,
			CreatedAt: r.CreatedAt,
		})
	}

	return out, nil
}

func (s *Storage) GetUsersWithRole(ctx context.Context, roleID string) ([]string, error) {
	users, err := s.queries.ListUsersWithRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("list users with role: %w", err)
	}

	return users, nil
}

func (s *Storage) CreateQueuePermission(ctx context.Context, p rbac.QueuePermission) error {
	now := time.Now()

	if err := s.queries.CreateQueuePermission(ctx, sqlcgen.CreateQueuePermissionParams{
		QueueID:    p.QueueID,
		RoleID:     p.RoleID,
		CanSend:    p.CanSend,
		CanReceive: p.CanReceive,
		CanPurge:   p.CanPurge,
		CanDelete:  p.CanDelete,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		return fmt.Errorf("create queue permission: %w", err)
	}

	return nil
}

func (s *Storage) GetQueuePermissions(ctx context.Context, queueID, roleID string) (*rbac.QueuePermission, error) {
	row, err := s.queries.GetQueuePermission(ctx, sqlcgen.GetQueuePermissionParams{
		QueueID: queueID,
		RoleID:  roleID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("queue permission not found: %w", pqerr.ErrNotFound)
		}

		return nil, fmt.Errorf("get queue permission: %w", err)
	}

	return &rbac.QueuePermission{
		QueueID:    row.QueueID,
		RoleID:     row.RoleID,
		CanSend:    row.CanSend,
		CanReceive: row.CanReceive,
		CanPurge:   row.CanPurge,
		CanDelete:  row.CanDelete,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}, nil
}

func (s *Storage) GetRoleQueuePermissions(ctx context.Context, roleID string) ([]rbac.QueuePermission, error) {
	rows, err := s.queries.ListRoleQueuePermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("list role queue permissions: %w", err)
	}

	out := make([]rbac.QueuePermission, 0, len(rows))
	for _, r := range rows {
		out = append(out, rbac.QueuePermission{
			QueueID:    r.QueueID,
			RoleID:     r.RoleID,
			CanSend:    r.CanSend,
			CanReceive: r.CanReceive,
			CanPurge:   r.CanPurge,
			CanDelete:  r.CanDelete,
			CreatedAt:  r.CreatedAt,
			UpdatedAt:  r.UpdatedAt,
		})
	}

	return out, nil
}

func (s *Storage) UpdateQueuePermission(ctx context.Context, p rbac.QueuePermission) error {
	rows, err := s.queries.UpdateQueuePermission(ctx, sqlcgen.UpdateQueuePermissionParams{
		CanSend:    p.CanSend,
		CanReceive: p.CanReceive,
		CanPurge:   p.CanPurge,
		CanDelete:  p.CanDelete,
		UpdatedAt:  time.Now(),
		QueueID:    p.QueueID,
		RoleID:     p.RoleID,
	})
	if err != nil {
		return fmt.Errorf("update queue permission: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("queue permission not found: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) DeleteQueuePermission(ctx context.Context, queueID, roleID string) error {
	rows, err := s.queries.DeleteQueuePermission(ctx, sqlcgen.DeleteQueuePermissionParams{
		QueueID: queueID,
		RoleID:  roleID,
	})
	if err != nil {
		return fmt.Errorf("delete queue permission: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("queue permission not found: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) HasQueuePermission(ctx context.Context, userID, queueID string, permission rbac.PermissionType) (bool, error) {
	var (
		count int64
		err   error
	)

	switch permission {
	case rbac.PermissionSend:
		count, err = s.queries.HasQueueSendPermission(ctx, sqlcgen.HasQueueSendPermissionParams{
			UserID: userID, QueueID: queueID,
		})

	case rbac.PermissionReceive:
		count, err = s.queries.HasQueueReceivePermission(ctx, sqlcgen.HasQueueReceivePermissionParams{
			UserID: userID, QueueID: queueID,
		})

	case rbac.PermissionPurge:
		count, err = s.queries.HasQueuePurgePermission(ctx, sqlcgen.HasQueuePurgePermissionParams{
			UserID: userID, QueueID: queueID,
		})

	case rbac.PermissionDelete:
		count, err = s.queries.HasQueueDeletePermission(ctx, sqlcgen.HasQueueDeletePermissionParams{
			UserID: userID, QueueID: queueID,
		})

	default:
		return false, fmt.Errorf("%w: invalid permission type: %s", pqerr.ErrInvalidInput, permission)
	}

	if err != nil {
		return false, fmt.Errorf("check queue permission: %w", err)
	}

	return count > 0, nil
}
