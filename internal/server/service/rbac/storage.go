package rbac

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marsolab/servekit/idkit"
)

// SQLiteStorage implements the RBAC Storage interface using SQLite
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(db *sql.DB) *SQLiteStorage {
	return &SQLiteStorage{db: db}
}

// Role management methods

func (s *SQLiteStorage) CreateRole(ctx context.Context, role Role) error {
	query := `INSERT INTO roles (role_id, role_name, created_at) VALUES (?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, role.RoleID, role.RoleName, time.Now())
	if err != nil {
		return fmt.Errorf("create role: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) GetRoleByID(ctx context.Context, roleID string) (*Role, error) {
	query := `SELECT role_id, role_name, created_at FROM roles WHERE role_id = ?`
	var role Role
	err := s.db.QueryRowContext(ctx, query, roleID).Scan(&role.RoleID, &role.RoleName, &role.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role not found")
		}
		return nil, fmt.Errorf("get role by ID: %w", err)
	}
	return &role, nil
}

func (s *SQLiteStorage) GetRoleByName(ctx context.Context, roleName string) (*Role, error) {
	query := `SELECT role_id, role_name, created_at FROM roles WHERE role_name = ?`
	var role Role
	err := s.db.QueryRowContext(ctx, query, roleName).Scan(&role.RoleID, &role.RoleName, &role.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role not found")
		}
		return nil, fmt.Errorf("get role by name: %w", err)
	}
	return &role, nil
}

func (s *SQLiteStorage) GetAllRoles(ctx context.Context) ([]Role, error) {
	query := `SELECT role_id, role_name, created_at FROM roles ORDER BY role_name`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get all roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.RoleID, &role.RoleName, &role.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return roles, nil
}

func (s *SQLiteStorage) UpdateRole(ctx context.Context, role Role) error {
	query := `UPDATE roles SET role_name = ? WHERE role_id = ?`
	result, err := s.db.ExecContext(ctx, query, role.RoleName, role.RoleID)
	if err != nil {
		return fmt.Errorf("update role: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

func (s *SQLiteStorage) DeleteRole(ctx context.Context, roleID string) error {
	query := `DELETE FROM roles WHERE role_id = ?`
	result, err := s.db.ExecContext(ctx, query, roleID)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

// User role management methods

func (s *SQLiteStorage) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	query := `INSERT INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, userID, roleID, time.Now())
	if err != nil {
		return fmt.Errorf("assign role to user: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = ? AND role_id = ?`
	result, err := s.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("remove role from user: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("user role not found")
	}

	return nil
}

func (s *SQLiteStorage) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	query := `
		SELECT r.role_id, r.role_name, r.created_at 
		FROM roles r 
		INNER JOIN user_roles ur ON r.role_id = ur.role_id 
		WHERE ur.user_id = ?
		ORDER BY r.role_name`
	
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.RoleID, &role.RoleName, &role.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return roles, nil
}

func (s *SQLiteStorage) GetUsersWithRole(ctx context.Context, roleID string) ([]string, error) {
	query := `SELECT user_id FROM user_roles WHERE role_id = ?`
	rows, err := s.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("get users with role: %w", err)
	}
	defer rows.Close()

	var userIDs []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("scan user ID: %w", err)
		}
		userIDs = append(userIDs, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return userIDs, nil
}

// Permission management methods

func (s *SQLiteStorage) CreateQueuePermission(ctx context.Context, permission QueuePermission) error {
	query := `
		INSERT INTO queue_permissions (queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	
	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, 
		permission.QueueID, permission.RoleID, 
		permission.CanSend, permission.CanReceive, permission.CanPurge, permission.CanDelete,
		now, now)
	if err != nil {
		return fmt.Errorf("create queue permission: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) GetQueuePermissions(ctx context.Context, queueID, roleID string) (*QueuePermission, error) {
	query := `
		SELECT queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at 
		FROM queue_permissions 
		WHERE queue_id = ? AND role_id = ?`
	
	var perm QueuePermission
	err := s.db.QueryRowContext(ctx, query, queueID, roleID).Scan(
		&perm.QueueID, &perm.RoleID, 
		&perm.CanSend, &perm.CanReceive, &perm.CanPurge, &perm.CanDelete,
		&perm.CreatedAt, &perm.UpdatedAt)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("queue permission not found")
		}
		return nil, fmt.Errorf("get queue permissions: %w", err)
	}
	
	return &perm, nil
}

func (s *SQLiteStorage) GetRoleQueuePermissions(ctx context.Context, roleID string) ([]QueuePermission, error) {
	query := `
		SELECT queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at 
		FROM queue_permissions 
		WHERE role_id = ?`
	
	rows, err := s.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role queue permissions: %w", err)
	}
	defer rows.Close()

	var permissions []QueuePermission
	for rows.Next() {
		var perm QueuePermission
		if err := rows.Scan(
			&perm.QueueID, &perm.RoleID, 
			&perm.CanSend, &perm.CanReceive, &perm.CanPurge, &perm.CanDelete,
			&perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return permissions, nil
}

func (s *SQLiteStorage) UpdateQueuePermission(ctx context.Context, permission QueuePermission) error {
	query := `
		UPDATE queue_permissions 
		SET can_send = ?, can_receive = ?, can_purge = ?, can_delete = ?, updated_at = ?
		WHERE queue_id = ? AND role_id = ?`
	
	result, err := s.db.ExecContext(ctx, query, 
		permission.CanSend, permission.CanReceive, permission.CanPurge, permission.CanDelete,
		time.Now(), permission.QueueID, permission.RoleID)
	if err != nil {
		return fmt.Errorf("update queue permission: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("queue permission not found")
	}

	return nil
}

func (s *SQLiteStorage) DeleteQueuePermission(ctx context.Context, queueID, roleID string) error {
	query := `DELETE FROM queue_permissions WHERE queue_id = ? AND role_id = ?`
	result, err := s.db.ExecContext(ctx, query, queueID, roleID)
	if err != nil {
		return fmt.Errorf("delete queue permission: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("queue permission not found")
	}

	return nil
}

// User permission checking method

func (s *SQLiteStorage) HasQueuePermission(ctx context.Context, userID, queueID string, permission PermissionType) (bool, error) {
	var permissionColumn string
	switch permission {
	case PermissionSend:
		permissionColumn = "can_send"
	case PermissionReceive:
		permissionColumn = "can_receive"
	case PermissionPurge:
		permissionColumn = "can_purge"
	case PermissionDelete:
		permissionColumn = "can_delete"
	default:
		return false, fmt.Errorf("invalid permission type: %s", permission)
	}

	query := fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM queue_permissions qp
		INNER JOIN user_roles ur ON qp.role_id = ur.role_id
		WHERE ur.user_id = ? AND qp.queue_id = ? AND qp.%s = 1`, permissionColumn)
	
	var count int
	err := s.db.QueryRowContext(ctx, query, userID, queueID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check queue permission: %w", err)
	}

	return count > 0, nil
}