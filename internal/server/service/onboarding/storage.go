package onboarding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQLiteStorage implements the onboarding Storage interface using SQLite
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite storage instance for onboarding
func NewSQLiteStorage(db *sql.DB) *SQLiteStorage {
	return &SQLiteStorage{db: db}
}

// HasAdminUsers checks if there are any users with admin role
func (s *SQLiteStorage) HasAdminUsers(ctx context.Context) (bool, error) {
	query := `
		SELECT COUNT(*) 
		FROM user_roles ur
		INNER JOIN roles r ON ur.role_id = r.role_id
		WHERE r.role_name = 'admin'`

	var count int
	err := s.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check admin users: %w", err)
	}

	return count > 0, nil
}

// GetAdminRoleID gets the admin role ID
func (s *SQLiteStorage) GetAdminRoleID(ctx context.Context) (string, error) {
	query := `SELECT role_id FROM roles WHERE role_name = 'admin'`

	var roleID string
	err := s.db.QueryRowContext(ctx, query).Scan(&roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("admin role not found")
		}
		return "", fmt.Errorf("get admin role ID: %w", err)
	}

	return roleID, nil
}

// CreateInitialAdmin creates the first admin user and assigns admin role
func (s *SQLiteStorage) CreateInitialAdmin(ctx context.Context, admin InitialAdmin) error {
	// Start a transaction to ensure atomicity
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return
		}
	}()

	// Double-check that no admin users exist (race condition protection)
	hasAdmins, err := s.hasAdminUsersInTx(ctx, tx)
	if err != nil {
		return fmt.Errorf("check admin users in transaction: %w", err)
	}

	if hasAdmins {
		return fmt.Errorf("admin users already exist, onboarding not allowed")
	}

	// Create the user
	userQuery := `
		INSERT INTO users (user_id, email, password, verified, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?)`

	now := time.Now()
	_, err = tx.ExecContext(ctx, userQuery,
		admin.UserID, admin.Email, admin.Password, admin.Verified, now, now)
	if err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	// Get admin role ID
	adminRoleID, err := s.getAdminRoleIDInTx(ctx, tx)
	if err != nil {
		return fmt.Errorf("get admin role ID: %w", err)
	}

	// Assign admin role to the user
	roleQuery := `INSERT INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)`
	_, err = tx.ExecContext(ctx, roleQuery, admin.UserID, adminRoleID, now)
	if err != nil {
		return fmt.Errorf("assign admin role: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// hasAdminUsersInTx checks for admin users within a transaction
func (s *SQLiteStorage) hasAdminUsersInTx(ctx context.Context, tx *sql.Tx) (bool, error) {
	query := `
		SELECT COUNT(*) 
		FROM user_roles ur
		INNER JOIN roles r ON ur.role_id = r.role_id
		WHERE r.role_name = 'admin'`

	var count int
	err := tx.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check admin users in tx: %w", err)
	}

	return count > 0, nil
}

// getAdminRoleIDInTx gets the admin role ID within a transaction
func (s *SQLiteStorage) getAdminRoleIDInTx(ctx context.Context, tx *sql.Tx) (string, error) {
	query := `SELECT role_id FROM roles WHERE role_name = 'admin'`

	var roleID string
	err := tx.QueryRowContext(ctx, query).Scan(&roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("admin role not found")
		}
		return "", fmt.Errorf("get admin role ID in tx: %w", err)
	}

	return roleID, nil
}
