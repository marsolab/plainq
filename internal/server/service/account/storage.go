package account

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marsolab/servekit/authkit/hashkit"
)

// SQLiteStorage implements the account Storage interface using SQLite
type SQLiteStorage struct {
	db     *sql.DB
	hasher hashkit.Hasher
}

// NewSQLiteStorage creates a new SQLite storage instance for accounts
func NewSQLiteStorage(db *sql.DB, hasher hashkit.Hasher) *SQLiteStorage {
	return &SQLiteStorage{
		db:     db,
		hasher: hasher,
	}
}

// CreateAccount creates record with account information in database.
func (s *SQLiteStorage) CreateAccount(ctx context.Context, account Account) error {
	// Use the users table instead of accounts for consistency
	query := `INSERT INTO users (user_id, email, password, verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`
	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, account.ID, account.Email, account.Password, account.Verified, now, now)
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	return nil
}

// GetAccountByID fetches account record from database by given id.
func (s *SQLiteStorage) GetAccountByID(ctx context.Context, id string) (*Account, error) {
	query := `SELECT user_id, email, password, verified, created_at, updated_at FROM users WHERE user_id = ?`
	var account Account
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&account.ID, &account.Email, &account.Password, &account.Verified, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("account not found")
		}
		return nil, fmt.Errorf("get account by ID: %w", err)
	}
	return &account, nil
}

// GetAccountByEmail fetches account record from database by given email.
func (s *SQLiteStorage) GetAccountByEmail(ctx context.Context, email string) (*Account, error) {
	query := `SELECT user_id, email, password, verified, created_at, updated_at FROM users WHERE email = ?`
	var account Account
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&account.ID, &account.Email, &account.Password, &account.Verified, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("account not found")
		}
		return nil, fmt.Errorf("get account by email: %w", err)
	}
	return &account, nil
}

// SetAccountVerified update 'verified' field of account record in database.
func (s *SQLiteStorage) SetAccountVerified(ctx context.Context, email string, verified bool) error {
	query := `UPDATE users SET verified = ?, updated_at = ? WHERE email = ?`
	result, err := s.db.ExecContext(ctx, query, verified, time.Now(), email)
	if err != nil {
		return fmt.Errorf("set account verified: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

// SetAccountPassword update account 'password' field of account record in database.
func (s *SQLiteStorage) SetAccountPassword(ctx context.Context, id, password string) error {
	query := `UPDATE users SET password = ?, updated_at = ? WHERE user_id = ?`
	result, err := s.db.ExecContext(ctx, query, password, time.Now(), id)
	if err != nil {
		return fmt.Errorf("set account password: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

// DeleteAccount deletes account record from database by given id.
func (s *SQLiteStorage) DeleteAccount(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE user_id = ?`
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete account: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

// CreateRefreshToken creates refresh token record in database.
func (s *SQLiteStorage) CreateRefreshToken(ctx context.Context, token RefreshToken) error {
	query := `INSERT INTO refresh_tokens (id, aid, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, token.ID, token.AID, token.Token, token.CreatedAt, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

// DeleteRefreshToken deletes given token from database.
func (s *SQLiteStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = ?`
	result, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("refresh token not found")
	}

	return nil
}

// DeleteRefreshTokenByTokenID deletes given token from database by its id.
func (s *SQLiteStorage) DeleteRefreshTokenByTokenID(ctx context.Context, tid string) error {
	query := `DELETE FROM refresh_tokens WHERE id = ?`
	result, err := s.db.ExecContext(ctx, query, tid)
	if err != nil {
		return fmt.Errorf("delete refresh token by ID: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("refresh token not found")
	}

	return nil
}

// PurgeRefreshTokens deletes all refresh token records related to given account.
func (s *SQLiteStorage) PurgeRefreshTokens(ctx context.Context, aid string) error {
	query := `DELETE FROM refresh_tokens WHERE aid = ?`
	_, err := s.db.ExecContext(ctx, query, aid)
	if err != nil {
		return fmt.Errorf("purge refresh tokens: %w", err)
	}
	return nil
}

// DenyAccessToken denies access token by given token string.
func (s *SQLiteStorage) DenyAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	query := `INSERT INTO denylist (token, denied_until) VALUES (?, ?)`
	deniedUntil := time.Now().Add(ttl).Unix()
	_, err := s.db.ExecContext(ctx, query, token, deniedUntil)
	if err != nil {
		return fmt.Errorf("deny access token: %w", err)
	}
	return nil
}

// GetUserRoles gets all roles for a user by user ID.
func (s *SQLiteStorage) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT r.role_name 
		FROM roles r 
		INNER JOIN user_roles ur ON r.role_id = ur.role_id 
		WHERE ur.user_id = ?
		ORDER BY r.role_name`
	
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var roleName string
		if err := rows.Scan(&roleName); err != nil {
			return nil, fmt.Errorf("scan role name: %w", err)
		}
		roles = append(roles, roleName)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return roles, nil
}