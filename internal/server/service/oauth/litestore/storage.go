package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/servekit/idkit"
)

// SQLiteStorage implements the OAuth Storage interface using SQLite
type SQLiteStorage struct{ db *sql.DB }

// NewSQLiteStorage creates a new SQLite storage instance for OAuth operations
func NewSQLiteStorage(db *sql.DB) *SQLiteStorage {
	return &SQLiteStorage{db: db}
}

const ()

// SyncOAuthUser synchronizes a user from OAuth provider
func (s *SQLiteStorage) SyncOAuthUser(ctx context.Context, user oauth.OAuthUser, providerName, orgID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if user already exists
	var userID string

	checkQuery := `SELECT user_id FROM users WHERE oauth_provider = ? AND oauth_sub = ?`

	err = tx.QueryRowContext(ctx, checkQuery, providerName, user.Subject).Scan(&userID)

	if err == sql.ErrNoRows {
		// Create new user
		userID = idkit.ULID()
		insertQuery := `
			INSERT INTO users (user_id, email, password, verified, org_id, oauth_provider, oauth_sub, is_oauth_user, last_sync_at, created_at, updated_at)
			VALUES (?, ?, '', true, ?, ?, ?, true, ?, ?, ?)`

		now := time.Now()
		_, err = tx.ExecContext(ctx, insertQuery,
			userID, user.Email, orgID, providerName, user.Subject, now, now, now)
		if err != nil {
			return fmt.Errorf("create oauth user: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("check existing user: %w", err)
	} else {
		// Update existing user
		updateQuery := `
			UPDATE users
			SET email = ?, org_id = ?, last_sync_at = ?, updated_at = ?
			WHERE user_id = ?`

		now := time.Now()
		_, err = tx.ExecContext(ctx, updateQuery, user.Email, orgID, now, now, userID)
		if err != nil {
			return fmt.Errorf("update oauth user: %w", err)
		}
	}

	return tx.Commit()
}

// GetUserByOAuthSub gets a user by OAuth subject
func (s *SQLiteStorage) GetUserByOAuthSub(ctx context.Context, providerName, subject string) (*SyncedUser, error) {
	query := `
		SELECT user_id, email, org_id, oauth_provider, oauth_sub, is_oauth_user, last_sync_at, created_at, updated_at
		FROM users
		WHERE oauth_provider = ? AND oauth_sub = ?`

	var user SyncedUser
	err := s.db.QueryRowContext(ctx, query, providerName, subject).Scan(
		&user.UserID, &user.Email, &user.OrgID, &user.Provider, &user.Subject,
		&user.IsOAuthUser, &user.LastSyncAt, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("get user by oauth sub: %w", err)
	}

	return &user, nil
}

// GetOrganizationByCode gets organization by code
func (s *SQLiteStorage) GetOrganizationByCode(ctx context.Context, orgCode string) (*Organization, error) {
	query := `
		SELECT org_id, org_code, org_name, org_domain, is_active, created_at, updated_at
		FROM organizations
		WHERE org_code = ? AND is_active = true`

	var org Organization
	var orgDomainPtr *string

	err := s.db.QueryRowContext(ctx, query, orgCode).Scan(
		&org.OrgID, &org.OrgCode, &org.OrgName, &orgDomainPtr,
		&org.IsActive, &org.CreatedAt, &org.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, fmt.Errorf("get organization by code: %w", err)
	}

	if orgDomainPtr != nil {
		org.OrgDomain = *orgDomainPtr
	}

	return &org, nil
}

// Implement other storage methods here...
// (For brevity, I'm showing key methods. The full implementation would include all interface methods)

// CreateProvider creates a new OAuth provider
func (s *SQLiteStorage) CreateProvider(ctx context.Context, provider Provider) error {
	configJSON, err := json.Marshal(provider.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	query := `
		INSERT INTO oauth_providers (provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	now := time.Now()
	_, err = s.db.ExecContext(ctx, query,
		provider.ProviderID, provider.ProviderName, provider.OrgID,
		string(configJSON), provider.IsActive, now, now)
	if err != nil {
		return fmt.Errorf("create provider: %w", err)
	}

	return nil
}

// GetProvider gets an OAuth provider
func (s *SQLiteStorage) GetProvider(ctx context.Context, providerName, orgID string) (*Provider, error) {
	// Implementation here
	return nil, fmt.Errorf("not implemented")
}

// UpdateProvider updates an OAuth provider
func (s *SQLiteStorage) UpdateProvider(ctx context.Context, provider Provider) error {
	// Implementation here
	return fmt.Errorf("not implemented")
}

// DeleteProvider deletes an OAuth provider
func (s *SQLiteStorage) DeleteProvider(ctx context.Context, providerID string) error {
	query := `DELETE FROM oauth_providers WHERE provider_id = ?`
	_, err := s.db.ExecContext(ctx, query, providerID)
	return err
}

// ListProviders lists OAuth providers
func (s *SQLiteStorage) ListProviders(ctx context.Context, orgID string) ([]Provider, error) {
	// Implementation here
	return nil, fmt.Errorf("not implemented")
}

// UpdateUserLastSync updates user's last sync time
func (s *SQLiteStorage) UpdateUserLastSync(ctx context.Context, userID string) error {
	query := `UPDATE users SET last_sync_at = ?, updated_at = ? WHERE user_id = ?`
	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, now, now, userID)
	return err
}

// GetOrganizationByDomain gets organization by domain
func (s *SQLiteStorage) GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error) {
	// Implementation here
	return nil, fmt.Errorf("not implemented")
}

// GetTeamsByOrg gets teams by organization
func (s *SQLiteStorage) GetTeamsByOrg(ctx context.Context, orgID string) ([]Team, error) {
	// Implementation here
	return nil, fmt.Errorf("not implemented")
}

// GetTeamByCode gets team by code
func (s *SQLiteStorage) GetTeamByCode(ctx context.Context, orgID, teamCode string) (*Team, error) {
	// Implementation here
	return nil, fmt.Errorf("not implemented")
}

// AssignUserToTeam assigns user to team
func (s *SQLiteStorage) AssignUserToTeam(ctx context.Context, userID, teamID string) error {
	query := `INSERT OR IGNORE INTO user_teams (user_id, team_id, created_at) VALUES (?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, userID, teamID, time.Now())
	return err
}

// RemoveUserFromTeam removes user from team
func (s *SQLiteStorage) RemoveUserFromTeam(ctx context.Context, userID, teamID string) error {
	query := `DELETE FROM user_teams WHERE user_id = ? AND team_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID, teamID)
	return err
}

// GetUserTeams gets user's teams
func (s *SQLiteStorage) GetUserTeams(ctx context.Context, userID string) ([]Team, error) {
	// Implementation here
	return nil, fmt.Errorf("not implemented")
}
