package litestore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/plainq/plainq/internal/server/auth"
	"github.com/plainq/servekit/idkit"
)

// Ensure Storage implements auth.AuthStorage
var _ auth.AuthStorage = (*Storage)(nil)

// CreateUser creates a new user
func (s *Storage) CreateUser(ctx context.Context, email, passwordHash string) (*auth.User, error) {
	userID := idkit.NewID()
	now := time.Now()

	query := `
		INSERT INTO users (user_id, email, password, verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query, userID, email, passwordHash, false, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &auth.User{
		UserID:    userID,
		Email:     email,
		Password:  passwordHash,
		Verified:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// GetUserByEmail retrieves a user by email
func (s *Storage) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	query := `
		SELECT user_id, email, password, verified, created_at, updated_at
		FROM users
		WHERE email = ?
	`

	var user auth.User
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.UserID,
		&user.Email,
		&user.Password,
		&user.Verified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (s *Storage) GetUserByID(ctx context.Context, userID string) (*auth.User, error) {
	query := `
		SELECT user_id, email, password, verified, created_at, updated_at
		FROM users
		WHERE user_id = ?
	`

	var user auth.User
	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&user.UserID,
		&user.Email,
		&user.Password,
		&user.Verified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// UpdateUserPassword updates a user's password
func (s *Storage) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	query := `
		UPDATE users
		SET password = ?, updated_at = ?
		WHERE user_id = ?
	`

	_, err := s.db.ExecContext(ctx, query, passwordHash, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdateUserVerified updates a user's verified status
func (s *Storage) UpdateUserVerified(ctx context.Context, userID string, verified bool) error {
	query := `
		UPDATE users
		SET verified = ?, updated_at = ?
		WHERE user_id = ?
	`

	_, err := s.db.ExecContext(ctx, query, verified, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update verified status: %w", err)
	}

	return nil
}

// GetUserRoles retrieves all roles for a user
func (s *Storage) GetUserRoles(ctx context.Context, userID string) ([]auth.Role, error) {
	query := `
		SELECT r.role_id, r.role_name, r.created_at
		FROM roles r
		INNER JOIN user_roles ur ON r.role_id = ur.role_id
		WHERE ur.user_id = ?
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	var roles []auth.Role
	for rows.Next() {
		var role auth.Role
		err := rows.Scan(&role.RoleID, &role.RoleName, &role.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// AssignRole assigns a role to a user
func (s *Storage) AssignRole(ctx context.Context, userID, roleID string) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, created_at)
		VALUES (?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query, userID, roleID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// IsSetupCompleted checks if initial setup has been completed
func (s *Storage) IsSetupCompleted(ctx context.Context) (bool, error) {
	query := `
		SELECT value
		FROM system_state
		WHERE key = 'setup_completed'
	`

	var value string
	err := s.db.QueryRowContext(ctx, query).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to check setup status: %w", err)
	}

	return value == "true", nil
}

// MarkSetupCompleted marks the initial setup as completed
func (s *Storage) MarkSetupCompleted(ctx context.Context) error {
	query := `
		UPDATE system_state
		SET value = 'true', updated_at = ?
		WHERE key = 'setup_completed'
	`

	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to mark setup completed: %w", err)
	}

	return nil
}

// CreateRefreshToken creates a new refresh token
func (s *Storage) CreateRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time, deviceInfo, ipAddress string) (*auth.RefreshToken, error) {
	tokenID := idkit.NewID()
	now := time.Now()

	query := `
		INSERT INTO refresh_tokens (token_id, user_id, token_hash, expires_at, revoked, created_at, last_used_at, device_info, ip_address)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query, tokenID, userID, tokenHash, expiresAt, false, now, now, deviceInfo, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	return &auth.RefreshToken{
		TokenID:    tokenID,
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  expiresAt,
		Revoked:    false,
		CreatedAt:  now,
		LastUsedAt: now,
		DeviceInfo: deviceInfo,
		IPAddress:  ipAddress,
	}, nil
}

// GetRefreshToken retrieves a refresh token by its hash
func (s *Storage) GetRefreshToken(ctx context.Context, tokenHash string) (*auth.RefreshToken, error) {
	query := `
		SELECT token_id, user_id, token_hash, expires_at, revoked, revoked_at, created_at, last_used_at, device_info, ip_address
		FROM refresh_tokens
		WHERE token_hash = ?
	`

	var token auth.RefreshToken
	var revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.TokenID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.Revoked,
		&revokedAt,
		&token.CreatedAt,
		&token.LastUsedAt,
		&token.DeviceInfo,
		&token.IPAddress,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}

	return &token, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *Storage) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = true, revoked_at = ?
		WHERE token_id = ?
	`

	_, err := s.db.ExecContext(ctx, query, time.Now(), tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user
func (s *Storage) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = true, revoked_at = ?
		WHERE user_id = ? AND revoked = false
	`

	_, err := s.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all refresh tokens: %w", err)
	}

	return nil
}

// UpdateRefreshTokenLastUsed updates the last used timestamp
func (s *Storage) UpdateRefreshTokenLastUsed(ctx context.Context, tokenID string) error {
	query := `
		UPDATE refresh_tokens
		SET last_used_at = ?
		WHERE token_id = ?
	`

	_, err := s.db.ExecContext(ctx, query, time.Now(), tokenID)
	if err != nil {
		return fmt.Errorf("failed to update last used time: %w", err)
	}

	return nil
}

// CleanupExpiredRefreshTokens removes expired refresh tokens
func (s *Storage) CleanupExpiredRefreshTokens(ctx context.Context) error {
	query := `
		DELETE FROM refresh_tokens
		WHERE expires_at < ?
	`

	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired refresh tokens: %w", err)
	}

	return nil
}

// AddToDenyList adds a token to the deny list
func (s *Storage) AddToDenyList(ctx context.Context, jti, userID string, expiresAt time.Time, reason string) error {
	query := `
		INSERT INTO token_denylist (jti, user_id, expires_at, revoked_at, reason)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query, jti, userID, expiresAt, time.Now(), reason)
	if err != nil {
		return fmt.Errorf("failed to add token to deny list: %w", err)
	}

	return nil
}

// IsTokenDenied checks if a token is in the deny list
func (s *Storage) IsTokenDenied(ctx context.Context, jti string) (bool, error) {
	query := `
		SELECT COUNT(*)
		FROM token_denylist
		WHERE jti = ? AND expires_at > ?
	`

	var count int
	err := s.db.QueryRowContext(ctx, query, jti, time.Now()).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check deny list: %w", err)
	}

	return count > 0, nil
}

// GetActiveDeniedTokens retrieves all active denied tokens (not expired)
func (s *Storage) GetActiveDeniedTokens(ctx context.Context) (map[string]time.Time, error) {
	query := `
		SELECT jti, expires_at
		FROM token_denylist
		WHERE expires_at > ?
	`

	rows, err := s.db.QueryContext(ctx, query, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get denied tokens: %w", err)
	}
	defer rows.Close()

	tokens := make(map[string]time.Time)
	for rows.Next() {
		var jti string
		var expiresAt time.Time
		err := rows.Scan(&jti, &expiresAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan denied token: %w", err)
		}
		tokens[jti] = expiresAt
	}

	return tokens, nil
}

// CleanupExpiredDeniedTokens removes expired tokens from the deny list
func (s *Storage) CleanupExpiredDeniedTokens(ctx context.Context) error {
	query := `
		DELETE FROM token_denylist
		WHERE expires_at < ?
	`

	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired denied tokens: %w", err)
	}

	return nil
}

// LogAuthEvent logs an authentication event
func (s *Storage) LogAuthEvent(ctx context.Context, userID, eventType string, success bool, ipAddress, userAgent, metadata string) error {
	logID := idkit.NewID()

	query := `
		INSERT INTO auth_audit_log (log_id, user_id, event_type, success, ip_address, user_agent, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query, logID, userID, eventType, success, ipAddress, userAgent, metadata, time.Now())
	if err != nil {
		// Don't fail the operation if logging fails, just log the error
		s.logger.Error("failed to log auth event", "error", err)
		return nil
	}

	return nil
}

// OAuth provider operations

// CreateOAuthProvider creates a new OAuth provider
func (s *Storage) CreateOAuthProvider(ctx context.Context, provider *auth.OAuthProvider) error {
	provider.ProviderID = idkit.NewID()
	provider.CreatedAt = time.Now()
	provider.UpdatedAt = time.Now()

	query := `
		INSERT INTO oauth_providers (
			provider_id, provider_name, provider_type, enabled,
			client_id, client_secret, issuer_url, auth_url, token_url,
			userinfo_url, jwks_url, scopes, saml_metadata_url, saml_entity_id,
			config_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		provider.ProviderID, provider.ProviderName, provider.ProviderType, provider.Enabled,
		provider.ClientID, provider.ClientSecret, provider.IssuerURL, provider.AuthURL, provider.TokenURL,
		provider.UserinfoURL, provider.JWKSURL, provider.Scopes, provider.SAMLMetadataURL, provider.SAMLEntityID,
		provider.ConfigJSON, provider.CreatedAt, provider.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create OAuth provider: %w", err)
	}

	return nil
}

// GetOAuthProvider retrieves an OAuth provider by name
func (s *Storage) GetOAuthProvider(ctx context.Context, providerName string) (*auth.OAuthProvider, error) {
	query := `
		SELECT provider_id, provider_name, provider_type, enabled,
			   client_id, client_secret, issuer_url, auth_url, token_url,
			   userinfo_url, jwks_url, scopes, saml_metadata_url, saml_entity_id,
			   config_json, created_at, updated_at
		FROM oauth_providers
		WHERE provider_name = ?
	`

	var provider auth.OAuthProvider
	err := s.db.QueryRowContext(ctx, query, providerName).Scan(
		&provider.ProviderID, &provider.ProviderName, &provider.ProviderType, &provider.Enabled,
		&provider.ClientID, &provider.ClientSecret, &provider.IssuerURL, &provider.AuthURL, &provider.TokenURL,
		&provider.UserinfoURL, &provider.JWKSURL, &provider.Scopes, &provider.SAMLMetadataURL, &provider.SAMLEntityID,
		&provider.ConfigJSON, &provider.CreatedAt, &provider.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("OAuth provider not found")
		}
		return nil, fmt.Errorf("failed to get OAuth provider: %w", err)
	}

	return &provider, nil
}

// GetOAuthProviderByID retrieves an OAuth provider by ID
func (s *Storage) GetOAuthProviderByID(ctx context.Context, providerID string) (*auth.OAuthProvider, error) {
	query := `
		SELECT provider_id, provider_name, provider_type, enabled,
			   client_id, client_secret, issuer_url, auth_url, token_url,
			   userinfo_url, jwks_url, scopes, saml_metadata_url, saml_entity_id,
			   config_json, created_at, updated_at
		FROM oauth_providers
		WHERE provider_id = ?
	`

	var provider auth.OAuthProvider
	err := s.db.QueryRowContext(ctx, query, providerID).Scan(
		&provider.ProviderID, &provider.ProviderName, &provider.ProviderType, &provider.Enabled,
		&provider.ClientID, &provider.ClientSecret, &provider.IssuerURL, &provider.AuthURL, &provider.TokenURL,
		&provider.UserinfoURL, &provider.JWKSURL, &provider.Scopes, &provider.SAMLMetadataURL, &provider.SAMLEntityID,
		&provider.ConfigJSON, &provider.CreatedAt, &provider.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("OAuth provider not found")
		}
		return nil, fmt.Errorf("failed to get OAuth provider: %w", err)
	}

	return &provider, nil
}

// ListEnabledOAuthProviders retrieves all enabled OAuth providers
func (s *Storage) ListEnabledOAuthProviders(ctx context.Context) ([]auth.OAuthProvider, error) {
	query := `
		SELECT provider_id, provider_name, provider_type, enabled,
			   client_id, client_secret, issuer_url, auth_url, token_url,
			   userinfo_url, jwks_url, scopes, saml_metadata_url, saml_entity_id,
			   config_json, created_at, updated_at
		FROM oauth_providers
		WHERE enabled = true
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list OAuth providers: %w", err)
	}
	defer rows.Close()

	var providers []auth.OAuthProvider
	for rows.Next() {
		var provider auth.OAuthProvider
		err := rows.Scan(
			&provider.ProviderID, &provider.ProviderName, &provider.ProviderType, &provider.Enabled,
			&provider.ClientID, &provider.ClientSecret, &provider.IssuerURL, &provider.AuthURL, &provider.TokenURL,
			&provider.UserinfoURL, &provider.JWKSURL, &provider.Scopes, &provider.SAMLMetadataURL, &provider.SAMLEntityID,
			&provider.ConfigJSON, &provider.CreatedAt, &provider.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan OAuth provider: %w", err)
		}
		providers = append(providers, provider)
	}

	return providers, nil
}

// UpdateOAuthProvider updates an OAuth provider
func (s *Storage) UpdateOAuthProvider(ctx context.Context, provider *auth.OAuthProvider) error {
	provider.UpdatedAt = time.Now()

	query := `
		UPDATE oauth_providers
		SET provider_name = ?, provider_type = ?, enabled = ?,
			client_id = ?, client_secret = ?, issuer_url = ?, auth_url = ?, token_url = ?,
			userinfo_url = ?, jwks_url = ?, scopes = ?, saml_metadata_url = ?, saml_entity_id = ?,
			config_json = ?, updated_at = ?
		WHERE provider_id = ?
	`

	_, err := s.db.ExecContext(ctx, query,
		provider.ProviderName, provider.ProviderType, provider.Enabled,
		provider.ClientID, provider.ClientSecret, provider.IssuerURL, provider.AuthURL, provider.TokenURL,
		provider.UserinfoURL, provider.JWKSURL, provider.Scopes, provider.SAMLMetadataURL, provider.SAMLEntityID,
		provider.ConfigJSON, provider.UpdatedAt, provider.ProviderID,
	)
	if err != nil {
		return fmt.Errorf("failed to update OAuth provider: %w", err)
	}

	return nil
}

// OAuth connection operations

// CreateOAuthConnection creates a new OAuth connection
func (s *Storage) CreateOAuthConnection(ctx context.Context, conn *auth.OAuthConnection) error {
	conn.ConnectionID = idkit.NewID()
	conn.CreatedAt = time.Now()
	conn.UpdatedAt = time.Now()

	query := `
		INSERT INTO oauth_connections (
			connection_id, user_id, provider_id, provider_user_id,
			email, profile_data, access_token, refresh_token, expires_at,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		conn.ConnectionID, conn.UserID, conn.ProviderID, conn.ProviderUserID,
		conn.Email, conn.ProfileData, conn.AccessToken, conn.RefreshToken, conn.ExpiresAt,
		conn.CreatedAt, conn.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create OAuth connection: %w", err)
	}

	return nil
}

// GetOAuthConnection retrieves an OAuth connection
func (s *Storage) GetOAuthConnection(ctx context.Context, providerID, providerUserID string) (*auth.OAuthConnection, error) {
	query := `
		SELECT connection_id, user_id, provider_id, provider_user_id,
			   email, profile_data, access_token, refresh_token, expires_at,
			   created_at, updated_at
		FROM oauth_connections
		WHERE provider_id = ? AND provider_user_id = ?
	`

	var conn auth.OAuthConnection
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, providerID, providerUserID).Scan(
		&conn.ConnectionID, &conn.UserID, &conn.ProviderID, &conn.ProviderUserID,
		&conn.Email, &conn.ProfileData, &conn.AccessToken, &conn.RefreshToken, &expiresAt,
		&conn.CreatedAt, &conn.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("OAuth connection not found")
		}
		return nil, fmt.Errorf("failed to get OAuth connection: %w", err)
	}

	if expiresAt.Valid {
		conn.ExpiresAt = &expiresAt.Time
	}

	return &conn, nil
}

// GetUserOAuthConnections retrieves all OAuth connections for a user
func (s *Storage) GetUserOAuthConnections(ctx context.Context, userID string) ([]auth.OAuthConnection, error) {
	query := `
		SELECT connection_id, user_id, provider_id, provider_user_id,
			   email, profile_data, access_token, refresh_token, expires_at,
			   created_at, updated_at
		FROM oauth_connections
		WHERE user_id = ?
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth connections: %w", err)
	}
	defer rows.Close()

	var connections []auth.OAuthConnection
	for rows.Next() {
		var conn auth.OAuthConnection
		var expiresAt sql.NullTime

		err := rows.Scan(
			&conn.ConnectionID, &conn.UserID, &conn.ProviderID, &conn.ProviderUserID,
			&conn.Email, &conn.ProfileData, &conn.AccessToken, &conn.RefreshToken, &expiresAt,
			&conn.CreatedAt, &conn.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan OAuth connection: %w", err)
		}

		if expiresAt.Valid {
			conn.ExpiresAt = &expiresAt.Time
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// UpdateOAuthConnection updates an OAuth connection
func (s *Storage) UpdateOAuthConnection(ctx context.Context, conn *auth.OAuthConnection) error {
	conn.UpdatedAt = time.Now()

	query := `
		UPDATE oauth_connections
		SET email = ?, profile_data = ?, access_token = ?, refresh_token = ?,
			expires_at = ?, updated_at = ?
		WHERE connection_id = ?
	`

	_, err := s.db.ExecContext(ctx, query,
		conn.Email, conn.ProfileData, conn.AccessToken, conn.RefreshToken,
		conn.ExpiresAt, conn.UpdatedAt, conn.ConnectionID,
	)
	if err != nil {
		return fmt.Errorf("failed to update OAuth connection: %w", err)
	}

	return nil
}

// DeleteOAuthConnection deletes an OAuth connection
func (s *Storage) DeleteOAuthConnection(ctx context.Context, connectionID string) error {
	query := `
		DELETE FROM oauth_connections
		WHERE connection_id = ?
	`

	_, err := s.db.ExecContext(ctx, query, connectionID)
	if err != nil {
		return fmt.Errorf("failed to delete OAuth connection: %w", err)
	}

	return nil
}
