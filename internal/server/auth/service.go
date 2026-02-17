package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	eventLogin        = "login"
	eventSignup       = "signup"
	eventTokenRefresh = "token_refresh"
)

// Service handles authentication operations.
type Service struct {
	storage  Storage
	jwt      *JWTService
	denyList *TokenDenyList
}

// NewAuthService creates a new authentication service.
func NewAuthService(storage Storage, jwtSecret, issuer string) *Service {
	jwtService := NewJWTService(jwtSecret, issuer)
	denyList := NewTokenDenyList(storage)

	return &Service{
		storage:  storage,
		jwt:      jwtService,
		denyList: denyList,
	}
}

// LoginResult contains the result of a successful login.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         *User
	Roles        []string
}

// Login authenticates a user and returns tokens.
//
//nolint:revive // argument-limit: all parameters are contextually required
func (s *Service) Login(ctx context.Context, email, password, deviceInfo, ipAddress string) (*LoginResult, error) {
	// Get user by email.
	user, err := s.storage.GetUserByEmail(ctx, email)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, "", eventLogin, false, ipAddress, deviceInfo, fmt.Sprintf("user not found: %s", email))
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	// Handle migration from plaintext passwords.
	var valid bool
	if IsPasswordHashed(user.Password) {
		valid, err = VerifyPassword(password, user.Password)
		if err != nil {
			//nolint:errcheck // best-effort logging
			s.storage.LogAuthEvent(ctx, user.UserID, eventLogin, false, ipAddress, deviceInfo, "password verification error")
			return nil, fmt.Errorf("invalid credentials")
		}
	} else {
		// Plaintext password (migration mode).
		valid = user.Password == password
		// Hash the password for next time.
		if valid {
			hashedPassword, err := HashPassword(password)
			if err == nil {
				//nolint:errcheck // best-effort password migration
				s.storage.UpdateUserPassword(ctx, user.UserID, hashedPassword)
			}
		}
	}

	if !valid {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventLogin, false, ipAddress, deviceInfo, "invalid password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Get user roles.
	roles, err := s.storage.GetUserRoles(ctx, user.UserID)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventLogin, false, ipAddress, deviceInfo, "failed to get roles")
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.RoleName
	}

	// Generate access token with role claims.
	accessToken, err := s.jwt.GenerateAccessToken(user.UserID, user.Email, roleNames)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventLogin, false, ipAddress, deviceInfo, "failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token.
	refreshToken, tokenHash, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventLogin, false, ipAddress, deviceInfo, "failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token.
	expiresAt := time.Now().Add(RefreshTokenDuration)
	_, err = s.storage.CreateRefreshToken(ctx, user.UserID, tokenHash, expiresAt, deviceInfo, ipAddress)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventLogin, false, ipAddress, deviceInfo, "failed to store refresh token")
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Log successful login
	//nolint:errcheck // best-effort logging
	s.storage.LogAuthEvent(ctx, user.UserID, eventLogin, true, ipAddress, deviceInfo, "")

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
		Roles:        roleNames,
	}, nil
}

// Signup creates a new user account.
//
//nolint:revive // argument-limit: all parameters are contextually required
func (s *Service) Signup(ctx context.Context, email, password, deviceInfo, ipAddress string) (*LoginResult, error) {
	// Hash the password.
	hashedPassword, err := HashPassword(password)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, "", eventSignup, false, ipAddress, deviceInfo, "failed to hash password")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user.
	user, err := s.storage.CreateUser(ctx, email, hashedPassword)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, "", eventSignup, false, ipAddress, deviceInfo, fmt.Sprintf("failed to create user: %s", email))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign default role (consumer) - get the role ID first.
	roles, err := s.storage.GetUserRoles(ctx, user.UserID)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventSignup, false, ipAddress, deviceInfo, "failed to get roles")
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// If user has no roles, assign consumer role (ID from migration).
	if len(roles) == 0 {
		err = s.storage.AssignRole(ctx, user.UserID, "01HQ5RJNXS6TPXK89PQWY4N8JF") // consumer role.
		if err != nil {
			//nolint:errcheck // best-effort logging
			s.storage.LogAuthEvent(ctx, user.UserID, eventSignup, false, ipAddress, deviceInfo, "failed to assign default role")
			return nil, fmt.Errorf("failed to assign default role: %w", err)
		}

		// Refresh roles.
		roles, err = s.storage.GetUserRoles(ctx, user.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user roles: %w", err)
		}
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.RoleName
	}

	// Generate tokens.
	accessToken, err := s.jwt.GenerateAccessToken(user.UserID, user.Email, roleNames)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventSignup, false, ipAddress, deviceInfo, "failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, tokenHash, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventSignup, false, ipAddress, deviceInfo, "failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	expiresAt := time.Now().Add(RefreshTokenDuration)
	_, err = s.storage.CreateRefreshToken(ctx, user.UserID, tokenHash, expiresAt, deviceInfo, ipAddress)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventSignup, false, ipAddress, deviceInfo, "failed to store refresh token")
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Log successful signup
	//nolint:errcheck // best-effort logging
	s.storage.LogAuthEvent(ctx, user.UserID, eventSignup, true, ipAddress, deviceInfo, "")

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
		Roles:        roleNames,
	}, nil
}

// RefreshAccessToken generates a new access token using a refresh token.
func (s *Service) RefreshAccessToken(ctx context.Context, refreshToken, deviceInfo, ipAddress string) (*LoginResult, error) {
	// Get refresh token from storage.
	storedToken, err := s.storage.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, "", eventTokenRefresh, false, ipAddress, deviceInfo, "refresh token not found")
		return nil, errors.New("invalid refresh token")
	}

	// Check if token is revoked.
	if storedToken.Revoked {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, storedToken.UserID, eventTokenRefresh, false, ipAddress, deviceInfo, "refresh token revoked")
		return nil, errors.New("refresh token has been revoked")
	}

	// Check if token is expired.
	if time.Now().After(storedToken.ExpiresAt) {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, storedToken.UserID, eventTokenRefresh, false, ipAddress, deviceInfo, "refresh token expired")
		return nil, errors.New("refresh token has expired")
	}

	// Get user.
	user, err := s.storage.GetUserByID(ctx, storedToken.UserID)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, storedToken.UserID, eventTokenRefresh, false, ipAddress, deviceInfo, "user not found")
		return nil, errors.New("user not found")
	}

	// Get user roles.
	roles, err := s.storage.GetUserRoles(ctx, user.UserID)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventTokenRefresh, false, ipAddress, deviceInfo, "failed to get roles")
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.RoleName
	}

	// Generate new access token.
	accessToken, err := s.jwt.GenerateAccessToken(user.UserID, user.Email, roleNames)
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, user.UserID, eventTokenRefresh, false, ipAddress, deviceInfo, "failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Update last used time
	//nolint:errcheck // best-effort update
	s.storage.UpdateRefreshTokenLastUsed(ctx, storedToken.TokenID)

	// Log successful refresh
	//nolint:errcheck // best-effort logging
	s.storage.LogAuthEvent(ctx, user.UserID, eventTokenRefresh, true, ipAddress, deviceInfo, "")

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // Return the same refresh token.
		User:         user,
		Roles:        roleNames,
	}, nil
}

// Logout invalidates tokens for a user.
//
//nolint:revive // argument-limit: all parameters are contextually required
func (s *Service) Logout(ctx context.Context, accessToken, refreshToken, ipAddress, userAgent string) error {
	// Extract user ID and JTI from access token.
	claims, err := s.jwt.ValidateToken(accessToken)
	if err != nil {
		// Even if token is invalid, try to revoke refresh token.
		if refreshToken != "" {
			storedToken, err := s.storage.GetRefreshToken(ctx, refreshToken)
			if err == nil {
				//nolint:errcheck // best-effort revocation
				s.storage.RevokeRefreshToken(ctx, storedToken.TokenID)
			}
		}
		return fmt.Errorf("invalid access token: %w", err)
	}

	// Add access token to deny list (TTL+1).
	expiresAt := claims.ExpiresAt.Time
	err = s.denyList.Add(ctx, DenyListEntry{
		JTI:       claims.ID,
		UserID:    claims.UserID,
		ExpiresAt: expiresAt,
		Reason:    "logout",
	})
	if err != nil {
		//nolint:errcheck // best-effort logging
		s.storage.LogAuthEvent(ctx, claims.UserID, "logout", false, ipAddress, userAgent, "failed to add to deny list")
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	// Revoke refresh token if provided.
	if refreshToken != "" {
		storedToken, err := s.storage.GetRefreshToken(ctx, refreshToken)
		if err == nil {
			err = s.storage.RevokeRefreshToken(ctx, storedToken.TokenID)
			if err != nil {
				//nolint:errcheck // best-effort logging
				s.storage.LogAuthEvent(ctx, claims.UserID, "logout", false, ipAddress, userAgent, "failed to revoke refresh token")
				return fmt.Errorf("failed to revoke refresh token: %w", err)
			}
		}
	}

	// Log successful logout
	//nolint:errcheck // best-effort logging
	s.storage.LogAuthEvent(ctx, claims.UserID, "logout", true, ipAddress, userAgent, "")

	return nil
}

// ValidateToken validates an access token and returns claims.
func (s *Service) ValidateToken(_ context.Context, token string) (*Claims, error) {
	// Parse and validate token.
	claims, err := s.jwt.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	// Check if token is in deny list.
	if s.denyList.IsRevoked(claims.ID) {
		return nil, errors.New("token has been revoked")
	}

	return claims, nil
}

// RevokeAllUserTokens revokes all tokens for a user (e.g., on password change).
func (s *Service) RevokeAllUserTokens(ctx context.Context, userID string) error {
	// Revoke all refresh tokens.
	err := s.storage.RevokeAllUserRefreshTokens(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	// Note: We don't add all access tokens to deny list since we don't have a way to enumerate them
	// Instead, we rely on short access token TTL (15 minutes)
	// In a production system, you might want to maintain a session table to track all active access tokens.

	return nil
}

// InitializeDenyList loads denied tokens from storage.
func (s *Service) InitializeDenyList(ctx context.Context) error {
	return s.denyList.LoadFromStorage(ctx)
}

// Stop stops background services.
func (s *Service) Stop() {
	s.denyList.Stop()
}
