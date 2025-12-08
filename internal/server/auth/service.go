package auth

import (
	"context"
	"fmt"
	"time"
)

// AuthService handles authentication operations
type AuthService struct {
	storage   AuthStorage
	jwt       *JWTService
	denyList  *TokenDenyList
}

// NewAuthService creates a new authentication service
func NewAuthService(storage AuthStorage, jwtSecret, issuer string) *AuthService {
	jwtService := NewJWTService(jwtSecret, issuer)
	denyList := NewTokenDenyList(storage)

	return &AuthService{
		storage:  storage,
		jwt:      jwtService,
		denyList: denyList,
	}
}

// LoginResult contains the result of a successful login
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         *User
	Roles        []string
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(ctx context.Context, email, password, deviceInfo, ipAddress string) (*LoginResult, error) {
	// Get user by email
	user, err := s.storage.GetUserByEmail(ctx, email)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, "", "login", false, ipAddress, deviceInfo, fmt.Sprintf("user not found: %s", email))
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	// Handle migration from plaintext passwords
	var valid bool
	if IsPasswordHashed(user.Password) {
		valid, err = VerifyPassword(password, user.Password)
		if err != nil {
			_ = s.storage.LogAuthEvent(ctx, user.UserID, "login", false, ipAddress, deviceInfo, "password verification error")
			return nil, fmt.Errorf("invalid credentials")
		}
	} else {
		// Plaintext password (migration mode)
		valid = user.Password == password
		// Hash the password for next time
		if valid {
			hashedPassword, err := HashPassword(password)
			if err == nil {
				_ = s.storage.UpdateUserPassword(ctx, user.UserID, hashedPassword)
			}
		}
	}

	if !valid {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "login", false, ipAddress, deviceInfo, "invalid password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Get user roles
	roles, err := s.storage.GetUserRoles(ctx, user.UserID)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "login", false, ipAddress, deviceInfo, "failed to get roles")
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.RoleName
	}

	// Generate access token with role claims
	accessToken, err := s.jwt.GenerateAccessToken(user.UserID, user.Email, roleNames)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "login", false, ipAddress, deviceInfo, "failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, tokenHash, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "login", false, ipAddress, deviceInfo, "failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token
	expiresAt := time.Now().Add(RefreshTokenDuration)
	_, err = s.storage.CreateRefreshToken(ctx, user.UserID, tokenHash, expiresAt, deviceInfo, ipAddress)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "login", false, ipAddress, deviceInfo, "failed to store refresh token")
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Log successful login
	_ = s.storage.LogAuthEvent(ctx, user.UserID, "login", true, ipAddress, deviceInfo, "")

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
		Roles:        roleNames,
	}, nil
}

// Signup creates a new user account
func (s *AuthService) Signup(ctx context.Context, email, password, deviceInfo, ipAddress string) (*LoginResult, error) {
	// Hash the password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, "", "signup", false, ipAddress, deviceInfo, "failed to hash password")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user
	user, err := s.storage.CreateUser(ctx, email, hashedPassword)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, "", "signup", false, ipAddress, deviceInfo, fmt.Sprintf("failed to create user: %s", email))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign default role (consumer) - get the role ID first
	roles, err := s.storage.GetUserRoles(ctx, user.UserID)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "signup", false, ipAddress, deviceInfo, "failed to get roles")
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// If user has no roles, assign consumer role (ID from migration)
	if len(roles) == 0 {
		err = s.storage.AssignRole(ctx, user.UserID, "01HQ5RJNXS6TPXK89PQWY4N8JF") // consumer role
		if err != nil {
			_ = s.storage.LogAuthEvent(ctx, user.UserID, "signup", false, ipAddress, deviceInfo, "failed to assign default role")
			return nil, fmt.Errorf("failed to assign default role: %w", err)
		}

		// Refresh roles
		roles, err = s.storage.GetUserRoles(ctx, user.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user roles: %w", err)
		}
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.RoleName
	}

	// Generate tokens
	accessToken, err := s.jwt.GenerateAccessToken(user.UserID, user.Email, roleNames)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "signup", false, ipAddress, deviceInfo, "failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, tokenHash, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "signup", false, ipAddress, deviceInfo, "failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	expiresAt := time.Now().Add(RefreshTokenDuration)
	_, err = s.storage.CreateRefreshToken(ctx, user.UserID, tokenHash, expiresAt, deviceInfo, ipAddress)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "signup", false, ipAddress, deviceInfo, "failed to store refresh token")
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Log successful signup
	_ = s.storage.LogAuthEvent(ctx, user.UserID, "signup", true, ipAddress, deviceInfo, "")

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
		Roles:        roleNames,
	}, nil
}

// RefreshAccessToken generates a new access token using a refresh token
func (s *AuthService) RefreshAccessToken(ctx context.Context, refreshToken, deviceInfo, ipAddress string) (*LoginResult, error) {
	// Get refresh token from storage
	storedToken, err := s.storage.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, "", "token_refresh", false, ipAddress, deviceInfo, "refresh token not found")
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if token is revoked
	if storedToken.Revoked {
		_ = s.storage.LogAuthEvent(ctx, storedToken.UserID, "token_refresh", false, ipAddress, deviceInfo, "refresh token revoked")
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	// Check if token is expired
	if time.Now().After(storedToken.ExpiresAt) {
		_ = s.storage.LogAuthEvent(ctx, storedToken.UserID, "token_refresh", false, ipAddress, deviceInfo, "refresh token expired")
		return nil, fmt.Errorf("refresh token has expired")
	}

	// Get user
	user, err := s.storage.GetUserByID(ctx, storedToken.UserID)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, storedToken.UserID, "token_refresh", false, ipAddress, deviceInfo, "user not found")
		return nil, fmt.Errorf("user not found")
	}

	// Get user roles
	roles, err := s.storage.GetUserRoles(ctx, user.UserID)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "token_refresh", false, ipAddress, deviceInfo, "failed to get roles")
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.RoleName
	}

	// Generate new access token
	accessToken, err := s.jwt.GenerateAccessToken(user.UserID, user.Email, roleNames)
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, user.UserID, "token_refresh", false, ipAddress, deviceInfo, "failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Update last used time
	_ = s.storage.UpdateRefreshTokenLastUsed(ctx, storedToken.TokenID)

	// Log successful refresh
	_ = s.storage.LogAuthEvent(ctx, user.UserID, "token_refresh", true, ipAddress, deviceInfo, "")

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // Return the same refresh token
		User:         user,
		Roles:        roleNames,
	}, nil
}

// Logout invalidates tokens for a user
func (s *AuthService) Logout(ctx context.Context, accessToken, refreshToken string, ipAddress, userAgent string) error {
	// Extract user ID and JTI from access token
	claims, err := s.jwt.ValidateToken(accessToken)
	if err != nil {
		// Even if token is invalid, try to revoke refresh token
		if refreshToken != "" {
			storedToken, err := s.storage.GetRefreshToken(ctx, refreshToken)
			if err == nil {
				_ = s.storage.RevokeRefreshToken(ctx, storedToken.TokenID)
			}
		}
		return fmt.Errorf("invalid access token: %w", err)
	}

	// Add access token to deny list (TTL+1)
	expiresAt := claims.ExpiresAt.Time
	err = s.denyList.Add(ctx, claims.ID, claims.UserID, expiresAt, "logout")
	if err != nil {
		_ = s.storage.LogAuthEvent(ctx, claims.UserID, "logout", false, ipAddress, userAgent, "failed to add to deny list")
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	// Revoke refresh token if provided
	if refreshToken != "" {
		storedToken, err := s.storage.GetRefreshToken(ctx, refreshToken)
		if err == nil {
			err = s.storage.RevokeRefreshToken(ctx, storedToken.TokenID)
			if err != nil {
				_ = s.storage.LogAuthEvent(ctx, claims.UserID, "logout", false, ipAddress, userAgent, "failed to revoke refresh token")
				return fmt.Errorf("failed to revoke refresh token: %w", err)
			}
		}
	}

	// Log successful logout
	_ = s.storage.LogAuthEvent(ctx, claims.UserID, "logout", true, ipAddress, userAgent, "")

	return nil
}

// ValidateToken validates an access token and returns claims
func (s *AuthService) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	// Parse and validate token
	claims, err := s.jwt.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	// Check if token is in deny list
	if s.denyList.IsRevoked(claims.ID) {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// RevokeAllUserTokens revokes all tokens for a user (e.g., on password change)
func (s *AuthService) RevokeAllUserTokens(ctx context.Context, userID string) error {
	// Revoke all refresh tokens
	err := s.storage.RevokeAllUserRefreshTokens(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	// Note: We don't add all access tokens to deny list since we don't have a way to enumerate them
	// Instead, we rely on short access token TTL (15 minutes)
	// In a production system, you might want to maintain a session table to track all active access tokens

	return nil
}

// InitializeDenyList loads denied tokens from storage
func (s *AuthService) InitializeDenyList(ctx context.Context) error {
	return s.denyList.LoadFromStorage(ctx)
}

// Stop stops background services
func (s *AuthService) Stop() {
	s.denyList.Stop()
}
