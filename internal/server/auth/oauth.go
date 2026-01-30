package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// OAuthService handles OAuth provider integrations
type OAuthService struct {
	storage     AuthStorage
	authService *AuthService
	baseURL     string // Base URL for OAuth callbacks (e.g., "https://example.com")
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(storage AuthStorage, authService *AuthService, baseURL string) *OAuthService {
	// Ensure baseURL doesn't have trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:8081"
	}
	return &OAuthService{
		storage:     storage,
		authService: authService,
		baseURL:     baseURL,
	}
}

// GetRedirectURL returns the OAuth redirect URL for a provider
func (s *OAuthService) GetRedirectURL(providerName string) string {
	return fmt.Sprintf("%s/api/v1/auth/oauth/%s/callback", s.baseURL, providerName)
}

// OAuthConfig represents OAuth configuration for a provider
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserinfoURL  string
}

// GetAuthorizationURL generates the OAuth authorization URL
func (s *OAuthService) GetAuthorizationURL(providerName, state string) (string, error) {
	provider, err := s.storage.GetOAuthProvider(context.Background(), providerName)
	if err != nil {
		return "", fmt.Errorf("provider not found: %w", err)
	}

	if !provider.Enabled {
		return "", fmt.Errorf("provider is disabled")
	}

	// Parse scopes from JSON
	var scopes []string
	if provider.Scopes != "" {
		if err := json.Unmarshal([]byte(provider.Scopes), &scopes); err != nil {
			scopes = []string{"openid", "email", "profile"}
		}
	} else {
		scopes = []string{"openid", "email", "profile"}
	}

	// Build authorization URL
	params := url.Values{}
	params.Add("client_id", provider.ClientID)
	params.Add("redirect_uri", s.GetRedirectURL(providerName))
	params.Add("response_type", "code")
	params.Add("scope", strings.Join(scopes, " "))
	params.Add("state", state)

	authURL := provider.AuthURL
	if authURL == "" && provider.IssuerURL != "" {
		authURL = provider.IssuerURL + "/authorize"
	}

	return authURL + "?" + params.Encode(), nil
}

// ExchangeCodeForToken exchanges an authorization code for tokens
func (s *OAuthService) ExchangeCodeForToken(ctx context.Context, providerName, code string) (map[string]interface{}, error) {
	provider, err := s.storage.GetOAuthProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}

	// Prepare token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("redirect_uri", s.GetRedirectURL(providerName))

	tokenURL := provider.TokenURL
	if tokenURL == "" && provider.IssuerURL != "" {
		tokenURL = provider.IssuerURL + "/token"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResponse, nil
}

// GetUserInfo retrieves user information from the OAuth provider
func (s *OAuthService) GetUserInfo(ctx context.Context, providerName, accessToken string) (map[string]interface{}, error) {
	provider, err := s.storage.GetOAuthProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}

	userinfoURL := provider.UserinfoURL
	if userinfoURL == "" && provider.IssuerURL != "" {
		userinfoURL = provider.IssuerURL + "/userinfo"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", string(body))
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	return userInfo, nil
}

// HandleCallback processes the OAuth callback and creates/links user account
func (s *OAuthService) HandleCallback(ctx context.Context, providerName, code, deviceInfo, ipAddress string) (*LoginResult, error) {
	// Exchange code for tokens
	tokenResponse, err := s.ExchangeCodeForToken(ctx, providerName, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	accessToken, ok := tokenResponse["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("no access token in response")
	}

	// Get user info from provider
	userInfo, err := s.GetUserInfo(ctx, providerName, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Extract user details
	providerUserID, ok := userInfo["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("no user ID in userinfo")
	}

	email, _ := userInfo["email"].(string)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	// Get provider
	provider, err := s.storage.GetOAuthProvider(ctx, providerName)
	if err != nil {
		return nil, err
	}

	// Check if OAuth connection exists
	conn, err := s.storage.GetOAuthConnection(ctx, provider.ProviderID, providerUserID)
	if err == nil {
		// Connection exists, login the user
		user, err := s.storage.GetUserByID(ctx, conn.UserID)
		if err != nil {
			return nil, fmt.Errorf("user not found: %w", err)
		}

		// Update connection with latest info
		profileData, _ := json.Marshal(userInfo)
		conn.ProfileData = string(profileData)
		conn.Email = email
		_ = s.storage.UpdateOAuthConnection(ctx, conn)

		// Generate tokens
		roles, err := s.storage.GetUserRoles(ctx, user.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user roles: %w", err)
		}

		roleNames := make([]string, len(roles))
		for i, role := range roles {
			roleNames[i] = role.RoleName
		}

		// Use the auth service to generate tokens
		return s.authService.Login(ctx, user.Email, "", deviceInfo, ipAddress)
	}

	// Connection doesn't exist, check if user exists by email
	user, err := s.storage.GetUserByEmail(ctx, email)
	if err != nil {
		// User doesn't exist, create new user
		// Generate a random password (user will login via OAuth)
		randomPassword, _ := generateRandomPassword(32)
		hashedPassword, err := HashPassword(randomPassword)
		if err != nil {
			return nil, err
		}

		user, err = s.storage.CreateUser(ctx, email, hashedPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		// Assign consumer role
		_ = s.storage.AssignRole(ctx, user.UserID, "01HQ5RJNXS6TPXK89PQWY4N8JF")

		// Mark as verified (OAuth email is trusted)
		_ = s.storage.UpdateUserVerified(ctx, user.UserID, true)
	}

	// Create OAuth connection
	profileData, _ := json.Marshal(userInfo)
	newConn := &OAuthConnection{
		UserID:         user.UserID,
		ProviderID:     provider.ProviderID,
		ProviderUserID: providerUserID,
		Email:          email,
		ProfileData:    string(profileData),
	}

	err = s.storage.CreateOAuthConnection(ctx, newConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth connection: %w", err)
	}

	// Login the user
	return s.authService.Login(ctx, user.Email, "", deviceInfo, ipAddress)
}

// generateRandomPassword generates a random password
func generateRandomPassword(length int) (string, error) {
	// Reuse the refresh token generation logic
	jwtService := NewJWTService("temp", "temp")
	token, _, err := jwtService.GenerateRefreshToken()
	if err != nil {
		return "", err
	}

	if len(token) > length {
		return token[:length], nil
	}
	return token, nil
}
