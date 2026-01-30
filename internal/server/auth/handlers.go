package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// Handler wraps authentication service for HTTP handlers
type Handler struct {
	service      *AuthService
	storage      AuthStorage
	oauthService *OAuthService
}

// NewHandler creates a new authentication handler
func NewHandler(service *AuthService, storage AuthStorage) *Handler {
	return &Handler{
		service: service,
		storage: storage,
	}
}

// SetOAuthService sets the OAuth service for the handler
func (h *Handler) SetOAuthService(oauthService *OAuthService) {
	h.oauthService = oauthService
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignupRequest represents a signup request
type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// SetupRequest represents the initial admin setup request
type SetupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents a successful authentication response
type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	User         UserInfo `json:"user"`
}

// UserInfo represents user information in the response
type UserInfo struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	Verified bool     `json:"verified"`
	Roles    []string `json:"roles"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// Login handles login requests
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Get device info and IP address
	deviceInfo := r.UserAgent()
	ipAddress := r.RemoteAddr

	result, err := h.service.Login(r.Context(), req.Email, req.Password, deviceInfo, ipAddress)
	if err != nil {
		http.Error(w, `{"error": "invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	response := AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		User: UserInfo{
			UserID:   result.User.UserID,
			Email:    result.User.Email,
			Verified: result.User.Verified,
			Roles:    result.Roles,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Signup handles signup requests
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate password strength (basic validation)
	if len(req.Password) < 8 {
		http.Error(w, `{"error": "password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	deviceInfo := r.UserAgent()
	ipAddress := r.RemoteAddr

	result, err := h.service.Signup(r.Context(), req.Email, req.Password, deviceInfo, ipAddress)
	if err != nil {
		http.Error(w, `{"error": "failed to create account"}`, http.StatusInternalServerError)
		return
	}

	response := AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		User: UserInfo{
			UserID:   result.User.UserID,
			Email:    result.User.Email,
			Verified: result.User.Verified,
			Roles:    result.Roles,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Refresh handles token refresh requests
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	deviceInfo := r.UserAgent()
	ipAddress := r.RemoteAddr

	result, err := h.service.RefreshAccessToken(r.Context(), req.RefreshToken, deviceInfo, ipAddress)
	if err != nil {
		http.Error(w, `{"error": "invalid refresh token"}`, http.StatusUnauthorized)
		return
	}

	response := AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		User: UserInfo{
			UserID:   result.User.UserID,
			Email:    result.User.Email,
			Verified: result.User.Verified,
			Roles:    result.Roles,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Logout handles logout requests
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get access token from Authorization header
	authHeader := r.Header.Get("Authorization")
	var accessToken string
	if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		accessToken = authHeader[7:]
	}

	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Logout can work with just the access token
		if accessToken == "" {
			http.Error(w, `{"error": "invalid request"}`, http.StatusBadRequest)
			return
		}
	}

	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	err := h.service.Logout(r.Context(), accessToken, req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		// Even if logout fails, return success to the client
		// This prevents information leakage about token validity
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out successfully"})
}

// Setup handles initial admin account creation
func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Check if setup is already completed
	completed, err := h.storage.IsSetupCompleted(r.Context())
	if err != nil {
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	if completed {
		http.Error(w, `{"error": "setup already completed"}`, http.StatusConflict)
		return
	}

	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate password strength
	if len(req.Password) < 8 {
		http.Error(w, `{"error": "password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error": "failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	// Create the admin user
	user, err := h.storage.CreateUser(r.Context(), req.Email, hashedPassword)
	if err != nil {
		http.Error(w, `{"error": "failed to create admin user"}`, http.StatusInternalServerError)
		return
	}

	// Assign admin role (ID from migration: 01HQ5RJNXS6TPXK89PQWY4N8JD)
	err = h.storage.AssignRole(r.Context(), user.UserID, "01HQ5RJNXS6TPXK89PQWY4N8JD")
	if err != nil {
		http.Error(w, `{"error": "failed to assign admin role"}`, http.StatusInternalServerError)
		return
	}

	// Mark user as verified (admin doesn't need email verification)
	err = h.storage.UpdateUserVerified(r.Context(), user.UserID, true)
	if err != nil {
		http.Error(w, `{"error": "failed to verify user"}`, http.StatusInternalServerError)
		return
	}

	// Mark setup as completed
	err = h.storage.MarkSetupCompleted(r.Context())
	if err != nil {
		http.Error(w, `{"error": "failed to complete setup"}`, http.StatusInternalServerError)
		return
	}

	// Log the setup event
	_ = h.storage.LogAuthEvent(r.Context(), user.UserID, "setup", true, r.RemoteAddr, r.UserAgent(), "initial admin setup")

	// Auto-login the admin user
	deviceInfo := r.UserAgent()
	ipAddress := r.RemoteAddr

	result, err := h.service.Login(r.Context(), req.Email, req.Password, deviceInfo, ipAddress)
	if err != nil {
		// Setup succeeded but login failed - that's OK, user can login manually
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "setup completed successfully, please login",
		})
		return
	}

	response := AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		User: UserInfo{
			UserID:   result.User.UserID,
			Email:    result.User.Email,
			Verified: result.User.Verified,
			Roles:    result.Roles,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// SetupStatus checks if initial setup has been completed
func (h *Handler) SetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	completed, err := h.storage.IsSetupCompleted(r.Context())
	if err != nil {
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"setup_completed": completed,
	})
}

// OAuthProviderResponse represents an OAuth provider in the API response.
type OAuthProviderResponse struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ListOAuthProviders returns a list of enabled OAuth providers.
func (h *Handler) ListOAuthProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	providers, err := h.storage.ListEnabledOAuthProviders(r.Context())
	if err != nil {
		http.Error(w, `{"error": "failed to list providers"}`, http.StatusInternalServerError)
		return
	}

	response := make([]OAuthProviderResponse, len(providers))
	for i, p := range providers {
		response[i] = OAuthProviderResponse{
			Name: p.ProviderName,
			Type: p.ProviderType,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": response,
	})
}

// OAuthInitRequest represents a request to initiate OAuth flow.
type OAuthInitRequest struct {
	Provider string `json:"provider"`
}

// OAuthInit initiates the OAuth flow by returning the authorization URL.
func (h *Handler) OAuthInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if h.oauthService == nil {
		http.Error(w, `{"error": "OAuth not configured"}`, http.StatusServiceUnavailable)
		return
	}

	var req OAuthInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Provider == "" {
		http.Error(w, `{"error": "provider is required"}`, http.StatusBadRequest)
		return
	}

	// Generate a secure state parameter
	state, err := generateOAuthState()
	if err != nil {
		http.Error(w, `{"error": "failed to generate state"}`, http.StatusInternalServerError)
		return
	}

	authURL, err := h.oauthService.GetAuthorizationURL(req.Provider, state)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"authorization_url": authURL,
		"state":             state,
	})
}

// OAuthCallback handles the OAuth callback from the provider.
func (h *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request, providerName string) {
	if h.oauthService == nil {
		http.Error(w, `{"error": "OAuth not configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Get the authorization code from query params
	code := r.URL.Query().Get("code")
	if code == "" {
		// Check for error from provider
		errorParam := r.URL.Query().Get("error")
		errorDesc := r.URL.Query().Get("error_description")
		if errorParam != "" {
			http.Error(w, `{"error": "`+errorParam+`: `+errorDesc+`"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error": "missing authorization code"}`, http.StatusBadRequest)
		return
	}

	// Process the callback
	deviceInfo := r.UserAgent()
	ipAddress := r.RemoteAddr

	result, err := h.oauthService.HandleCallback(r.Context(), providerName, code, deviceInfo, ipAddress)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	response := AuthResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		User: UserInfo{
			UserID:   result.User.UserID,
			Email:    result.User.Email,
			Verified: result.User.Verified,
			Roles:    result.Roles,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// generateOAuthState generates a secure random state parameter for OAuth.
func generateOAuthState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
