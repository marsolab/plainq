package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

const (
	tokenIssuer = "plainq-server"
)

// onboardingRequest is the payload accepted by completeOnboardingHandler.
// It is package-level so validateOnboardingRequest can reference the type.
type onboardingRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

// getOnboardingStatusHandler returns the current onboarding status
func (s *Service) getOnboardingStatusHandler(w http.ResponseWriter, r *http.Request) {
	needsOnboarding, err := s.NeedsOnboarding(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("check onboarding status: %w", err))
		return
	}

	status := OnboardingStatus{
		NeedsOnboarding: needsOnboarding,
		HasAdminUsers:   !needsOnboarding,
	}

	httpkit.JSON(w, r, status)
}

// completeOnboardingHandler handles the creation of the initial admin user
func (s *Service) completeOnboardingHandler(w http.ResponseWriter, r *http.Request) {
	// First, verify that onboarding is actually needed
	needsOnboarding, err := s.NeedsOnboarding(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("check onboarding status: %w", err))
		return
	}

	if !needsOnboarding {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: onboarding has already been completed", errkit.ErrInvalidArgument))
		return
	}

	var req onboardingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("complete onboarding: close request body", slog.String("error", err.Error()))
		}
	}()

	// Validate input
	if err := s.validateOnboardingRequest(req); err != nil {
		httpkit.ErrorHTTP(w, r, err)
		return
	}

	// Create the initial admin user
	admin, err := s.CreateInitialAdmin(r.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create initial admin: %w", err))
		return
	}

	// Generate session tokens for the new admin
	session, err := s.createAdminSession(r.Context(), admin.UserID, admin.Email, time.Now())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create admin session: %w", err))
		return
	}

	type response struct {
		Admin   *InitialAdmin `json:"admin"`
		Session *Session      `json:"session"`
		Message string        `json:"message"`
	}

	resp := response{
		Admin:   admin,
		Session: session,
		Message: "Onboarding completed successfully. Welcome to PlainQ!",
	}

	s.logger.Info("onboarding completed",
		slog.String("admin_email", admin.Email),
		slog.String("admin_id", admin.UserID))

	httpkit.JSON(w, r, resp)
}

// validateOnboardingRequest validates the onboarding request data
func (s *Service) validateOnboardingRequest(req onboardingRequest) error {
	if req.Email == "" {
		return fmt.Errorf("%w: email is required", errkit.ErrInvalidArgument)
	}

	if req.Password == "" {
		return fmt.Errorf("%w: password is required", errkit.ErrInvalidArgument)
	}

	// Basic email validation
	if !strings.Contains(req.Email, "@") || !strings.Contains(req.Email, ".") {
		return fmt.Errorf("%w: invalid email format", errkit.ErrInvalidArgument)
	}

	// Password strength validation
	if len(req.Password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters long", errkit.ErrInvalidArgument)
	}

	// Optional name validation
	if req.Name != "" && len(req.Name) > 100 {
		return fmt.Errorf("%w: name must be less than 100 characters", errkit.ErrInvalidArgument)
	}

	return nil
}

// Session represents an authentication session (same as account service)
type Session struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// createAdminSession creates a session for the newly created admin user
func (s *Service) createAdminSession(ctx context.Context, userID, email string, t time.Time) (*Session, error) {
	// Admin users get the admin role
	roles := []string{"admin"}

	tokenID := generateUserID() // Generate a unique token ID

	accessToken, aErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tokenID,
			Audience:  []string{},
			Issuer:    tokenIssuer,
			Subject:   "",
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthAccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"uid":   userID,
			"email": email,
			"roles": roles,
		},
	})
	if aErr != nil {
		return nil, fmt.Errorf("onboarding service: failed to create access token: %w", aErr)
	}

	refreshToken, rErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tokenID,
			Audience:  []string{},
			Issuer:    tokenIssuer,
			Subject:   "",
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthRefreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"aid": userID, // For compatibility with refresh token parsing
		},
	})
	if rErr != nil {
		return nil, fmt.Errorf("onboarding service: failed to create refresh token: %w", rErr)
	}

	session := Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreatedAt:    t,
		ExpiresAt:    t.Add(s.cfg.AuthAccessTokenTTL),
	}

	return &session, nil
}
