package onboarding

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

const defaultBootstrapMaxBytes int64 = 32 << 10

// onboardingRequest is the payload accepted by completeOnboardingHandler.
// It is package-level so validateOnboardingRequest can reference the type.
type onboardingRequest struct {
	BootstrapSecret string `json:"bootstrap_secret"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	Name            string `json:"name,omitempty"`
}

// getOnboardingStatusHandler returns the current onboarding status.
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

// completeOnboardingHandler handles the creation of the initial admin user.
func (s *Service) completeOnboardingHandler(w http.ResponseWriter, r *http.Request) {
	maxBytes := s.cfg.AuthRequestMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultBootstrapMaxBytes
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

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

	if !s.allowBootstrapRequest(r, req.Email) {
		rejectBootstrapRate(w, r)

		return
	}

	// Validate input.
	if err := s.validateOnboardingRequest(req); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	admin, session, err := s.bootstrap(r.Context(), req, bootstrapRequestMetadata{
		RequestID: requestID(r), SourceIP: requestSourceIP(r), UserAgent: r.UserAgent(),
	})
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("complete onboarding: %w", err))

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

type bootstrapRequestMetadata struct {
	RequestID string
	SourceIP  string
	UserAgent string
}

// bootstrap creates tokens first, then commits the user, role, principal,
// hashed refresh token, and audit event in one storage transaction. Raw
// tokens are returned only after that transaction succeeds.
func (s *Service) bootstrap(
	ctx context.Context,
	req onboardingRequest,
	metadata bootstrapRequestMetadata,
) (*InitialAdmin, *Session, error) {
	if !bootstrapSecretMatches(req.BootstrapSecret, s.cfg.AuthBootstrapSecret) {
		return nil, nil, errkit.ErrUnauthenticated
	}

	hashedPassword, err := s.hasher.HashPassword(req.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	admin := InitialAdmin{
		UserID: generateUserID(), Email: req.Email, Password: hashedPassword, Name: req.Name,
		Verified: true, CreatedAt: now, TenantID: principal.LegacyTenantID,
		AuthVersion: 1, Status: "active",
	}

	session, refresh, err := s.createAdminSession(admin, now)
	if err != nil {
		return nil, nil, err
	}

	record := BootstrapRecord{
		Admin:        admin,
		RefreshToken: refresh,
		Audit: AuditEvent{
			ID: generateUserID(), TenantID: admin.TenantID,
			PrincipalKind: string(principal.KindHuman), PrincipalID: admin.UserID,
			Action: "onboarding.bootstrap", ResourceKind: "tenant", ResourceID: admin.TenantID,
			Outcome: "success", RequestID: metadata.RequestID, SourceIP: metadata.SourceIP,
			UserAgent: metadata.UserAgent, MetadataJSON: []byte(`{}`), CreatedAt: now,
		},
	}
	if err := s.storage.Bootstrap(ctx, record); err != nil {
		return nil, nil, fmt.Errorf("persist bootstrap transaction: %w", err)
	}

	admin.Password = ""

	return &admin, session, nil
}

// validateOnboardingRequest validates the onboarding request data.
func (s *Service) validateOnboardingRequest(req onboardingRequest) error {
	if req.BootstrapSecret == "" {
		return fmt.Errorf("%w: bootstrap secret is required", errkit.ErrUnauthenticated)
	}

	if req.Email == "" {
		return fmt.Errorf("%w: email is required", errkit.ErrInvalidArgument)
	}

	if req.Password == "" {
		return fmt.Errorf("%w: password is required", errkit.ErrInvalidArgument)
	}

	// Basic email validation.
	if !strings.Contains(req.Email, "@") || !strings.Contains(req.Email, ".") {
		return fmt.Errorf("%w: invalid email format", errkit.ErrInvalidArgument)
	}

	// Password strength validation.
	if len(req.Password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters long", errkit.ErrInvalidArgument)
	}

	// Optional name validation.
	if req.Name != "" && len(req.Name) > 100 {
		return fmt.Errorf("%w: name must be less than 100 characters", errkit.ErrInvalidArgument)
	}

	return nil
}

// Session represents an authentication session (same as account service).
type Session struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// createAdminSession creates a session for the newly created admin user.
func (s *Service) createAdminSession(admin InitialAdmin, t time.Time) (*Session, RefreshTokenRecord, error) {
	// Admin users get the admin role.
	roles := []string{"admin"}

	tokenID := generateUserID() // Generate a unique token ID.

	accessToken, aErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tokenID,
			Audience:  []string{s.cfg.AuthJWTAudience},
			Issuer:    s.cfg.AuthJWTIssuer,
			Subject:   admin.UserID,
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthAccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"uid":          admin.UserID,
			"email":        admin.Email,
			"roles":        roles,
			"tenant_id":    admin.TenantID,
			"auth_version": admin.AuthVersion,
			"token_use":    "access",
		},
	})
	if aErr != nil {
		return nil, RefreshTokenRecord{}, fmt.Errorf("onboarding service: failed to create access token: %w", aErr)
	}

	refreshToken, rErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tokenID,
			Audience:  []string{s.cfg.AuthJWTAudience},
			Issuer:    s.cfg.AuthJWTIssuer,
			Subject:   admin.UserID,
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthRefreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"aid":          admin.UserID,
			"tenant_id":    admin.TenantID,
			"auth_version": admin.AuthVersion,
			"token_use":    "refresh",
		},
	})
	if rErr != nil {
		return nil, RefreshTokenRecord{}, fmt.Errorf("onboarding service: failed to create refresh token: %w", rErr)
	}

	session := Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreatedAt:    t,
		ExpiresAt:    t.Add(s.cfg.AuthAccessTokenTTL),
	}

	tokenHash := sha256.Sum256([]byte(refreshToken))
	record := RefreshTokenRecord{
		ID: tokenID, AccountID: admin.UserID, TokenHash: tokenHash[:],
		CreatedAt: t, ExpiresAt: t.Add(s.cfg.AuthRefreshTokenTTL), LastUsedAt: t,
	}

	return &session, record, nil
}

func bootstrapSecretMatches(provided, configured string) bool {
	providedDigest := sha256.Sum256([]byte(provided))
	configuredDigest := sha256.Sum256([]byte(configured))

	return subtle.ConstantTimeCompare(providedDigest[:], configuredDigest[:]) == 1
}

func requestID(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get("X-Request-ID")); id != "" {
		return id
	}

	return generateUserID()
}

func requestSourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return r.RemoteAddr
}
