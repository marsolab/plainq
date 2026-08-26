package onboarding

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/config"
	serversecurity "github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/servekit/authkit/hashkit"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/idkit"
)

// Storage encapsulates interaction with onboarding storage operations.
type Storage interface {
	// HasAdminUsers checks if there are any users with admin role.
	HasAdminUsers(ctx context.Context) (bool, error)

	// Bootstrap atomically creates the first administrator, role projection,
	// hashed refresh session, and security audit record. The implementation
	// must serialize the no-admin check with those writes.
	Bootstrap(ctx context.Context, record BootstrapRecord) error
}

// InitialAdmin represents the initial admin user to be created.
type InitialAdmin struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Password    string    `json:"-"`
	Name        string    `json:"name,omitempty"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
	TenantID    string    `json:"tenant_id"`
	AuthVersion uint64    `json:"auth_version"`
	Status      string    `json:"status"`
}

// RefreshTokenRecord is the persisted half of the initial administrator's
// session. TokenHash is SHA-256(raw signed refresh token); raw credentials
// never cross the storage boundary.
type RefreshTokenRecord struct {
	ID         string
	AccountID  string
	TokenHash  []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

// AuditEvent captures the bootstrap mutation in the same transaction as the
// administrator and session.
type AuditEvent struct {
	ID            string
	TenantID      string
	PrincipalKind string
	PrincipalID   string
	Action        string
	ResourceKind  string
	ResourceID    string
	Outcome       string
	RequestID     string
	Reason        string
	SourceIP      string
	UserAgent     string
	MetadataJSON  []byte
	CreatedAt     time.Time
}

// BootstrapRecord is the complete transaction input for first-admin setup.
type BootstrapRecord struct {
	Admin        InitialAdmin
	RefreshToken RefreshTokenRecord
	Audit        AuditEvent
}

// OnboardingStatus represents the current onboarding state.
type OnboardingStatus struct {
	NeedsOnboarding bool `json:"needs_onboarding"`
	HasAdminUsers   bool `json:"has_admin_users"`
}

// Service handles the onboarding process.
type Service struct {
	cfg         *config.Config
	logger      *slog.Logger
	router      *chi.Mux
	hasher      hashkit.Hasher
	tokman      jwtkit.TokenManager
	storage     Storage
	rateLimiter *serversecurity.KeyedLimiter
}

// NewService creates a new onboarding service.
func NewService(
	cfg *config.Config,
	logger *slog.Logger,
	hasher hashkit.Hasher,
	tokenManager jwtkit.TokenManager,
	storage Storage,
) *Service {
	s := Service{
		cfg:         cfg,
		logger:      logger,
		router:      chi.NewRouter(),
		hasher:      hasher,
		tokman:      tokenManager,
		storage:     storage,
		rateLimiter: newBootstrapRateLimiter(cfg),
	}

	// Setup routes - these are public routes that don't require authentication.
	s.router.Route("/", func(r chi.Router) {
		r.Get("/status", s.getOnboardingStatusHandler)
		r.Post("/complete", s.completeOnboardingHandler)
	})

	return &s
}

// ServeHTTP implements the http.Handler interface.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// NeedsOnboarding checks if the system needs onboarding (no admin users exist).
func (s *Service) NeedsOnboarding(ctx context.Context) (bool, error) {
	hasAdmins, err := s.storage.HasAdminUsers(ctx)
	if err != nil {
		return false, fmt.Errorf("check admin users: %w", err)
	}

	return !hasAdmins, nil
}

// IsOnboardingComplete checks if onboarding has been completed (admin users exist).
func (s *Service) IsOnboardingComplete(ctx context.Context) (bool, error) {
	hasAdmins, err := s.storage.HasAdminUsers(ctx)
	if err != nil {
		return false, fmt.Errorf("check admin users: %w", err)
	}

	return hasAdmins, nil
}

// generateUserID generates a new ULID for user ID.
func generateUserID() string {
	return idkit.ULID()
}
