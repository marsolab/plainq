package onboarding

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/servekit/authkit/hashkit"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/idkit"
)

// Storage encapsulates interaction with onboarding storage operations.
type Storage interface {
	// HasAdminUsers checks if there are any users with admin role
	HasAdminUsers(ctx context.Context) (bool, error)

	// CreateInitialAdmin creates the first admin user and assigns admin role
	CreateInitialAdmin(ctx context.Context, admin InitialAdmin) error

	// GetAdminRoleID gets the admin role ID
	GetAdminRoleID(ctx context.Context) (string, error)
}

// InitialAdmin represents the initial admin user to be created
type InitialAdmin struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Name      string    `json:"name,omitempty"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

// OnboardingStatus represents the current onboarding state
type OnboardingStatus struct {
	NeedsOnboarding bool `json:"needs_onboarding"`
	HasAdminUsers   bool `json:"has_admin_users"`
}

// Service handles the onboarding process
type Service struct {
	cfg     *config.Config
	logger  *slog.Logger
	router  *chi.Mux
	hasher  hashkit.Hasher
	tokman  jwtkit.TokenManager
	storage Storage
}

// NewService creates a new onboarding service
func NewService(
	cfg *config.Config,
	logger *slog.Logger,
	hasher hashkit.Hasher,
	tokenManager jwtkit.TokenManager,
	storage Storage,
) *Service {
	s := Service{
		cfg:     cfg,
		logger:  logger,
		router:  chi.NewRouter(),
		hasher:  hasher,
		tokman:  tokenManager,
		storage: storage,
	}

	// Setup routes - these are public routes that don't require authentication
	s.router.Route("/", func(r chi.Router) {
		r.Get("/status", s.getOnboardingStatusHandler)
		r.Post("/complete", s.completeOnboardingHandler)
	})

	return &s
}

// ServeHTTP implements the http.Handler interface
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// NeedsOnboarding checks if the system needs onboarding (no admin users exist)
func (s *Service) NeedsOnboarding(ctx context.Context) (bool, error) {
	hasAdmins, err := s.storage.HasAdminUsers(ctx)
	if err != nil {
		return false, err
	}
	return !hasAdmins, nil
}

// IsOnboardingComplete checks if onboarding has been completed (admin users exist)
func (s *Service) IsOnboardingComplete(ctx context.Context) (bool, error) {
	return s.storage.HasAdminUsers(ctx)
}

// CreateInitialAdmin creates the first admin user during onboarding
func (s *Service) CreateInitialAdmin(ctx context.Context, email, password, name string) (*InitialAdmin, error) {
	// Hash the password
	hashedPassword, err := s.hasher.HashPassword(password)
	if err != nil {
		return nil, err
	}

	admin := InitialAdmin{
		UserID:    generateUserID(),
		Email:     email,
		Password:  hashedPassword,
		Name:      name,
		Verified:  true, // Initial admin is auto-verified
		CreatedAt: time.Now(),
	}

	if err := s.storage.CreateInitialAdmin(ctx, admin); err != nil {
		return nil, err
	}

	// Don't return the hashed password
	admin.Password = ""
	return &admin, nil
}

// generateUserID generates a new ULID for user ID
func generateUserID() string {
	return idkit.ULID()
}
