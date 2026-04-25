package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/config"
)

// Provider represents an OAuth provider configuration
type Provider struct {
	ProviderID   string            `json:"provider_id"`
	ProviderName string            `json:"provider_name"` // "kinde", "auth0", "okta", etc.
	OrgID        string            `json:"org_id,omitempty"`
	Config       map[string]string `json:"config"`
	IsActive     bool              `json:"is_active"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// OAuthUser represents a user from an OAuth provider
type OAuthUser struct {
	Subject      string         `json:"sub"` // OAuth subject identifier
	Email        string         `json:"email"`
	Name         string         `json:"name,omitempty"`
	Picture      string         `json:"picture,omitempty"`
	Roles        []string       `json:"roles,omitempty"`
	Organization string         `json:"organization,omitempty"`
	Teams        []string       `json:"teams,omitempty"`
	Claims       map[string]any `json:"claims,omitempty"`
}

// Storage encapsulates interaction with OAuth storage operations
type Storage interface {
	// OAuth provider management.
	CreateProvider(ctx context.Context, provider Provider) error
	GetProvider(ctx context.Context, providerName, orgID string) (*Provider, error)
	UpdateProvider(ctx context.Context, provider Provider) error
	DeleteProvider(ctx context.Context, providerID string) error
	ListProviders(ctx context.Context, orgID string) ([]Provider, error)

	// User synchronization.
	SyncOAuthUser(ctx context.Context, user OAuthUser, providerName, orgID string) error
	GetUserByOAuthSub(ctx context.Context, providerName, subject string) (*SyncedUser, error)
	UpdateUserLastSync(ctx context.Context, userID string) error

	// Organization and team management.
	GetOrganizationByCode(ctx context.Context, orgCode string) (*Organization, error)
	GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error)
	GetTeamsByOrg(ctx context.Context, orgID string) ([]Team, error)
	GetTeamByCode(ctx context.Context, orgID, teamCode string) (*Team, error)
	AssignUserToTeam(ctx context.Context, userID, teamID string) error
	RemoveUserFromTeam(ctx context.Context, userID, teamID string) error
	GetUserTeams(ctx context.Context, userID string) ([]Team, error)
}

// SyncedUser represents a synchronized OAuth user
type SyncedUser struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Name        string    `json:"name,omitempty"`
	OrgID       string    `json:"org_id"`
	Provider    string    `json:"oauth_provider"`
	Subject     string    `json:"oauth_sub"`
	IsOAuthUser bool      `json:"is_oauth_user"`
	LastSyncAt  time.Time `json:"last_sync_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Organization represents an organization entity
type Organization struct {
	OrgID     string    `json:"org_id"`
	OrgCode   string    `json:"org_code"`
	OrgName   string    `json:"org_name"`
	OrgDomain string    `json:"org_domain,omitempty"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Team represents a team within an organization
type Team struct {
	TeamID      string    `json:"team_id"`
	OrgID       string    `json:"org_id"`
	TeamName    string    `json:"team_name"`
	TeamCode    string    `json:"team_code"`
	Description string    `json:"description,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Service handles OAuth operations
type Service struct {
	cfg     *config.Config
	logger  *slog.Logger
	router  *chi.Mux
	storage Storage
}

// NewService creates a new OAuth service
func NewService(cfg *config.Config, logger *slog.Logger, storage Storage) *Service {
	s := Service{
		cfg:     cfg,
		logger:  logger,
		router:  chi.NewRouter(),
		storage: storage,
	}

	// Setup routes
	s.router.Route("/", func(r chi.Router) {
		// OAuth provider management
		r.Route("/providers", func(r chi.Router) {
			r.Get("/", s.listProvidersHandler)
			r.Post("/", s.createProviderHandler)
			r.Get("/{providerID}", s.getProviderHandler)
			r.Put("/{providerID}", s.updateProviderHandler)
			r.Delete("/{providerID}", s.deleteProviderHandler)
		})

		// User synchronization endpoints
		r.Route("/sync", func(r chi.Router) {
			r.Post("/user", s.syncUserHandler)
			r.Get("/user/{userID}", s.getUserSyncStatusHandler)
		})

		// Organization and team management
		r.Route("/organizations", func(r chi.Router) {
			r.Get("/", s.listOrganizationsHandler)
			r.Get("/{orgID}/teams", s.listTeamsHandler)
		})

		// Team management for users
		r.Route("/users/{userID}/teams", func(r chi.Router) {
			r.Get("/", s.getUserTeamsHandler)
			r.Post("/{teamID}", s.assignUserToTeamHandler)
			r.Delete("/{teamID}", s.removeUserFromTeamHandler)
		})
	})

	return &s
}

// ServeHTTP implements the http.Handler interface
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// SyncUser synchronizes a user from OAuth provider
func (s *Service) SyncUser(ctx context.Context, oauthUser OAuthUser, providerName string) (*SyncedUser, error) {
	// Determine organization
	orgID, err := s.determineOrganization(ctx, oauthUser)
	if err != nil {
		return nil, fmt.Errorf("determine organization: %w", err)
	}

	// Sync the user
	if err := s.storage.SyncOAuthUser(ctx, oauthUser, providerName, orgID); err != nil {
		return nil, fmt.Errorf("sync oauth user: %w", err)
	}

	// Get the synced user
	syncedUser, err := s.storage.GetUserByOAuthSub(ctx, providerName, oauthUser.Subject)
	if err != nil {
		return nil, fmt.Errorf("get synced user: %w", err)
	}

	// Sync teams
	if err := s.syncUserTeams(ctx, syncedUser.UserID, oauthUser.Teams, orgID); err != nil {
		s.logger.Warn("failed to sync user teams",
			slog.String("user_id", syncedUser.UserID),
			slog.String("error", err.Error()))
	}

	return syncedUser, nil
}

// determineOrganization determines which organization a user belongs to
func (s *Service) determineOrganization(ctx context.Context, user OAuthUser) (string, error) {
	// If organization is specified in the OAuth claims
	if user.Organization != "" {
		org, err := s.storage.GetOrganizationByCode(ctx, user.Organization)
		if err == nil {
			return org.OrgID, nil
		}
	}

	// Try to determine by email domain
	if user.Email != "" {
		domain := extractDomain(user.Email)
		if domain != "" {
			org, err := s.storage.GetOrganizationByDomain(ctx, domain)
			if err == nil {
				return org.OrgID, nil
			}
		}
	}

	// Fall back to default organization if multi-tenancy is disabled
	if !s.cfg.MultiTenancyEnable && s.cfg.DefaultOrganization != "" {
		org, err := s.storage.GetOrganizationByCode(ctx, s.cfg.DefaultOrganization)
		if err == nil {
			return org.OrgID, nil
		}
	}

	return "", fmt.Errorf("could not determine organization for user %s", user.Email)
}

// syncUserTeams synchronizes user team memberships
func (s *Service) syncUserTeams(ctx context.Context, userID string, teamCodes []string, orgID string) error {
	// Get current teams
	currentTeams, err := s.storage.GetUserTeams(ctx, userID)
	if err != nil {
		return fmt.Errorf("get current user teams: %w", err)
	}

	// Build map of current team codes
	currentTeamCodes := make(map[string]string)
	for _, team := range currentTeams {
		currentTeamCodes[team.TeamCode] = team.TeamID
	}

	// Add user to new teams
	for _, teamCode := range teamCodes {
		if _, exists := currentTeamCodes[teamCode]; !exists {
			team, err := s.storage.GetTeamByCode(ctx, orgID, teamCode)
			if err != nil {
				s.logger.Warn("team not found for code",
					slog.String("team_code", teamCode),
					slog.String("org_id", orgID))
				continue
			}

			if err := s.storage.AssignUserToTeam(ctx, userID, team.TeamID); err != nil {
				s.logger.Warn("failed to assign user to team",
					slog.String("user_id", userID),
					slog.String("team_id", team.TeamID),
					slog.String("error", err.Error()))
			}
		}
	}

	// Remove user from teams not in the new list (optional - depends on sync strategy)
	// This is commented out as it might be too aggressive
	// for _, teamCode := range currentTeamCodes {
	//     if !contains(teamCodes, teamCode) {
	//         // Remove from team
	//     }
	// }

	return nil
}

// extractDomain extracts domain from email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// IsOAuthEnabled returns true if OAuth is enabled
func (s *Service) IsOAuthEnabled() bool {
	return s.cfg.OAuthEnable
}

// GetProviderConfig returns the OAuth provider configuration
func (s *Service) GetProviderConfig() map[string]string {
	return map[string]string{
		"provider":     s.cfg.OAuthProvider,
		"client_id":    s.cfg.OAuthClientID,
		"domain":       s.cfg.OAuthDomain,
		"audience":     s.cfg.OAuthAudience,
		"callback_url": s.cfg.OAuthCallbackURL,
		"scope":        s.cfg.OAuthScope,
		"jwks_url":     s.cfg.OAuthJWKSURL,
	}
}
