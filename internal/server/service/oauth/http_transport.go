package oauth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
	"github.com/marsolab/servekit/idkit"
)

// OAuth Provider Management Handlers

func (s *Service) listProvidersHandler(w http.ResponseWriter, r *http.Request) {
	// Get organization from context or query parameter
	orgID := r.URL.Query().Get("org_id")

	providers, err := s.storage.ListProviders(r.Context(), orgID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("list providers: %w", err))
		return
	}

	httpkit.JSON(w, r, providers)
}

func (s *Service) createProviderHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		ProviderName string            `json:"provider_name"`
		OrgID        string            `json:"org_id,omitempty"`
		Config       map[string]string `json:"config"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("create provider: close request body", slog.String("error", err.Error()))
		}
	}()

	if req.ProviderName == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider name is required", errkit.ErrInvalidArgument))
		return
	}

	provider := Provider{
		ProviderID:   idkit.ULID(),
		ProviderName: req.ProviderName,
		OrgID:        req.OrgID,
		Config:       req.Config,
		IsActive:     true,
	}

	if err := s.storage.CreateProvider(r.Context(), provider); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create provider: %w", err))
		return
	}

	httpkit.JSON(w, r, provider)
}

func (s *Service) getProviderHandler(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")
	if providerID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider ID is required", errkit.ErrInvalidArgument))
		return
	}

	// This is a simplified version - in practice, you'd need to implement GetProviderByID
	// For now, return an error indicating this needs implementation
	httpkit.ErrorHTTP(w, r, fmt.Errorf("get provider by ID not implemented yet"))
}

func (s *Service) updateProviderHandler(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")
	if providerID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider ID is required", errkit.ErrInvalidArgument))
		return
	}

	type request struct {
		ProviderName string            `json:"provider_name"`
		Config       map[string]string `json:"config"`
		IsActive     *bool             `json:"is_active,omitempty"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("update provider: close request body", slog.String("error", err.Error()))
		}
	}()

	// Implementation would go here - simplified for now
	httpkit.ErrorHTTP(w, r, fmt.Errorf("update provider not implemented yet"))
}

func (s *Service) deleteProviderHandler(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")
	if providerID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider ID is required", errkit.ErrInvalidArgument))
		return
	}

	if err := s.storage.DeleteProvider(r.Context(), providerID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("delete provider: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// User Synchronization Handlers

func (s *Service) syncUserHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Provider string    `json:"provider"`
		User     OAuthUser `json:"user"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("sync user: close request body", slog.String("error", err.Error()))
		}
	}()

	if req.Provider == "" || req.User.Subject == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider and user subject are required", errkit.ErrInvalidArgument))
		return
	}

	syncedUser, err := s.SyncUser(r.Context(), req.User, req.Provider)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("sync user: %w", err))
		return
	}

	httpkit.JSON(w, r, syncedUser)
}

func (s *Service) getUserSyncStatusHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID is required", errkit.ErrInvalidArgument))
		return
	}

	// Implementation would get sync status from storage
	// For now, return a placeholder
	type response struct {
		UserID   string `json:"user_id"`
		IsSynced bool   `json:"is_synced"`
		LastSync string `json:"last_sync,omitempty"`
		Provider string `json:"provider,omitempty"`
	}

	resp := response{
		UserID:   userID,
		IsSynced: false,
	}

	httpkit.JSON(w, r, resp)
}

// Organization and Team Handlers

func (s *Service) listOrganizationsHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context to determine accessible organizations
	userInfo, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)
		return
	}

	// For now, return a simple response
	// In practice, this would query the database for organizations the user can access
	type response struct {
		Organizations []Organization `json:"organizations"`
		UserOrg       string         `json:"user_org"`
	}

	resp := response{
		Organizations: []Organization{},
		UserOrg:       "", // Would be derived from user info
	}

	httpkit.JSON(w, r, resp)
}

func (s *Service) listTeamsHandler(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if orgID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: organization ID is required", errkit.ErrInvalidArgument))
		return
	}

	teams, err := s.storage.GetTeamsByOrg(r.Context(), orgID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get teams: %w", err))
		return
	}

	httpkit.JSON(w, r, teams)
}

// User Team Management Handlers

func (s *Service) getUserTeamsHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID is required", errkit.ErrInvalidArgument))
		return
	}

	teams, err := s.storage.GetUserTeams(r.Context(), userID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get user teams: %w", err))
		return
	}

	httpkit.JSON(w, r, teams)
}

func (s *Service) assignUserToTeamHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	teamID := chi.URLParam(r, "teamID")

	if userID == "" || teamID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID and team ID are required", errkit.ErrInvalidArgument))
		return
	}

	if err := s.storage.AssignUserToTeam(r.Context(), userID, teamID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("assign user to team: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusCreated)
}

func (s *Service) removeUserFromTeamHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	teamID := chi.URLParam(r, "teamID")

	if userID == "" || teamID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID and team ID are required", errkit.ErrInvalidArgument))
		return
	}

	if err := s.storage.RemoveUserFromTeam(r.Context(), userID, teamID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("remove user from team: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}
