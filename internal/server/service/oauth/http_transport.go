package oauth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
	"github.com/marsolab/servekit/idkit"
)

// OAuth Provider Management Handlers.

func (s *Service) listProvidersHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.providerScope(w, r)
	if !ok {
		return
	}

	providers, err := s.storage.ListProviders(r.Context(), orgID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("list providers: %w", err)))

		return
	}

	stats, err := s.storage.ListProviderSyncStats(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("list provider sync stats: %w", err)))

		return
	}

	type response struct {
		Providers []PublicProvider   `json:"providers"`
		SyncStats []ProviderSyncStat `json:"sync_stats"`
	}

	httpkit.JSON(w, r, response{
		Providers: PublicProviders(providers),
		SyncStats: stats,
	})
}

func (s *Service) createProviderHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		ProviderName string            `json:"provider_name"`
		OrgID        string            `json:"org_id,omitempty"`
		Config       map[string]string `json:"config"`
		IsActive     *bool             `json:"is_active,omitempty"`
	}

	var req request
	if err := s.decode(r, &req, "create provider"); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	if req.ProviderName == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider name is required", errkit.ErrInvalidArgument))

		return
	}

	// A provider registered against another tenant would be invisible to that
	// tenant's operators and editable by this one, so the scope is the
	// caller's, never the request's, whenever multi-tenancy is on.
	orgID := req.OrgID

	if s.cfg.MultiTenancyEnable {
		scoped, ok := s.providerScope(w, r)
		if !ok {
			return
		}

		orgID = scoped
	}

	provider := Provider{
		ProviderID:   idkit.ULID(),
		ProviderName: req.ProviderName,
		OrgID:        orgID,
		Config:       req.Config,
		// A provider is inert until somebody activates it: creating one stores
		// configuration, it does not put an untested issuer into the sign-in
		// path.
		IsActive: req.IsActive != nil && *req.IsActive,
	}

	if err := s.storage.CreateProvider(r.Context(), provider); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("create provider: %w", err)))

		return
	}

	// Storage stamps the timestamps, so answering with the struct that went in
	// would report a provider created in year one.
	stored, err := s.storage.GetProviderByID(r.Context(), provider.ProviderID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("read created provider: %w", err)))

		return
	}

	httpkit.JSON(w, r, stored.Public(), httpkit.WithStatus(http.StatusCreated))
}

func (s *Service) getProviderHandler(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.loadProvider(w, r)
	if !ok {
		return
	}

	httpkit.JSON(w, r, provider.Public())
}

func (s *Service) updateProviderHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		ProviderName string            `json:"provider_name,omitempty"`
		Config       map[string]string `json:"config"`
		IsActive     *bool             `json:"is_active,omitempty"`
	}

	stored, ok := s.loadProvider(w, r)
	if !ok {
		return
	}

	var req request
	if err := s.decode(r, &req, "update provider"); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	updated := Provider{
		ProviderID:   stored.ProviderID,
		ProviderName: stored.ProviderName,
		OrgID:        stored.OrgID,
		Config:       stored.Config,
		IsActive:     stored.IsActive,
		CreatedAt:    stored.CreatedAt,
	}

	if req.ProviderName != "" {
		updated.ProviderName = req.ProviderName
	}

	if req.Config != nil {
		updated.Config = MergeConfig(stored.Config, req.Config)
	}

	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}

	if err := s.storage.UpdateProvider(r.Context(), updated); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("update provider: %w", err)))

		return
	}

	// Answer with what was stored rather than with what was sent: the response
	// is the value a reload will show, timestamps included.
	stored, err := s.storage.GetProviderByID(r.Context(), updated.ProviderID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("read updated provider: %w", err)))

		return
	}

	httpkit.JSON(w, r, stored.Public())
}

func (s *Service) deleteProviderHandler(w http.ResponseWriter, r *http.Request) {
	// Loading first both resolves a missing provider to 404 rather than 204 and
	// enforces the tenant scope, which a delete-by-ID alone would not.
	provider, ok := s.loadProvider(w, r)
	if !ok {
		return
	}

	if err := s.storage.DeleteProvider(r.Context(), provider.ProviderID); err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("delete provider: %w", err)))

		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}

// loadProvider reads the provider named in the URL and checks it belongs to the
// caller's scope. It writes the response and returns false when it cannot.
func (s *Service) loadProvider(w http.ResponseWriter, r *http.Request) (*Provider, bool) {
	providerID := chi.URLParam(r, "providerID")
	if providerID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider ID is required", errkit.ErrInvalidArgument))

		return nil, false
	}

	provider, err := s.storage.GetProviderByID(r.Context(), providerID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get provider: %w", err)))

		return nil, false
	}

	if s.cfg.MultiTenancyEnable {
		scope, ok := s.providerScope(w, r)
		if !ok {
			return nil, false
		}

		if provider.OrgID != scope {
			// Not found, not forbidden: confirming the ID exists would let a
			// caller enumerate another tenant's providers.
			httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider not found", errkit.ErrNotFound))

			return nil, false
		}
	}

	return provider, true
}

// providerScope is the organization whose providers this request may see. With
// multi-tenancy off there is one implicit organization and the global scope is
// it; with it on, the scope is the caller's own organization, read from the
// server's record rather than from the request.
func (s *Service) providerScope(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !s.cfg.MultiTenancyEnable {
		return r.URL.Query().Get("org_id"), true
	}

	orgID, err := s.callerOrg(r)
	if err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return "", false
	}

	return orgID, true
}

// callerOrg resolves the authenticated caller's organization.
func (s *Service) callerOrg(r *http.Request) (string, error) {
	user, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		return "", fmt.Errorf(
			"%w: multi-tenancy requires authentication to scope the request",
			errkit.ErrUnauthorized,
		)
	}

	orgID, err := s.storage.GetUserOrgID(r.Context(), user.UserID)
	if err != nil {
		return "", pqerr.AsTransport(fmt.Errorf("resolve caller organization: %w", err))
	}

	return orgID, nil
}

// decode reads a JSON request body, closing it whatever happens.
func (s *Service) decode(r *http.Request, target any, op string) error {
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error(op+": close request body", slog.String("error", err.Error()))
		}
	}()

	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error())
	}

	return nil
}

// User Synchronization Handlers.

func (s *Service) syncUserHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Provider string    `json:"provider"`
		User     OAuthUser `json:"user"`
	}

	var req request
	if err := s.decode(r, &req, "sync user"); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	if req.Provider == "" || req.User.Subject == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: provider and user subject are required", errkit.ErrInvalidArgument))

		return
	}

	syncedUser, err := s.SyncUser(r.Context(), req.User, req.Provider)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("sync user: %w", err)))

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

	status, err := s.storage.GetUserSyncStatus(r.Context(), userID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get user sync status: %w", err)))

		return
	}

	httpkit.JSON(w, r, status)
}

// Organization and Team Handlers.

func (s *Service) listOrganizationsHandler(w http.ResponseWriter, r *http.Request) {
	organizations, err := s.storage.ListOrganizations(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("list organizations: %w", err)))

		return
	}

	// The caller's own organization is reported separately so a client can tell
	// "the organization I administer" from "organizations that exist".
	var userOrg string

	if user, ok := middleware.GetUserFromContext(r.Context()); ok {
		orgID, orgErr := s.storage.GetUserOrgID(r.Context(), user.UserID)
		if orgErr != nil {
			httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("resolve caller organization: %w", orgErr)))

			return
		}

		userOrg = orgID
	}

	// With multi-tenancy off, every account shares one implicit organization
	// and listing the others would suggest a boundary the server does not
	// enforce.
	if s.cfg.MultiTenancyEnable && userOrg != "" {
		scoped := make([]Organization, 0, 1)

		for _, organization := range organizations {
			if organization.OrgID == userOrg {
				scoped = append(scoped, organization)
			}
		}

		organizations = scoped
	}

	type response struct {
		Organizations  []Organization `json:"organizations"`
		UserOrg        string         `json:"user_org"`
		MultiTenancy   bool           `json:"multi_tenancy_enabled"`
		DefaultOrgCode string         `json:"default_org_code,omitempty"`
	}

	httpkit.JSON(w, r, response{
		Organizations:  organizations,
		UserOrg:        userOrg,
		MultiTenancy:   s.cfg.MultiTenancyEnable,
		DefaultOrgCode: s.cfg.DefaultOrganization,
	})
}

func (s *Service) listTeamsHandler(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if orgID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: organization ID is required", errkit.ErrInvalidArgument))

		return
	}

	if s.cfg.MultiTenancyEnable {
		scope, err := s.callerOrg(r)
		if err != nil {
			httpkit.ErrorHTTP(w, r, err)

			return
		}

		if orgID != scope {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: organization not found", errkit.ErrNotFound))

			return
		}
	}

	teams, err := s.storage.GetTeamsByOrg(r.Context(), orgID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get teams: %w", err)))

		return
	}

	httpkit.JSON(w, r, teams)
}

// User Team Management Handlers.

func (s *Service) getUserTeamsHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user ID is required", errkit.ErrInvalidArgument))

		return
	}

	teams, err := s.storage.GetUserTeams(r.Context(), userID)
	if err != nil {
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("get user teams: %w", err)))

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
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("assign user to team: %w", err)))

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
		httpkit.ErrorHTTP(w, r, pqerr.AsTransport(fmt.Errorf("remove user from team: %w", err)))

		return
	}

	httpkit.Status(w, r, http.StatusNoContent)
}
