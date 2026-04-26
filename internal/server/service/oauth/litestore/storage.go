package litestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/plainq/internal/server/service/oauth/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/idkit"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements oauth.Storage.
var _ oauth.Storage = (*Storage)(nil)

// Storage is the SQLite-backed implementation of oauth.Storage.
type Storage struct {
	db      *litekit.Conn
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the storage's logger.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

// NewStorage creates a new SQLite-backed oauth storage.
func NewStorage(db *litekit.Conn, logger *slog.Logger, opts ...Option) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	s := &Storage{
		db:      db,
		queries: sqlcgen.New(db),
		logger:  logger,
	}

	if s.logger == nil {
		s.logger = logkit.NewNop()
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

func (s *Storage) CreateProvider(ctx context.Context, p oauth.Provider) error {
	configJSON, err := json.Marshal(p.Config)
	if err != nil {
		return fmt.Errorf("marshal provider config: %w", err)
	}

	now := time.Now()

	return s.queries.CreateOAuthProvider(ctx, sqlcgen.CreateOAuthProviderParams{
		ProviderID:   p.ProviderID,
		ProviderName: p.ProviderName,
		OrgID:        toNullString(p.OrgID),
		ConfigJson:   string(configJSON),
		IsActive:     p.IsActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
}

func (s *Storage) GetProvider(ctx context.Context, providerName, orgID string) (*oauth.Provider, error) {
	row, err := s.queries.GetOAuthProviderByName(ctx, sqlcgen.GetOAuthProviderByNameParams{
		ProviderName: providerName,
		OrgID:        toNullString(orgID),
		Column3:      orgID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("oauth provider not found: %w", pqerr.ErrNotFound)
		}
		return nil, fmt.Errorf("get oauth provider: %w", err)
	}

	return rowToProvider(row)
}

func (s *Storage) UpdateProvider(ctx context.Context, p oauth.Provider) error {
	configJSON, err := json.Marshal(p.Config)
	if err != nil {
		return fmt.Errorf("marshal provider config: %w", err)
	}

	rows, err := s.queries.UpdateOAuthProvider(ctx, sqlcgen.UpdateOAuthProviderParams{
		ConfigJson: string(configJSON),
		IsActive:   p.IsActive,
		UpdatedAt:  time.Now(),
		ProviderID: p.ProviderID,
	})
	if err != nil {
		return fmt.Errorf("update oauth provider: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("oauth provider not found: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) DeleteProvider(ctx context.Context, providerID string) error {
	rows, err := s.queries.DeleteOAuthProvider(ctx, providerID)
	if err != nil {
		return fmt.Errorf("delete oauth provider: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("oauth provider not found: %w", pqerr.ErrNotFound)
	}

	return nil
}

func (s *Storage) ListProviders(ctx context.Context, orgID string) ([]oauth.Provider, error) {
	rows, err := s.queries.ListOAuthProvidersByOrg(ctx, toNullString(orgID))
	if err != nil {
		return nil, fmt.Errorf("list oauth providers: %w", err)
	}

	out := make([]oauth.Provider, 0, len(rows))
	for _, r := range rows {
		p, err := rowToProvider(r)
		if err != nil {
			return nil, err
		}

		out = append(out, *p)
	}

	return out, nil
}

// SyncOAuthUser upserts an OAuth-authenticated user by (oauth_provider,
// oauth_sub) in a serializable transaction so the check-then-act is
// race-free.
func (s *Storage) SyncOAuthUser(ctx context.Context, user oauth.OAuthUser, providerName, orgID string) (sErr error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	q := s.queries.WithTx(tx)

	userID, lookupErr := q.GetUserIDByOAuthSub(ctx, sqlcgen.GetUserIDByOAuthSubParams{
		OauthProvider: toNullString(providerName),
		OauthSub:      toNullString(user.Subject),
	})

	now := time.Now()

	switch {
	case errors.Is(lookupErr, sql.ErrNoRows):
		if err := q.InsertOAuthUser(ctx, sqlcgen.InsertOAuthUserParams{
			UserID:        idkit.ULID(),
			Email:         user.Email,
			OrgID:         toNullString(orgID),
			OauthProvider: toNullString(providerName),
			OauthSub:      toNullString(user.Subject),
			LastSyncAt:    sql.NullTime{Time: now, Valid: true},
			CreatedAt:     now,
			UpdatedAt:     now,
		}); err != nil {
			return fmt.Errorf("insert oauth user: %w", err)
		}

	case lookupErr != nil:
		return fmt.Errorf("check existing oauth user: %w", lookupErr)

	default:
		if err := q.UpdateOAuthUser(ctx, sqlcgen.UpdateOAuthUserParams{
			Email:      user.Email,
			OrgID:      toNullString(orgID),
			LastSyncAt: sql.NullTime{Time: now, Valid: true},
			UpdatedAt:  now,
			UserID:     userID,
		}); err != nil {
			return fmt.Errorf("update oauth user: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (s *Storage) GetUserByOAuthSub(ctx context.Context, providerName, subject string) (*oauth.SyncedUser, error) {
	row, err := s.queries.GetUserByOAuthSub(ctx, sqlcgen.GetUserByOAuthSubParams{
		OauthProvider: toNullString(providerName),
		OauthSub:      toNullString(subject),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("oauth user not found: %w", pqerr.ErrNotFound)
		}
		return nil, fmt.Errorf("get user by oauth sub: %w", err)
	}

	return &oauth.SyncedUser{
		UserID:      row.UserID,
		Email:       row.Email,
		OrgID:       row.OrgID.String,
		Provider:    row.OauthProvider.String,
		Subject:     row.OauthSub.String,
		IsOAuthUser: row.IsOauthUser,
		LastSyncAt:  row.LastSyncAt.Time,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

func (s *Storage) UpdateUserLastSync(ctx context.Context, userID string) error {
	now := time.Now()
	return s.queries.UpdateUserLastSync(ctx, sqlcgen.UpdateUserLastSyncParams{
		LastSyncAt: sql.NullTime{Time: now, Valid: true},
		UpdatedAt:  now,
		UserID:     userID,
	})
}

func (s *Storage) GetOrganizationByCode(ctx context.Context, orgCode string) (*oauth.Organization, error) {
	row, err := s.queries.GetOrganizationByCode(ctx, orgCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("organization not found: %w", pqerr.ErrNotFound)
		}
		return nil, fmt.Errorf("get organization by code: %w", err)
	}

	return rowToOrganization(row), nil
}

func (s *Storage) GetOrganizationByDomain(ctx context.Context, domain string) (*oauth.Organization, error) {
	row, err := s.queries.GetOrganizationByDomain(ctx, toNullString(domain))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("organization not found: %w", pqerr.ErrNotFound)
		}
		return nil, fmt.Errorf("get organization by domain: %w", err)
	}

	return rowToOrganization(row), nil
}

func (s *Storage) GetTeamsByOrg(ctx context.Context, orgID string) ([]oauth.Team, error) {
	rows, err := s.queries.ListTeamsByOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list teams by org: %w", err)
	}

	out := make([]oauth.Team, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToTeam(r))
	}

	return out, nil
}

func (s *Storage) GetTeamByCode(ctx context.Context, orgID, teamCode string) (*oauth.Team, error) {
	row, err := s.queries.GetTeamByCode(ctx, sqlcgen.GetTeamByCodeParams{
		OrgID:    orgID,
		TeamCode: teamCode,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("team not found: %w", pqerr.ErrNotFound)
		}
		return nil, fmt.Errorf("get team by code: %w", err)
	}

	t := rowToTeam(row)
	return &t, nil
}

func (s *Storage) AssignUserToTeam(ctx context.Context, userID, teamID string) error {
	return s.queries.AssignUserToTeam(ctx, sqlcgen.AssignUserToTeamParams{
		UserID:    userID,
		TeamID:    teamID,
		CreatedAt: time.Now(),
	})
}

func (s *Storage) RemoveUserFromTeam(ctx context.Context, userID, teamID string) error {
	return s.queries.RemoveUserFromTeam(ctx, sqlcgen.RemoveUserFromTeamParams{
		UserID: userID,
		TeamID: teamID,
	})
}

func (s *Storage) GetUserTeams(ctx context.Context, userID string) ([]oauth.Team, error) {
	rows, err := s.queries.ListUserTeams(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user teams: %w", err)
	}

	out := make([]oauth.Team, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToTeam(r))
	}

	return out, nil
}

// toNullString converts a Go string to sql.NullString. Empty strings become
// NULL — matches the existing convention where empty org_id means "no
// organization" and empty oauth_sub means "not OAuth-synced".
func toNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}

	return sql.NullString{String: s, Valid: true}
}

func rowToProvider(row sqlcgen.OauthProvider) (*oauth.Provider, error) {
	p := &oauth.Provider{
		ProviderID:   row.ProviderID,
		ProviderName: row.ProviderName,
		OrgID:        row.OrgID.String,
		IsActive:     row.IsActive,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}

	if row.ConfigJson != "" {
		if err := json.Unmarshal([]byte(row.ConfigJson), &p.Config); err != nil {
			return nil, fmt.Errorf("unmarshal provider config: %w", err)
		}
	}

	return p, nil
}

func rowToOrganization(row sqlcgen.Organization) *oauth.Organization {
	return &oauth.Organization{
		OrgID:     row.OrgID,
		OrgCode:   row.OrgCode,
		OrgName:   row.OrgName,
		OrgDomain: row.OrgDomain.String,
		IsActive:  row.IsActive,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

func rowToTeam(row sqlcgen.Team) oauth.Team {
	return oauth.Team{
		TeamID:      row.TeamID,
		OrgID:       row.OrgID,
		TeamName:    row.TeamName,
		TeamCode:    row.TeamCode,
		Description: row.Description.String,
		IsActive:    row.IsActive,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}
