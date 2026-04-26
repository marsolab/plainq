package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/plainq/internal/server/service/oauth/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements oauth.Storage.
var _ oauth.Storage = (*Storage)(nil)

// Storage is the PostgreSQL-backed implementation of oauth.Storage.
type Storage struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the storage's logger.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

// NewStorage creates a new PostgreSQL-backed oauth storage.
func NewStorage(pool *pgxpool.Pool, logger *slog.Logger, opts ...Option) (*Storage, error) {
	if pool == nil {
		return nil, errors.New("pool is nil")
	}

	s := &Storage{
		pool:    pool,
		queries: sqlcgen.New(pool),
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

	now := toTimestamptz(time.Now())

	return s.queries.CreateOAuthProvider(ctx, sqlcgen.CreateOAuthProviderParams{
		ProviderID:   p.ProviderID,
		ProviderName: p.ProviderName,
		OrgID:        toPgText(p.OrgID),
		ConfigJson:   string(configJSON),
		IsActive:     p.IsActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
}

func (s *Storage) GetProvider(ctx context.Context, providerName, orgID string) (*oauth.Provider, error) {
	row, err := s.queries.GetOAuthProviderByName(ctx, sqlcgen.GetOAuthProviderByNameParams{
		ProviderName: providerName,
		OrgID:        toPgText(orgID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
		UpdatedAt:  toTimestamptz(time.Now()),
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
	rows, err := s.queries.ListOAuthProvidersByOrg(ctx, toPgText(orgID))
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

func (s *Storage) SyncOAuthUser(ctx context.Context, user oauth.OAuthUser, providerName, orgID string) (sErr error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	q := s.queries.WithTx(tx)

	userID, lookupErr := q.GetUserIDByOAuthSub(ctx, sqlcgen.GetUserIDByOAuthSubParams{
		OauthProvider: toPgText(providerName),
		OauthSub:      toPgText(user.Subject),
	})

	now := toTimestamptz(time.Now())

	switch {
	case errors.Is(lookupErr, pgx.ErrNoRows):
		if err := q.InsertOAuthUser(ctx, sqlcgen.InsertOAuthUserParams{
			UserID:        idkit.ULID(),
			Email:         user.Email,
			OrgID:         toPgText(orgID),
			OauthProvider: toPgText(providerName),
			OauthSub:      toPgText(user.Subject),
			LastSyncAt:    now,
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
			OrgID:      toPgText(orgID),
			LastSyncAt: now,
			UpdatedAt:  now,
			UserID:     userID,
		}); err != nil {
			return fmt.Errorf("update oauth user: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (s *Storage) GetUserByOAuthSub(ctx context.Context, providerName, subject string) (*oauth.SyncedUser, error) {
	row, err := s.queries.GetUserByOAuthSub(ctx, sqlcgen.GetUserByOAuthSubParams{
		OauthProvider: toPgText(providerName),
		OauthSub:      toPgText(subject),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
		CreatedAt:   row.CreatedAt.Time,
		UpdatedAt:   row.UpdatedAt.Time,
	}, nil
}

func (s *Storage) UpdateUserLastSync(ctx context.Context, userID string) error {
	now := toTimestamptz(time.Now())
	return s.queries.UpdateUserLastSync(ctx, sqlcgen.UpdateUserLastSyncParams{
		LastSyncAt: now,
		UpdatedAt:  now,
		UserID:     userID,
	})
}

func (s *Storage) GetOrganizationByCode(ctx context.Context, orgCode string) (*oauth.Organization, error) {
	row, err := s.queries.GetOrganizationByCode(ctx, orgCode)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("organization not found: %w", pqerr.ErrNotFound)
		}
		return nil, fmt.Errorf("get organization by code: %w", err)
	}

	return rowToOrganization(row), nil
}

func (s *Storage) GetOrganizationByDomain(ctx context.Context, domain string) (*oauth.Organization, error) {
	row, err := s.queries.GetOrganizationByDomain(ctx, toPgText(domain))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
		if errors.Is(err, pgx.ErrNoRows) {
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
		CreatedAt: toTimestamptz(time.Now()),
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

func toTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func toPgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}

	return pgtype.Text{String: s, Valid: true}
}

func rowToProvider(row sqlcgen.OauthProvider) (*oauth.Provider, error) {
	p := &oauth.Provider{
		ProviderID:   row.ProviderID,
		ProviderName: row.ProviderName,
		OrgID:        row.OrgID.String,
		IsActive:     row.IsActive,
		CreatedAt:    row.CreatedAt.Time,
		UpdatedAt:    row.UpdatedAt.Time,
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
		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
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
		CreatedAt:   row.CreatedAt.Time,
		UpdatedAt:   row.UpdatedAt.Time,
	}
}
