package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/plainq/internal/server/service/oauth/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func (s *Storage) GetProviderByID(ctx context.Context, providerID string) (*oauth.Provider, error) {
	row, err := s.queries.GetOAuthProviderByID(ctx, providerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("oauth provider not found: %w", pqerr.ErrNotFound)
		}

		return nil, fmt.Errorf("get oauth provider by id: %w", err)
	}

	return rowToProvider(row)
}

func (s *Storage) ListOrganizations(ctx context.Context) ([]oauth.Organization, error) {
	rows, err := s.queries.ListOrganizations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}

	out := make([]oauth.Organization, 0, len(rows))
	for _, row := range rows {
		out = append(out, *rowToOrganization(row))
	}

	return out, nil
}

func (s *Storage) GetUserOrgID(ctx context.Context, userID string) (string, error) {
	orgID, err := s.queries.GetUserOrgID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("user not found: %w", pqerr.ErrNotFound)
		}

		return "", fmt.Errorf("get user org id: %w", err)
	}

	return orgID, nil
}

func (s *Storage) GetUserSyncStatus(ctx context.Context, userID string) (*oauth.UserSyncStatus, error) {
	row, err := s.queries.GetUserSyncStatus(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", pqerr.ErrNotFound)
		}

		return nil, fmt.Errorf("get user sync status: %w", err)
	}

	status := oauth.UserSyncStatus{
		UserID:   userID,
		IsSynced: row.IsOauthUser,
		Provider: row.ProviderName,
	}

	if row.LastSyncAt.Valid {
		syncedAt := row.LastSyncAt.Time
		status.LastSyncAt = &syncedAt
	}

	return &status, nil
}

func (s *Storage) ListProviderSyncStats(
	ctx context.Context, query oauth.SyncStatsQuery,
) ([]oauth.ProviderSyncStat, error) {
	rows, err := s.queries.ListProviderSyncStats(ctx, sqlcgen.ListProviderSyncStatsParams{
		ScopeOrg: query.ScopeOrg,
		OrgID:    query.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("list provider sync stats: %w", err)
	}

	out := make([]oauth.ProviderSyncStat, 0, len(rows))

	for _, row := range rows {
		stat := oauth.ProviderSyncStat{
			ProviderName: row.ProviderName,
			UserCount:    row.UserCount,
		}

		if row.LastSyncAt.Valid {
			syncedAt := row.LastSyncAt.Time
			stat.LastSyncAt = &syncedAt
		}

		out = append(out, stat)
	}

	return out, nil
}
