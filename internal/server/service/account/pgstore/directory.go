package pgstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/account/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func (s *Storage) GetAccountOrgID(ctx context.Context, userID string) (string, error) {
	orgID, err := s.queries.GetAccountOrgID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("account not found: %w", pqerr.ErrNotFound)
		}

		return "", fmt.Errorf("get account org id: %w", err)
	}

	return orgID, nil
}

// ListDirectory reads one page of accounts plus the role and team rows that
// belong to it. See the SQLite implementation for why the page is over-read by
// one row and why roles and teams are fetched per page rather than per account.
func (s *Storage) ListDirectory(ctx context.Context, query account.DirectoryQuery) (*account.DirectoryPage, error) {
	limit := account.ClampDirectoryLimit(query.Limit)

	rows, err := s.queries.ListDirectoryAccounts(ctx, sqlcgen.ListDirectoryAccountsParams{
		Search:    query.Search,
		ScopeOrg:  query.ScopeOrg,
		OrgID:     query.OrgID,
		Cursor:    query.Cursor,
		PageLimit: int64(limit) + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("list directory accounts: %w", err)
	}

	total, err := s.queries.CountDirectoryAccounts(ctx, sqlcgen.CountDirectoryAccountsParams{
		Search:   query.Search,
		ScopeOrg: query.ScopeOrg,
		OrgID:    query.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("count directory accounts: %w", err)
	}

	entries := make([]account.DirectoryEntry, 0, len(rows))
	userIDs := make([]string, 0, len(rows))

	for _, row := range rows {
		entry := account.DirectoryEntry{
			UserID:        row.UserID,
			Email:         row.Email,
			Verified:      row.Verified,
			OrgID:         row.OrgID.String,
			OrgCode:       row.OrgCode.String,
			OrgName:       row.OrgName.String,
			OAuthProvider: row.OauthProvider.String,
			IsOAuthUser:   row.IsOauthUser,
			CreatedAt:     row.CreatedAt.Time,
			UpdatedAt:     row.UpdatedAt.Time,
			Roles:         []account.DirectoryRole{},
			Teams:         []account.DirectoryTeam{},
		}

		if row.LastSyncAt.Valid {
			syncedAt := row.LastSyncAt.Time
			entry.LastSyncAt = &syncedAt
		}

		entries = append(entries, entry)
		userIDs = append(userIDs, row.UserID)
	}

	if len(userIDs) > 0 {
		if err := s.attachRoles(ctx, entries, userIDs); err != nil {
			return nil, err
		}

		if err := s.attachTeams(ctx, entries, userIDs); err != nil {
			return nil, err
		}
	}

	return account.BuildDirectoryPage(entries, limit, total), nil
}

func (s *Storage) attachRoles(ctx context.Context, entries []account.DirectoryEntry, userIDs []string) error {
	rows, err := s.queries.ListRolesForAccounts(ctx, userIDs)
	if err != nil {
		return fmt.Errorf("list roles for accounts: %w", err)
	}

	index := indexByUserID(entries)

	for _, row := range rows {
		at, ok := index[row.UserID]
		if !ok {
			continue
		}

		entries[at].Roles = append(entries[at].Roles, account.DirectoryRole{
			RoleID:   row.RoleID,
			RoleName: row.RoleName,
		})
	}

	return nil
}

func (s *Storage) attachTeams(ctx context.Context, entries []account.DirectoryEntry, userIDs []string) error {
	rows, err := s.queries.ListTeamsForAccounts(ctx, userIDs)
	if err != nil {
		return fmt.Errorf("list teams for accounts: %w", err)
	}

	index := indexByUserID(entries)

	for _, row := range rows {
		at, ok := index[row.UserID]
		if !ok {
			continue
		}

		entries[at].Teams = append(entries[at].Teams, account.DirectoryTeam{
			TeamID:   row.TeamID,
			OrgID:    row.OrgID,
			TeamName: row.TeamName,
			TeamCode: row.TeamCode,
		})
	}

	return nil
}

func indexByUserID(entries []account.DirectoryEntry) map[string]int {
	index := make(map[string]int, len(entries))
	for at, entry := range entries {
		index[entry.UserID] = at
	}

	return index
}
