package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/account/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func (s *Storage) GetAccountOrgID(ctx context.Context, userID string) (string, error) {
	orgID, err := s.queries.GetAccountOrgID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("account not found: %w", pqerr.ErrNotFound)
		}

		return "", fmt.Errorf("get account org id: %w", err)
	}

	return orgID, nil
}

// ListDirectory reads one page of accounts plus the role and team rows that
// belong to it.
//
// One row over the page size is asked for so "is there another page" is
// answered by the database rather than guessed from a full page. Roles and
// teams are then fetched for exactly the accounts on the page: three queries
// regardless of page size, instead of two per account.
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
			OrgID:         row.OrgID,
			OrgCode:       row.OrgCode.String,
			OrgName:       row.OrgName.String,
			OAuthProvider: row.OauthProvider.String,
			IsOAuthUser:   row.IsOauthUser,
			CreatedAt:     row.CreatedAt,
			UpdatedAt:     row.UpdatedAt,
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
