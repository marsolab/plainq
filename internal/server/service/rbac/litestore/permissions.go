package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/server/service/rbac/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/plainq/internal/shared/pqlite"
)

func (s *Storage) CountUsersWithRole(ctx context.Context, roleID string) (int64, error) {
	count, err := s.queries.CountUsersWithRole(ctx, roleID)
	if err != nil {
		return 0, fmt.Errorf("count users with role: %w", err)
	}

	return count, nil
}

func (s *Storage) CountUsersPerRole(ctx context.Context) (map[string]int64, error) {
	rows, err := s.queries.CountUsersPerRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("count users per role: %w", err)
	}

	counts := make(map[string]int64, len(rows))
	for _, row := range rows {
		counts[row.RoleID] = row.UserCount
	}

	return counts, nil
}

// ReplaceRoleQueuePermissions rewrites a role's grants in one transaction:
// every existing row for the role is removed and the given set inserted, so a
// half-applied matrix is never observable and never left behind by a failure.
func (s *Storage) ReplaceRoleQueuePermissions(
	ctx context.Context, roleID string, permissions []rbac.QueuePermission,
) (sErr error) {
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

	if _, err := q.DeleteRoleQueuePermissions(ctx, roleID); err != nil {
		return fmt.Errorf("delete role queue permissions: %w", err)
	}

	now := time.Now()

	for _, permission := range permissions {
		if err := q.CreateQueuePermission(ctx, sqlcgen.CreateQueuePermissionParams{
			QueueID:    permission.QueueID,
			RoleID:     roleID,
			CanSend:    permission.CanSend,
			CanReceive: permission.CanReceive,
			CanPurge:   permission.CanPurge,
			CanDelete:  permission.CanDelete,
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			return classifyWrite(fmt.Errorf("create queue permission for queue %s: %w", permission.QueueID, err))
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// RemoveRoleFromUserUnlessLastHolder makes the "another holder must remain"
// condition part of the delete, so two concurrent removals cannot both observe
// the other account and both succeed.
func (s *Storage) RemoveRoleFromUserUnlessLastHolder(ctx context.Context, userID, roleID string) error {
	err := pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return errors.New("RBAC write transaction is not database/sql")
		}

		q := s.queries.WithTx(sqlTx)

		rows, err := q.RemoveRoleFromUserUnlessLastHolder(ctx, sqlcgen.RemoveRoleFromUserUnlessLastHolderParams{
			UserID: userID, RoleID: roleID, RoleID_2: roleID,
		})
		if err != nil {
			return fmt.Errorf("conditional role removal: %w", err)
		}

		if rows > 0 {
			return bumpAndProjectHuman(ctx, q, userID, time.Now())
		}

		held, err := q.UserHasRole(ctx, sqlcgen.UserHasRoleParams{UserID: userID, RoleID: roleID})
		if err != nil {
			return fmt.Errorf("check refused role removal: %w", err)
		}

		if held {
			return rbac.ErrLastRoleHolder
		}

		return fmt.Errorf("user role not found: %w", pqerr.ErrNotFound)
	})
	if err != nil {
		if errors.Is(err, rbac.ErrLastRoleHolder) {
			return rbac.ErrLastRoleHolder
		}

		return fmt.Errorf("remove role from user: %w", err)
	}

	return nil
}
