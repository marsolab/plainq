package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/server/service/rbac/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

// PostgreSQL SQLSTATE codes for the two constraint failures a caller can cause.
const (
	pgForeignKeyViolation = "23503"
	pgUniqueViolation     = "23505"
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

	if _, err := q.DeleteRoleQueuePermissions(ctx, roleID); err != nil {
		return fmt.Errorf("delete role queue permissions: %w", err)
	}

	now := toTimestamptz(time.Now())

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

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// classifyWrite maps a constraint failure onto a domain error so the transport
// can answer 400 or 409 instead of 500. A grant naming a queue that does not
// exist is the caller's mistake, not the server's.
func classifyWrite(err error) error {
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}

	switch pgErr.Code {
	case pgForeignKeyViolation:
		return fmt.Errorf("%w: %w", pqerr.ErrInvalidInput, err)

	case pgUniqueViolation:
		return fmt.Errorf("%w: %w", pqerr.ErrAlreadyExists, err)

	default:
		return err
	}
}
