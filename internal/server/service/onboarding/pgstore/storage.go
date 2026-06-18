package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/server/service/onboarding/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements onboarding.Storage.
var _ onboarding.Storage = (*Storage)(nil)

// Storage is the PostgreSQL-backed implementation of onboarding.Storage.
type Storage struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the storage's logger.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

// NewStorage creates a new PostgreSQL-backed onboarding storage.
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

func (s *Storage) HasAdminUsers(ctx context.Context) (bool, error) {
	count, err := s.queries.CountAdminUsers(ctx)
	if err != nil {
		return false, fmt.Errorf("count admin users: %w", err)
	}

	return count > 0, nil
}

func (s *Storage) GetAdminRoleID(ctx context.Context) (string, error) {
	id, err := s.queries.GetAdminRoleID(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("admin role not found: %w", pqerr.ErrNotFound)
		}

		return "", fmt.Errorf("get admin role id: %w", err)
	}

	return id, nil
}

// CreateInitialAdmin creates the first admin user and assigns admin role in
// a serializable transaction with a pre-flight count check.
//
//nolint:cyclop // Complex transaction with multiple validation steps.
func (s *Storage) CreateInitialAdmin(ctx context.Context, admin onboarding.InitialAdmin) (sErr error) {
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

	count, err := q.CountAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("count admin users in tx: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("%w: admin users already exist, onboarding not allowed", pqerr.ErrAlreadyExists)
	}

	now := toTimestamptz(time.Now())

	if err := q.CreateUser(ctx, sqlcgen.CreateUserParams{
		UserID:    admin.UserID,
		Email:     admin.Email,
		Password:  admin.Password,
		Verified:  admin.Verified,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	adminRoleID, err := q.GetAdminRoleID(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("admin role not found: %w", pqerr.ErrNotFound)
		}

		return fmt.Errorf("get admin role id: %w", err)
	}

	if err := q.AssignUserRole(ctx, sqlcgen.AssignUserRoleParams{
		UserID:    admin.UserID,
		RoleID:    adminRoleID,
		CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("assign admin role: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func toTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
