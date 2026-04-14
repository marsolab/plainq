package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/server/service/onboarding/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements onboarding.Storage.
var _ onboarding.Storage = (*Storage)(nil)

// Storage is the SQLite-backed implementation of onboarding.Storage.
type Storage struct {
	db      *litekit.Conn
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the storage's logger.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

// NewStorage creates a new SQLite-backed onboarding storage.
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
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("admin role not found: %w", pqerr.ErrNotFound)
		}
		return "", fmt.Errorf("get admin role id: %w", err)
	}

	return id, nil
}

// CreateInitialAdmin creates the first admin user and assigns the admin role
// inside a single transaction. A double-check ensures no admin exists yet —
// this is a write-contention barrier, not true uniqueness (the users/roles
// tables are not unique-constrained on role_name=admin).
//
//nolint:cyclop // Complex transaction with multiple validation steps.
func (s *Storage) CreateInitialAdmin(ctx context.Context, admin onboarding.InitialAdmin) (sErr error) {
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

	count, err := q.CountAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("count admin users in tx: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("%w: admin users already exist, onboarding not allowed", pqerr.ErrAlreadyExists)
	}

	now := time.Now()

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
		if errors.Is(err, sql.ErrNoRows) {
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}
