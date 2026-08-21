package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/server/service/onboarding/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements onboarding.Storage.
var _ onboarding.Storage = (*Storage)(nil)

// Storage is the SQLite-backed implementation of onboarding.Storage.
type Storage struct {
	db      pqlite.DB
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the storage's logger.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

// NewStorage creates a new SQLite-backed onboarding storage.
func NewStorage(db pqlite.DB, logger *slog.Logger, opts ...Option) (*Storage, error) {
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

// Bootstrap performs every first-administrator side effect on one dedicated
// writer connection. WithWriteTx retries the entire callback on SQLite/libSQL
// contention, so a remote or concurrent caller re-runs the admin check after
// the winning transaction commits instead of creating a second administrator.
func (s *Storage) Bootstrap(ctx context.Context, record onboarding.BootstrapRecord) error {
	err := pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return errors.New("bootstrap write transaction is not database/sql")
		}

		return writeBootstrap(ctx, s.queries.WithTx(sqlTx), record)
	})
	if err != nil {
		return fmt.Errorf("bootstrap initial administrator: %w", err)
	}

	return nil
}

//nolint:cyclop // Each first-admin transactional side effect has a distinct failure.
func writeBootstrap(ctx context.Context, q *sqlcgen.Queries, record onboarding.BootstrapRecord) error {
	count, err := q.CountAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("count admin users in transaction: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("%w: admin users already exist, onboarding not allowed", pqerr.ErrAlreadyExists)
	}

	admin := record.Admin

	authVersion, err := security.AuthVersionInt64(admin.AuthVersion)
	if err != nil {
		return fmt.Errorf("validate admin authentication version: %w", err)
	}

	if err := q.CreateUser(ctx, sqlcgen.CreateUserParams{
		UserID: admin.UserID, Email: admin.Email, Password: admin.Password,
		Verified: admin.Verified, CreatedAt: admin.CreatedAt, UpdatedAt: admin.CreatedAt,
		OrgID: admin.TenantID, AuthVersion: authVersion, Status: admin.Status,
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
		UserID: admin.UserID, RoleID: adminRoleID, CreatedAt: admin.CreatedAt,
	}); err != nil {
		return fmt.Errorf("assign admin role: %w", err)
	}

	if err := q.UpsertHumanSecurityPrincipal(ctx, sqlcgen.UpsertHumanSecurityPrincipalParams{
		UpdatedAtNs: admin.CreatedAt.UnixNano(), UserID: admin.UserID,
	}); err != nil {
		return fmt.Errorf("project admin security principal: %w", err)
	}

	refresh := record.RefreshToken
	if err := q.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		ID: refresh.ID, Aid: refresh.AccountID, TokenHash: refresh.TokenHash,
		CreatedAtNs: refresh.CreatedAt.UnixNano(), ExpiresAtNs: refresh.ExpiresAt.UnixNano(),
		LastUsedAtNs: refresh.LastUsedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("persist bootstrap refresh session: %w", err)
	}

	audit := record.Audit
	if err := q.CreateSecurityAuditEvent(ctx, sqlcgen.CreateSecurityAuditEventParams{
		AuditID: audit.ID, TenantID: audit.TenantID, PrincipalKind: audit.PrincipalKind,
		PrincipalID: audit.PrincipalID, Action: audit.Action, ResourceKind: audit.ResourceKind,
		ResourceID: audit.ResourceID, Outcome: audit.Outcome, RequestID: audit.RequestID,
		Reason: audit.Reason, SourceIp: audit.SourceIP, UserAgent: audit.UserAgent,
		MetadataJson: string(audit.MetadataJSON), CreatedAtNs: audit.CreatedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("persist bootstrap security audit: %w", err)
	}

	return nil
}
