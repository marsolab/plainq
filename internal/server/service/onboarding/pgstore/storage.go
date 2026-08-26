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
	"github.com/marsolab/plainq/internal/server/security"
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

// Bootstrap serializes the no-admin predicate with every first-admin side
// effect. PostgreSQL's Serializable isolation makes concurrent winners
// conflict at commit rather than allowing two administrators.
func (s *Storage) Bootstrap(ctx context.Context, record onboarding.BootstrapRecord) (sErr error) {
	authVersion, err := security.AuthVersionInt64(record.Admin.AuthVersion)
	if err != nil {
		return fmt.Errorf("validate admin authentication version: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin bootstrap transaction: %w", err)
	}

	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	if err := writeBootstrap(ctx, s.queries.WithTx(tx), record, authVersion); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bootstrap transaction: %w", err)
	}

	return nil
}

func writeBootstrap(
	ctx context.Context,
	q *sqlcgen.Queries,
	record onboarding.BootstrapRecord,
	authVersion int64,
) error {
	count, err := q.CountAdminUsers(ctx)
	if err != nil {
		return fmt.Errorf("count admin users in bootstrap transaction: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("%w: admin users already exist, onboarding not allowed", pqerr.ErrAlreadyExists)
	}

	admin := record.Admin

	createdAt := toTimestamptz(admin.CreatedAt)
	if err := q.CreateUser(ctx, sqlcgen.CreateUserParams{
		UserID: admin.UserID, Email: admin.Email, Password: admin.Password,
		Verified: admin.Verified, CreatedAt: createdAt, UpdatedAt: createdAt,
		OrgID: admin.TenantID, AuthVersion: authVersion, Status: admin.Status,
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
		UserID: admin.UserID, RoleID: adminRoleID, CreatedAt: createdAt,
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
		MetadataJson: audit.MetadataJSON, CreatedAtNs: audit.CreatedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("persist bootstrap security audit: %w", err)
	}

	return nil
}

func toTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
