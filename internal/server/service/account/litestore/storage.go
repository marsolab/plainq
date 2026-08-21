package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/account/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements account.Storage.
var _ account.Storage = (*Storage)(nil)

// Storage is the SQLite-backed implementation of account.Storage.
// It delegates all queries to sqlc-generated code.
type Storage struct {
	db      pqlite.DB
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// NewStorage creates a new SQLite-backed account storage.
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

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the logger for the storage.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Storage) { s.logger = logger }
}

func (s *Storage) CreateAccount(ctx context.Context, a account.Account) error {
	authVersion, err := security.AuthVersionInt64(a.AuthVersion)
	if err != nil {
		return fmt.Errorf("validate account authentication version: %w", err)
	}

	err = pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return errors.New("account write transaction is not database/sql")
		}

		q := s.queries.WithTx(sqlTx)
		if err := q.CreateAccount(ctx, sqlcgen.CreateAccountParams{
			UserID: a.ID, Email: a.Email, Password: a.Password, Verified: a.Verified,
			CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, OrgID: a.TenantID,
			AuthVersion: authVersion, Status: a.Status,
		}); err != nil {
			return fmt.Errorf("insert account: %w", err)
		}

		if err := q.UpsertHumanSecurityPrincipal(ctx, sqlcgen.UpsertHumanSecurityPrincipalParams{
			UpdatedAtNs: a.UpdatedAt.UnixNano(), UserID: a.ID,
		}); err != nil {
			return fmt.Errorf("project human principal: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}

	return nil
}

func (s *Storage) GetAccountByID(ctx context.Context, id string) (*account.Account, error) {
	row, err := s.queries.GetAccountByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get account by id: %w", err)
	}

	authVersion, err := security.AuthVersionUint64(row.AuthVersion)
	if err != nil {
		return nil, fmt.Errorf("decode account authentication version: %w", err)
	}

	return &account.Account{
		ID:          row.UserID,
		Email:       row.Email,
		Password:    row.Password,
		Verified:    row.Verified,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
		TenantID:    row.OrgID,
		AuthVersion: authVersion,
		Status:      row.Status,
	}, nil
}

func (s *Storage) GetAccountByEmail(ctx context.Context, email string) (*account.Account, error) {
	row, err := s.queries.GetAccountByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("get account by email: %w", err)
	}

	authVersion, err := security.AuthVersionUint64(row.AuthVersion)
	if err != nil {
		return nil, fmt.Errorf("decode account authentication version: %w", err)
	}

	return &account.Account{
		ID:          row.UserID,
		Email:       row.Email,
		Password:    row.Password,
		Verified:    row.Verified,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
		TenantID:    row.OrgID,
		AuthVersion: authVersion,
		Status:      row.Status,
	}, nil
}

func (s *Storage) SetAccountVerified(ctx context.Context, email string, verified bool) error {
	if _, err := s.queries.SetAccountVerified(ctx, sqlcgen.SetAccountVerifiedParams{
		Verified: verified,
		Email:    email,
	}); err != nil {
		return fmt.Errorf("set account verified: %w", err)
	}

	return nil
}

func (s *Storage) SetAccountPassword(ctx context.Context, id, password string) error {
	if _, err := s.queries.SetAccountPassword(ctx, sqlcgen.SetAccountPasswordParams{
		Password: password,
		UserID:   id,
	}); err != nil {
		return fmt.Errorf("set account password: %w", err)
	}

	return nil
}

func (s *Storage) DeleteAccount(ctx context.Context, id string) error {
	if _, err := s.queries.DeleteAccount(ctx, id); err != nil {
		return fmt.Errorf("delete account: %w", err)
	}

	return nil
}

func (s *Storage) CreateRefreshToken(ctx context.Context, t account.RefreshToken) error {
	if err := s.queries.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		ID: t.ID, Aid: t.AID, TokenHash: append([]byte(nil), t.TokenHash...),
		CreatedAtNs: t.CreatedAt.UnixNano(), ExpiresAtNs: t.ExpiresAt.UnixNano(),
		LastUsedAtNs: t.LastUsedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	return nil
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, tokenHash []byte) error {
	rows, err := s.queries.DeleteRefreshToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}

	if rows == 0 {
		return account.ErrRefreshTokenNotFound
	}

	return nil
}

func (s *Storage) DeleteRefreshTokenByTokenID(ctx context.Context, tid string) error {
	if err := s.queries.DeleteRefreshTokenByTokenID(ctx, tid); err != nil {
		return fmt.Errorf("delete refresh token by id: %w", err)
	}

	return nil
}

func (s *Storage) PurgeRefreshTokens(ctx context.Context, aid string) error {
	if err := s.queries.PurgeRefreshTokens(ctx, aid); err != nil {
		return fmt.Errorf("purge refresh tokens: %w", err)
	}

	return nil
}

func (s *Storage) DenyAccessToken(ctx context.Context, token account.DeniedToken) error {
	if err := s.queries.DenyAccessToken(ctx, sqlcgen.DenyAccessTokenParams{
		TokenID: token.TokenID, Aid: token.AID, ExpiresAtNs: token.ExpiresAt.UnixNano(),
		CreatedAtNs: token.CreatedAt.UnixNano(), Reason: token.Reason,
	}); err != nil {
		return fmt.Errorf("deny access token: %w", err)
	}

	return nil
}

func (s *Storage) RevokeSession(ctx context.Context, token account.DeniedToken) error {
	err := pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return errors.New("session revocation transaction is not database/sql")
		}

		q := s.queries.WithTx(sqlTx)
		if err := q.DenyAccessToken(ctx, sqlcgen.DenyAccessTokenParams{
			TokenID: token.TokenID, Aid: token.AID, ExpiresAtNs: token.ExpiresAt.UnixNano(),
			CreatedAtNs: token.CreatedAt.UnixNano(), Reason: token.Reason,
		}); err != nil {
			return fmt.Errorf("deny access token: %w", err)
		}

		if err := q.DeleteRefreshTokenByTokenID(ctx, token.TokenID); err != nil {
			return fmt.Errorf("delete refresh token by id: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

func (s *Storage) IsAccessTokenDenied(ctx context.Context, tokenID string) (bool, error) {
	count, err := s.queries.IsAccessTokenDenied(ctx, sqlcgen.IsAccessTokenDeniedParams{
		TokenID:     tokenID,
		ExpiresAtNs: time.Now().UnixNano(),
	})
	if err != nil {
		return false, fmt.Errorf("is access token denied: %w", err)
	}

	return count > 0, nil
}

func (s *Storage) GetAccountSecurity(ctx context.Context, userID string) (account.AccountSecurity, error) {
	row, err := s.queries.GetAccountSecurity(ctx, userID)
	if err != nil {
		return account.AccountSecurity{}, fmt.Errorf("get account security: %w", err)
	}

	authVersion, err := security.AuthVersionUint64(row.AuthVersion)
	if err != nil {
		return account.AccountSecurity{}, fmt.Errorf("decode account authentication version: %w", err)
	}

	return account.AccountSecurity{
		TenantID: row.OrgID, Status: row.Status, AuthVersion: authVersion,
	}, nil
}

//nolint:gocritic // Interface compatibility requires the tenant, status, version tuple.
func (s *Storage) ResolveHumanSecurity(
	ctx context.Context,
	userID string,
) (string, string, uint64, error) {
	accountSecurity, err := s.GetAccountSecurity(ctx, userID)
	if err != nil {
		return "", "", 0, err
	}

	return accountSecurity.TenantID, accountSecurity.Status, accountSecurity.AuthVersion, nil
}

func (s *Storage) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	roles, err := s.queries.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}

	return roles, nil
}
