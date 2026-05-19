package litestore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/account/litestore/sqlcgen"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/logkit"
)

// Compile-time check that Storage implements account.Storage.
var _ account.Storage = (*Storage)(nil)

// Storage is the SQLite-backed implementation of account.Storage.
// It delegates all queries to sqlc-generated code.
type Storage struct {
	db      *litekit.Conn
	queries *sqlcgen.Queries
	logger  *slog.Logger
}

// NewStorage creates a new SQLite-backed account storage.
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

// Option configures the Storage.
type Option func(*Storage)

// WithLogger sets the logger for the storage.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Storage) { s.logger = logger }
}

func (s *Storage) CreateAccount(ctx context.Context, a account.Account) error {
	if err := s.queries.CreateAccount(ctx, sqlcgen.CreateAccountParams{
		UserID:    a.ID,
		Email:     a.Email,
		Password:  a.Password,
		Verified:  a.Verified,
		CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt,
	}); err != nil {
		return fmt.Errorf("create account: %w", err)
	}

	return nil
}

func (s *Storage) GetAccountByID(ctx context.Context, id string) (*account.Account, error) {
	row, err := s.queries.GetAccountByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get account by id: %w", err)
	}

	return &account.Account{
		ID:        row.UserID,
		Email:     row.Email,
		Password:  row.Password,
		Verified:  row.Verified,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}

func (s *Storage) GetAccountByEmail(ctx context.Context, email string) (*account.Account, error) {
	row, err := s.queries.GetAccountByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("get account by email: %w", err)
	}

	return &account.Account{
		ID:        row.UserID,
		Email:     row.Email,
		Password:  row.Password,
		Verified:  row.Verified,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
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
		ID:        t.ID,
		Aid:       t.AID,
		Token:     t.Token,
		CreatedAt: t.CreatedAt,
		ExpiresAt: t.ExpiresAt,
	}); err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	return nil
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, token string) error {
	if err := s.queries.DeleteRefreshToken(ctx, token); err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
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

func (s *Storage) DenyAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	if err := s.queries.DenyAccessToken(ctx, sqlcgen.DenyAccessTokenParams{
		Token:       token,
		DeniedUntil: time.Now().Add(ttl).Unix(),
	}); err != nil {
		return fmt.Errorf("deny access token: %w", err)
	}

	return nil
}

func (s *Storage) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	roles, err := s.queries.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}

	return roles, nil
}
