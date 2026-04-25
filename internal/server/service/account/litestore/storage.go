package litestore

import (
	"context"
	"errors"
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
	return s.queries.CreateAccount(ctx, sqlcgen.CreateAccountParams{
		UserID:    a.ID,
		Email:     a.Email,
		Password:  a.Password,
		Verified:  a.Verified,
		CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt,
	})
}

func (s *Storage) GetAccountByID(ctx context.Context, id string) (*account.Account, error) {
	row, err := s.queries.GetAccountByID(ctx, id)
	if err != nil {
		return nil, err
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
		return nil, err
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
	_, err := s.queries.SetAccountVerified(ctx, sqlcgen.SetAccountVerifiedParams{
		Verified: verified,
		Email:    email,
	})
	return err
}

func (s *Storage) SetAccountPassword(ctx context.Context, id, password string) error {
	_, err := s.queries.SetAccountPassword(ctx, sqlcgen.SetAccountPasswordParams{
		Password: password,
		UserID:   id,
	})
	return err
}

func (s *Storage) DeleteAccount(ctx context.Context, id string) error {
	_, err := s.queries.DeleteAccount(ctx, id)
	return err
}

func (s *Storage) CreateRefreshToken(ctx context.Context, t account.RefreshToken) error {
	return s.queries.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		ID:        t.ID,
		Aid:       t.AID,
		Token:     t.Token,
		CreatedAt: t.CreatedAt,
		ExpiresAt: t.ExpiresAt,
	})
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, token string) error {
	return s.queries.DeleteRefreshToken(ctx, token)
}

func (s *Storage) DeleteRefreshTokenByTokenID(ctx context.Context, tid string) error {
	return s.queries.DeleteRefreshTokenByTokenID(ctx, tid)
}

func (s *Storage) PurgeRefreshTokens(ctx context.Context, aid string) error {
	return s.queries.PurgeRefreshTokens(ctx, aid)
}

func (s *Storage) DenyAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	return s.queries.DenyAccessToken(ctx, sqlcgen.DenyAccessTokenParams{
		Token:       token,
		DeniedUntil: time.Now().Add(ttl).Unix(),
	})
}

func (s *Storage) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	return s.queries.GetUserRoles(ctx, userID)
}
