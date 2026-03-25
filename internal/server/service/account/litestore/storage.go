package litestore

import (
	"context"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/servekit/dbkit/litekit"
)

// Storage is an account storage.
type Storage struct {
	db     *litekit.Conn
	logger *slog.Logger
}

// NewStorage creates a new account storage.
func NewStorage(db *litekit.Conn, logger *slog.Logger, opts ...Option) (*Storage, error) {
	storage := &Storage{
		db:     db,
		logger: logger,
	}

	for _, opt := range opts {
		opt(storage)
	}

	return storage, nil
}

// Option is a function that configures the storage.
type Option func(*Storage)

// WithLogger sets the logger for the storage.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

func (s *Storage) SetAccountVerified(ctx context.Context, email string, verified bool) error {
	query := `
		UPDATE users
		SET verified = ?,
			updated_at = current_timestamp
		WHERE email = ?
	`
	_, err := s.db.ExecContext(ctx, query, verified, email)
	return err
}

func (s *Storage) SetAccountPassword(ctx context.Context, id, password string) error {
	query := `
		UPDATE users
		SET password = ?,
			updated_at = current_timestamp
		WHERE user_id = ?
	`
	_, err := s.db.ExecContext(ctx, query, password, id)
	return err
}

func (s *Storage) DeleteAccount(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

func (s *Storage) CreateRefreshToken(ctx context.Context, token account.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, aid, token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(ctx, query,
		token.ID,
		token.AID,
		token.Token,
		token.CreatedAt,
		token.ExpiresAt,
	)
	return err
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	return err
}

func (s *Storage) DeleteRefreshTokenByTokenID(ctx context.Context, tid string) error {
	query := `DELETE FROM refresh_tokens WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, tid)
	return err
}

func (s *Storage) PurgeRefreshTokens(ctx context.Context, aid string) error {
	query := `DELETE FROM refresh_tokens WHERE aid = ?`
	_, err := s.db.ExecContext(ctx, query, aid)
	return err
}

func (s *Storage) DenyAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	query := `
		INSERT INTO denylist (token, denied_until)
		VALUES (?, ?)
	`
	deniedUntil := time.Now().Add(ttl).Unix()
	_, err := s.db.ExecContext(ctx, query, token, deniedUntil)
	return err
}

func (s *Storage) CreateAccount(ctx context.Context, account account.Account) error {
	query := `
		INSERT INTO users (user_id, email, password, verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(ctx, query,
		account.ID,
		account.Email,
		account.Password,
		account.Verified,
		account.CreatedAt,
		account.UpdatedAt,
	)
	return err
}

func (s *Storage) GetAccountByID(ctx context.Context, id string) (*account.Account, error) {
	query := `
		SELECT user_id, email, password, verified, created_at, updated_at
		FROM users
		WHERE user_id = ?
	`

	var acc account.Account
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&acc.ID,
		&acc.Email,
		&acc.Password,
		&acc.Verified,
		&acc.CreatedAt,
		&acc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &acc, nil
}

func (s *Storage) GetAccountByEmail(ctx context.Context, email string) (*account.Account, error) {
	query := `
		SELECT user_id, email, password, verified, created_at, updated_at
		FROM users
		WHERE email = ?
	`

	var acc account.Account
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&acc.ID,
		&acc.Email,
		&acc.Password,
		&acc.Verified,
		&acc.CreatedAt,
		&acc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &acc, nil
}
