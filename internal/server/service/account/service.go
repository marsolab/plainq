package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/config"
	serversecurity "github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/servekit/authkit/hashkit"
	"github.com/marsolab/servekit/authkit/jwtkit"
)

// ErrRefreshTokenNotFound is returned by DeleteRefreshToken when the token has
// no matching row — it was already rotated away or revoked on sign-out. The
// refresh flow treats it as an authentication failure so a stale refresh token
// cannot mint a new session.
var ErrRefreshTokenNotFound = errors.New("refresh token not found")

// ErrEmailNotVerified is returned when a valid password belongs to an account
// that has not completed the configured verification flow.
var ErrEmailNotVerified = errors.New("email is not verified")

// Storage encapsulates interaction with account storage.
//
//nolint:interfacebloat // domain interface for the account service; methods cohere around the account aggregate.
type Storage interface {
	// CreateAccount creates record with account information in database.
	CreateAccount(ctx context.Context, account Account) error

	// GetAccountByID fetches account record from database by given id.
	GetAccountByID(ctx context.Context, id string) (*Account, error)

	// GetAccountByEmail fetches account record from database by given email.
	GetAccountByEmail(ctx context.Context, email string) (*Account, error)

	// SetAccountVerified update 'verified' field of account record in database.
	SetAccountVerified(ctx context.Context, email string, verified bool) error

	// SetAccountPassword update account 'password' field of account record in database.
	SetAccountPassword(ctx context.Context, id, password string) error

	// DeleteAccount deletes account record from database by given id.
	DeleteAccount(ctx context.Context, id string) error

	// CreateRefreshToken creates refresh token record in database.
	CreateRefreshToken(ctx context.Context, token RefreshToken) error

	// DeleteRefreshToken deletes given token from database. It returns
	// ErrRefreshTokenNotFound when no row matched, so the caller can tell a
	// consumed or revoked token from a successful single-use rotation.
	DeleteRefreshToken(ctx context.Context, tokenHash []byte) error

	// DeleteRefreshTokenByTokenID deletes given token from database by its id.
	DeleteRefreshTokenByTokenID(ctx context.Context, tid string) error

	// PurgeRefreshTokens deletes all refresh token records related to given account.
	PurgeRefreshTokens(ctx context.Context, aid string) error

	// DenyAccessToken denies access token by given token string.
	DenyAccessToken(ctx context.Context, token DeniedToken) error

	// RevokeSession atomically denies the access-token id and removes the
	// refresh token sharing that id. Implementations must commit both changes
	// together or leave both unchanged.
	RevokeSession(ctx context.Context, token DeniedToken) error

	// IsAccessTokenDenied reports whether the given access token has been
	// denied (e.g. via sign-out) and is still within its denial window.
	IsAccessTokenDenied(ctx context.Context, tokenID string) (bool, error)

	// GetAccountSecurity returns the live tenant/status/version used to reject
	// stale human access tokens after a role change or account disable.
	GetAccountSecurity(ctx context.Context, userID string) (AccountSecurity, error)
	ResolveHumanSecurity(ctx context.Context, userID string) (tenantID, status string, authVersion uint64, err error)

	// GetUserRoles gets all roles for a user by user ID.
	GetUserRoles(ctx context.Context, userID string) ([]string, error)

	// GetAccountOrgID returns the organization the account belongs to, or an
	// empty string when it belongs to none. The directory uses it to scope a
	// listing to the caller's own tenant.
	GetAccountOrgID(ctx context.Context, userID string) (string, error)

	// ListDirectory returns one page of the account directory. Implementations
	// must return only the fields DirectoryEntry declares — never a password
	// hash — and must clamp the page size with ClampDirectoryLimit.
	ListDirectory(ctx context.Context, query DirectoryQuery) (*DirectoryPage, error)
}

// Account represents user account with all its properties.
type Account struct {
	ID          string
	Name        string
	Email       string
	Password    string
	Verified    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	TenantID    string
	AuthVersion uint64
	Status      string
}

const AccountStatusActive = "active"

// AccountSecurity is the mutable session-security projection for one human.
type AccountSecurity struct {
	TenantID    string
	Status      string
	AuthVersion uint64
}

// Session represents an auth session.
type Session struct {
	// AccessToken to be used for accessing resources.
	AccessToken string

	// RefreshToken to be used to generate a new pair of tokens.
	RefreshToken string

	// Time of token creation.
	CreatedAt time.Time

	// Time of token expiry.
	ExpiresAt time.Time
}

// RefreshToken represents refresh token.
type RefreshToken struct {
	ID         string
	AID        string
	TokenHash  []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

// DeniedToken is the non-secret revocation record persisted at logout.
type DeniedToken struct {
	TokenID   string
	AID       string
	ExpiresAt time.Time
	CreatedAt time.Time
	Reason    string
}

type Service struct {
	cfg         *config.Config
	logger      *slog.Logger
	router      *chi.Mux
	hasher      hashkit.Hasher
	tokman      jwtkit.TokenManager
	storage     Storage
	rateLimiter *serversecurity.KeyedLimiter
}

func NewService(
	cfg *config.Config,
	logger *slog.Logger,
	hasher hashkit.Hasher,
	tokenManager jwtkit.TokenManager,
	storage Storage,
) *Service {
	s := Service{
		cfg:    cfg,
		router: chi.NewRouter(),
		logger: logger,
		hasher: hasher,
		// Sessions are signed here (createSession), so without a token manager
		// signin/signup/refresh dereference a nil interface and panic.
		tokman:      tokenManager,
		storage:     storage,
		rateLimiter: newAuthRateLimiter(cfg),
	}

	s.router.Route("/", func(r chi.Router) {
		r.Post("/signup", s.signUpHandler)
		r.Post("/signin", s.signInHandler)
		r.Post("/signout", s.signOutHandler)
		r.Post("/refresh", s.refreshHandler)
	})

	return &s
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }

// IsAccessTokenDenied reports whether the given raw access token (without the
// "Bearer " prefix) has been revoked via sign-out and is still within its
// denial window. The auth middleware consults this so a signed-out token stops
// working immediately rather than lingering until its natural expiry.
func (s *Service) IsAccessTokenDenied(ctx context.Context, tokenID string) (bool, error) {
	denied, err := s.storage.IsAccessTokenDenied(ctx, tokenID)
	if err != nil {
		return false, fmt.Errorf("account service: check access token denylist: %w", err)
	}

	return denied, nil
}

// GetAccountSecurity exposes the live human session-security projection to
// HTTP and gRPC authentication middleware.
func (s *Service) GetAccountSecurity(ctx context.Context, userID string) (AccountSecurity, error) {
	security, err := s.storage.GetAccountSecurity(ctx, userID)
	if err != nil {
		return AccountSecurity{}, fmt.Errorf("account service: get account security: %w", err)
	}

	return security, nil
}

// ResolveHumanSecurity implements the transport-neutral live-session resolver
// used by both HTTP and gRPC authentication.
//
//nolint:gocritic // Interface compatibility requires the tenant, status, version tuple.
func (s *Service) ResolveHumanSecurity(
	ctx context.Context,
	userID string,
) (string, string, uint64, error) {
	security, err := s.GetAccountSecurity(ctx, userID)
	if err != nil {
		return "", "", 0, err
	}

	return security.TenantID, security.Status, security.AuthVersion, nil
}
