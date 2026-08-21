package account

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
	"github.com/marsolab/servekit/idkit"
)

const (
	defaultTokenIssuer   = "plainq-server"
	defaultTokenAudience = "plainq-human"
	maxAuthRequestBytes  = 32 << 10
)

//nolint:cyclop // Each request validation and persistence failure maps to a distinct HTTP response.
func (s *Service) signUpHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, authRequestMaxBytes(s.cfg))
	// Check if registration is enabled.
	if !s.cfg.AuthRegistrationEnable {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: user registration is disabled", errkit.ErrUnauthorized))

		return
	}

	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name,omitempty"`
	}

	var req request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))

		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("sign up: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	if !s.allowIPAndAccount(r, req.Email) {
		rejectAuthRate(w, r)

		return
	}

	if err := validateEmail(req.Email); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("validate email: %w", err))

		return
	}

	if req.Name != "" {
		if err := validateUserName(req.Name); err != nil {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("validate user name: %w", err))

			return
		}
	}

	if err := validatePassword(req.Password); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("validate user password: %w", err))

		return
	}

	hashedPassword, hashErr := s.hasher.HashPassword(req.Password)
	if hashErr != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("hash user password: %w", hashErr))

		return
	}

	verified := initialVerified(s.cfg)

	userAccount := Account{
		ID:          idkit.ULID(),
		Name:        req.Name,
		Email:       req.Email,
		Password:    hashedPassword,
		Verified:    verified,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		TenantID:    principal.LegacyTenantID,
		AuthVersion: 1,
		Status:      AccountStatusActive,
	}

	if err := s.storage.CreateAccount(r.Context(), userAccount); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create user record: %w", err))

		return
	}

	httpkit.Status(w, r, http.StatusCreated)
}

func (s *Service) signInHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, authRequestMaxBytes(s.cfg))

	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var req request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))

		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("sign in: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	if !s.allowIPAndAccount(r, req.Email) {
		rejectAuthRate(w, r)

		return
	}

	if err := validateEmail(req.Email); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("validate email: %w", err))

		return
	}

	account, err := s.storage.GetAccountByEmail(r.Context(), req.Email)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get account: %w", err))

		return
	}

	if err := s.hasher.CheckPassword(account.Password, req.Password); err != nil {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

		return
	}

	if err := requireVerified(*account); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: %w", errkit.ErrUnauthorized, err))

		return
	}

	session, err := s.createSession(r.Context(), account.ID, idkit.ULID(), time.Now())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create session: %w", err))

		return
	}

	httpkit.JSON(w, r, session)
}

func (s *Service) signOutHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthorized)

		return
	}

	token = strings.TrimPrefix(token, "Bearer")
	token = strings.TrimSpace(token)

	parsed, parseErr := s.tokman.ParseVerify(token)

	claims, claimsErr := validateHumanSessionClaims(parsed, s.cfg, "access", "uid")
	if parseErr != nil || claimsErr != nil {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

		return
	}

	if err := s.storage.DenyAccessToken(r.Context(), DeniedToken{
		TokenID: parsed.ID, AID: claims.accountID, ExpiresAt: parsed.ExpiresAt.UTC(),
		CreatedAt: time.Now(), Reason: "logout",
	}); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("deny access token: %w", err))

		return
	}

	// Denying the access token is not enough: the session's refresh token would
	// still mint a new one via the public /refresh endpoint. Access and refresh
	// tokens of a session share a token id (jti), so drop the refresh row by
	// that id to revoke the whole session. Best effort — an unparseable token
	// has no id to match, and the access token is already denied regardless.
	if err := s.storage.DeleteRefreshTokenByTokenID(r.Context(), parsed.ID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("delete refresh token: %w", err))

		return
	}

	httpkit.Status(w, r, http.StatusOK)
}

//nolint:cyclop // Refresh deliberately keeps parse, live-state, rotation, and replay failures distinct.
func (s *Service) refreshHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, authRequestMaxBytes(s.cfg))

	type request struct {
		RefreshToken string `json:"refresh_token"`
	}

	var req request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))

		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("refresh: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	if !s.allowIP(r) {
		rejectAuthRate(w, r)

		return
	}

	token, parseErr := s.tokman.ParseVerify(req.RefreshToken)
	if parseErr != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: parse refresh token: %s", errkit.ErrUnauthenticated, parseErr.Error()))

		return
	}

	claims, claimsErr := validateHumanSessionClaims(token, s.cfg, "refresh", "aid")
	if claimsErr != nil {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)

		return
	}

	if !s.allowAccount(claims.accountID) {
		rejectAuthRate(w, r)

		return
	}

	live, securityErr := s.storage.GetAccountSecurity(r.Context(), claims.accountID)
	if securityErr != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("get account security: %w", securityErr))

		return
	}

	if live.Status != AccountStatusActive || live.TenantID != claims.tenantID ||
		live.AuthVersion != claims.authVersion {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: refresh token is stale", errkit.ErrUnauthenticated))

		return
	}

	// Consume the presented refresh token as a single-use credential. A missing
	// row means it was already rotated away or revoked on sign-out, so refuse to
	// mint a new session rather than resurrect a dead one.
	tokenHash := hashSessionToken(req.RefreshToken)
	if err := s.storage.DeleteRefreshToken(r.Context(), tokenHash[:]); err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: refresh token is no longer valid", errkit.ErrUnauthenticated))

			return
		}

		httpkit.ErrorHTTP(w, r, fmt.Errorf("delete refresh token: %w", err))

		return
	}

	// Create new session.
	session, err := s.createSession(r.Context(), claims.accountID, idkit.ULID(), time.Now())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create session: %w", err))

		return
	}

	httpkit.JSON(w, r, session)
}

// createSession is a helper function to create a new session.
//
//nolint:cyclop // Session creation validates every security precondition before signing or persistence.
func (s *Service) createSession(ctx context.Context, aid, tid string, t time.Time) (*Session, error) {
	// Get user account to get email.
	account, err := s.storage.GetAccountByID(ctx, aid)
	if err != nil {
		return nil, fmt.Errorf("account service: failed to get account: %w", err)
	}

	if err := requireVerified(*account); err != nil {
		return nil, err
	}

	if account.Status != "" && account.Status != AccountStatusActive {
		return nil, errors.New("account is disabled")
	}

	if account.TenantID == "" {
		return nil, errors.New("account tenant is required")
	}

	if account.AuthVersion == 0 {
		return nil, errors.New("account auth version is required")
	}

	// Get user roles.
	roles, err := s.storage.GetUserRoles(ctx, aid)
	if err != nil {
		// If no roles found, continue with empty roles.
		roles = []string{}
	}

	accessToken, aErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tid,
			Audience:  []string{humanTokenAudience(s.cfg)},
			Issuer:    humanTokenIssuer(s.cfg),
			Subject:   aid,
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthAccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"uid":          aid,
			"email":        account.Email,
			"roles":        roles,
			"tenant_id":    account.TenantID,
			"auth_version": account.AuthVersion,
			"token_use":    "access",
		},
	})
	if aErr != nil {
		return nil, fmt.Errorf("account service: failed to create session: %w", aErr)
	}

	refreshToken, rErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tid,
			Audience:  []string{humanTokenAudience(s.cfg)},
			Issuer:    humanTokenIssuer(s.cfg),
			Subject:   aid,
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthRefreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"aid":          aid,
			"tenant_id":    account.TenantID,
			"auth_version": account.AuthVersion,
			"token_use":    "refresh",
		},
	})
	if rErr != nil {
		return nil, fmt.Errorf("account service: failed to create session: %w", rErr)
	}

	refreshHash := hashSessionToken(refreshToken)
	refreshTokenRecord := RefreshToken{
		ID:         tid,
		AID:        aid,
		TokenHash:  append([]byte(nil), refreshHash[:]...),
		CreatedAt:  t,
		ExpiresAt:  t.Add(s.cfg.AuthRefreshTokenTTL),
		LastUsedAt: t,
	}

	if err := s.storage.CreateRefreshToken(ctx, refreshTokenRecord); err != nil {
		return nil, fmt.Errorf("account service: failed to save refresh token in database: %w", err)
	}

	session := Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreatedAt:    t,
		ExpiresAt:    t.Add(s.cfg.AuthAccessTokenTTL),
	}

	return &session, nil
}

func initialVerified(cfg *config.Config) bool {
	return cfg == nil || !cfg.AuthEmailVerificationEnable
}

func requireVerified(account Account) error {
	if !account.Verified {
		return ErrEmailNotVerified
	}

	return nil
}

func hashSessionToken(raw string) [32]byte {
	return sha256.Sum256([]byte(raw))
}

func humanTokenIssuer(cfg *config.Config) string {
	if cfg != nil && cfg.AuthJWTIssuer != "" {
		return cfg.AuthJWTIssuer
	}

	return defaultTokenIssuer
}

func humanTokenAudience(cfg *config.Config) string {
	if cfg != nil && cfg.AuthJWTAudience != "" {
		return cfg.AuthJWTAudience
	}

	return defaultTokenAudience
}

type humanSessionClaims struct {
	accountID   string
	tenantID    string
	authVersion uint64
}

//nolint:cyclop // Every required refresh/access-token claim is validated independently.
func validateHumanSessionClaims(
	token *jwtkit.Token,
	cfg *config.Config,
	wantUse string,
	accountMetaKey string,
) (humanSessionClaims, error) {
	if err := validateRegisteredHumanToken(token, cfg); err != nil {
		return humanSessionClaims{}, err
	}

	accountID, ok := token.Meta[accountMetaKey].(string)
	if !ok || accountID == "" || accountID != token.Subject {
		return humanSessionClaims{}, errors.New("invalid account token claim")
	}

	tokenUse, ok := token.Meta["token_use"].(string)
	if !ok || tokenUse != wantUse {
		return humanSessionClaims{}, errors.New("invalid token use")
	}

	tenantID, ok := token.Meta["tenant_id"].(string)
	if !ok || tenantID == "" {
		return humanSessionClaims{}, errors.New("invalid tenant token claim")
	}

	authVersion, ok := security.Uint64Claim(token.Meta["auth_version"])
	if !ok || authVersion == 0 {
		return humanSessionClaims{}, errors.New("invalid auth version token claim")
	}

	return humanSessionClaims{
		accountID: accountID, tenantID: tenantID, authVersion: authVersion,
	}, nil
}

func validateRegisteredHumanToken(token *jwtkit.Token, cfg *config.Config) error {
	if token == nil || token.ID == "" || token.ExpiresAt == nil || token.Subject == "" ||
		token.Issuer != humanTokenIssuer(cfg) || !tokenHasAudience(token.Audience, humanTokenAudience(cfg)) {
		return errors.New("invalid registered token claims")
	}

	return nil
}

func tokenHasAudience(audiences []string, want string) bool {
	for _, audience := range audiences {
		if audience == want {
			return true
		}
	}

	return false
}
