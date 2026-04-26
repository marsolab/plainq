package account

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
	"github.com/marsolab/servekit/idkit"
	"github.com/marsolab/servekit/mailkit"
)

const (
	tokenIssuer = "plainq-server"
)

func (s *Service) signUpHandler(w http.ResponseWriter, r *http.Request) {
	// Check if registration is enabled
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

	verified := !s.cfg.AuthRegistrationEnable

	userAccount := Account{
		ID:        idkit.ULID(),
		Name:      req.Name,
		Email:     req.Email,
		Password:  hashedPassword,
		Verified:  verified,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.storage.CreateAccount(r.Context(), userAccount); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create user record: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusCreated)
}

func (s *Service) signInHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := s.storage.DenyAccessToken(r.Context(), token, s.cfg.AuthAccessTokenTTL); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("deny access token: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusOK)
}

func (s *Service) refreshHandler(w http.ResponseWriter, r *http.Request) {
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

	token, parseErr := s.tokman.ParseVerify(req.RefreshToken)
	if parseErr != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: parse refresh token: %s", errkit.ErrUnauthenticated, parseErr.Error()))
		return
	}

	aid, ok := token.Meta["aid"]
	if !ok {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)
		return
	}

	accountID, ok := aid.(string)
	if !ok {
		httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)
		return
	}

	// Delete the old refresh token.
	if err := s.storage.DeleteRefreshToken(r.Context(), req.RefreshToken); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("delete refresh token: %w", err))
		return
	}

	// Create new session.
	session, err := s.createSession(r.Context(), accountID, idkit.ULID(), time.Now())
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("create session: %w", err))
		return
	}

	httpkit.JSON(w, r, session)
}

func (s *Service) emailVerificationHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email string `json:"email"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer r.Body.Close()

	if err := validateEmail(req.Email); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("validate email: %w", err))
		return
	}

	code := idkit.DigiCode()

	if err := s.mailer.Send(r.Context(), mailkit.Message{
		From:    "noreply@plainq.com",
		To:      []string{req.Email},
		Subject: "Verify your email",
		HTML:    fmt.Sprintf("<p>Click <a href='https://plainq.com/verify?code=%s'>here</a> to verify your email.</p>", code),
		Text:    "Click here to verify your email: https://plainq.com/verify?code=" + code,
	}); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("send email: %w", err))
		return
	}

	httpkit.Status(w, r, http.StatusOK)
}

func (s *Service) verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Code string `json:"code"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("verify email: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	// TODO: Implement verification code validation logic

	httpkit.Status(w, r, http.StatusOK)
}

func (s *Service) resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email string `json:"email"`
	}

	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("reset password: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	if err := validateEmail(req.Email); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("validate email: %w", err))
		return
	}

	// TODO: Implement password reset code sending logic

	httpkit.Status(w, r, http.StatusOK)
}

func (s *Service) verifyPasswordResetCodeHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Code string `json:"code"`
	}

	var req request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: decode request json: %s", errkit.ErrInvalidArgument, err.Error()))
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("verify password reset code: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	// TODO: Implement password reset code validation logic

	httpkit.Status(w, r, http.StatusOK)
}

// createSession is a helper function to create a new session.
func (s *Service) createSession(ctx context.Context, aid, tid string, t time.Time) (*Session, error) {
	// Get user account to get email
	account, err := s.storage.GetAccountByID(ctx, aid)
	if err != nil {
		return nil, fmt.Errorf("account service: failed to get account: %w", err)
	}

	// Get user roles
	roles, err := s.storage.GetUserRoles(ctx, aid)
	if err != nil {
		// If no roles found, continue with empty roles
		roles = []string{}
	}

	accessToken, aErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tid,
			Audience:  []string{},
			Issuer:    tokenIssuer,
			Subject:   "",
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthAccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"uid":   aid,
			"email": account.Email,
			"roles": roles,
		},
	})
	if aErr != nil {
		return nil, fmt.Errorf("account service: failed to create session: %w", aErr)
	}

	refreshToken, rErr := s.tokman.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID:        tid,
			Audience:  []string{},
			Issuer:    tokenIssuer,
			Subject:   "",
			ExpiresAt: jwt.NewNumericDate(t.Add(s.cfg.AuthRefreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(t),
			NotBefore: jwt.NewNumericDate(t),
		},
		Meta: map[string]any{
			"aid": aid,
		},
	})
	if rErr != nil {
		return nil, fmt.Errorf("account service: failed to create session: %w", rErr)
	}

	refreshTokenRecord := RefreshToken{
		ID:        tid,
		AID:       aid,
		Token:     refreshToken,
		CreatedAt: t,
		ExpiresAt: t.Add(s.cfg.AuthRefreshTokenTTL),
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
