package account

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/logkit"
)

type authStorageStub struct {
	Storage
	account      Account
	created      Account
	refresh      RefreshToken
	denied       string
	deletedToken string
	deletedHash  []byte
	revoked      DeniedToken
	revokeCalls  int
}

func (s *authStorageStub) CreateAccount(_ context.Context, got Account) error {
	s.created = got

	return nil
}

func (s *authStorageStub) GetAccountByEmail(context.Context, string) (*Account, error) {
	got := s.account

	return &got, nil
}

func (s *authStorageStub) GetAccountByID(context.Context, string) (*Account, error) {
	got := s.account

	return &got, nil
}

func (*authStorageStub) GetUserRoles(context.Context, string) ([]string, error) {
	return []string{"admin"}, nil
}

func (s *authStorageStub) CreateRefreshToken(_ context.Context, token RefreshToken) error {
	s.refresh = token

	return nil
}

func (s *authStorageStub) DenyAccessToken(_ context.Context, token DeniedToken) error {
	s.denied = token.TokenID

	return nil
}

func (s *authStorageStub) DeleteRefreshTokenByTokenID(_ context.Context, id string) error {
	s.deletedToken = id

	return nil
}

func (s *authStorageStub) DeleteRefreshToken(_ context.Context, tokenHash []byte) error {
	s.deletedHash = append([]byte(nil), tokenHash...)

	return nil
}

func (s *authStorageStub) RevokeSession(_ context.Context, token DeniedToken) error {
	s.revokeCalls++
	s.revoked = token

	return nil
}

func (s *authStorageStub) GetAccountSecurity(context.Context, string) (AccountSecurity, error) {
	return AccountSecurity{
		TenantID: s.account.TenantID, Status: s.account.Status, AuthVersion: s.account.AuthVersion,
	}, nil
}

func (s *authStorageStub) ResolveHumanSecurity(context.Context, string) (string, string, uint64, error) {
	return s.account.TenantID, s.account.Status, s.account.AuthVersion, nil
}

type authHasherStub struct{}

func (authHasherStub) HashPassword(string) (string, error) { return "password-hash", nil }

func (authHasherStub) CheckPassword(hash, password string) error {
	if hash != "password-hash" || password != "correct-password" {
		return errors.New("password mismatch")
	}

	return nil
}

type authTokenManagerStub struct {
	signed int
	parsed *jwtkit.Token
}

func (m *authTokenManagerStub) Sign(*jwtkit.Token) (string, error) {
	m.signed++
	if m.signed%2 == 1 {
		return "access-token", nil
	}

	return "refresh-token", nil
}

func (*authTokenManagerStub) Verify(string) error { return nil }

func (m *authTokenManagerStub) ParseVerify(string) (*jwtkit.Token, error) {
	if m.parsed != nil {
		return m.parsed, nil
	}

	now := time.Now()

	return &jwtkit.Token{Claims: jwtkit.Claims{
		ID: "session-jti", Subject: "user-1", Issuer: "plainq-server",
		Audience: []string{"plainq-human"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}, Meta: map[string]any{
		"uid": "user-1", "tenant_id": "tenant-1", "auth_version": uint64(1), "token_use": "access",
	}}, nil
}

func TestRefreshRejectsStaleAuthVersionBeforeConsumption(t *testing.T) {
	now := time.Now()
	storage := &authStorageStub{account: Account{
		ID: "user-1", TenantID: "tenant-1", AuthVersion: 2, Status: AccountStatusActive, Verified: true,
	}}
	tokens := &authTokenManagerStub{parsed: &jwtkit.Token{
		Claims: jwtkit.Claims{
			ID: "old-session", Subject: "user-1", Issuer: "plainq-server",
			Audience: []string{"plainq-human"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Meta: map[string]any{
			"aid": "user-1", "tenant_id": "tenant-1", "auth_version": float64(1), "token_use": "refresh",
		},
	}}
	cfg := config.Config{
		AuthAccessTokenTTL: time.Hour, AuthRefreshTokenTTL: 24 * time.Hour,
		AuthJWTIssuer: "plainq-server", AuthJWTAudience: "plainq-human",
	}
	svc := NewService(&cfg, logkit.NewNop(), authHasherStub{}, tokens, storage)

	rec := postJSON(t, svc, "/refresh", `{"refresh_token":"old-refresh-token"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh status = %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if len(storage.deletedHash) != 0 {
		t.Fatal("stale refresh token was consumed after it should have been rejected")
	}
}

func (*authTokenManagerStub) ParseVerifyClaims(string, any) error { return nil }

func newAuthService(cfg config.Config, storage Storage) *Service {
	if cfg.AuthAccessTokenTTL == 0 {
		cfg.AuthAccessTokenTTL = time.Hour
	}
	if cfg.AuthRefreshTokenTTL == 0 {
		cfg.AuthRefreshTokenTTL = 24 * time.Hour
	}

	return NewService(&cfg, logkit.NewNop(), authHasherStub{}, &authTokenManagerStub{}, storage)
}

func postJSON(t *testing.T, handler http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func TestSignupVerificationFollowsEmailVerificationFlag(t *testing.T) {
	for _, test := range []struct {
		name         string
		enabled      bool
		wantVerified bool
	}{
		{name: "verification required", enabled: true, wantVerified: false},
		{name: "verification disabled", enabled: false, wantVerified: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			storage := &authStorageStub{}
			svc := newAuthService(config.Config{
				AuthRegistrationEnable: true, AuthEmailVerificationEnable: test.enabled,
			}, storage)

			rec := postJSON(t, svc, "/signup", `{"email":"user@example.test","password":"correct-password"}`)
			if rec.Code != http.StatusCreated {
				t.Fatalf("signup status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
			}
			if storage.created.Verified != test.wantVerified {
				t.Fatalf("created verified = %v, want %v", storage.created.Verified, test.wantVerified)
			}
		})
	}
}

func TestSignupRateLimitsByIPAndAccount(t *testing.T) {
	storage := &authStorageStub{}
	svc := newAuthService(config.Config{
		AuthRegistrationEnable: true, AuthRequestMaxBytes: 32 << 10,
		AuthRateRequestsPerSecond: 1, AuthRateBurst: 1,
	}, storage)
	body := `{"email":"user@example.test","password":"correct-password"}`

	first := postJSON(t, svc, "/signup", body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first signup status = %d, want %d: %s", first.Code, http.StatusCreated, first.Body.String())
	}
	second := postJSON(t, svc, "/signup", body)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second signup status = %d, want %d: %s", second.Code, http.StatusTooManyRequests, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited response omitted Retry-After")
	}
}

func TestSigninRejectsUnverifiedUser(t *testing.T) {
	storage := &authStorageStub{account: Account{
		ID: "user-1", Email: "user@example.test", Password: "password-hash", Verified: false,
		TenantID: "tenant-1", AuthVersion: 1, Status: AccountStatusActive,
	}}
	svc := newAuthService(config.Config{}, storage)

	rec := postJSON(t, svc, "/signin", `{"email":"user@example.test","password":"correct-password"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("signin status = %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if storage.refresh.ID != "" {
		t.Fatal("signin created a refresh session for an unverified user")
	}
}

func TestRefreshTokenPersistenceNeverContainsClearToken(t *testing.T) {
	storage := &authStorageStub{account: Account{
		ID: "user-1", Email: "user@example.test", Password: "password-hash", Verified: true,
		TenantID: "tenant-1", AuthVersion: 1, Status: AccountStatusActive,
	}}
	svc := newAuthService(config.Config{}, storage)

	session, err := svc.createSession(context.Background(), "user-1", "session-jti", time.Now())
	if err != nil {
		t.Fatalf("createSession() error = %v", err)
	}
	if string(storage.refresh.TokenHash) == session.RefreshToken {
		t.Fatal("refresh storage contains the clear bearer token")
	}
}

func TestSignoutStoresOnlyTokenID(t *testing.T) {
	storage := &authStorageStub{}
	svc := newAuthService(config.Config{}, storage)
	req := httptest.NewRequest(http.MethodPost, "/signout", nil)
	req.Header.Set("Authorization", "Bearer clear-access-token")
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("signout status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if storage.revoked.TokenID != "session-jti" {
		t.Fatalf("denylist key = %q, want token id", storage.revoked.TokenID)
	}
}

func TestSignoutUsesOneAtomicSessionRevocation(t *testing.T) {
	storage := &authStorageStub{}
	svc := newAuthService(config.Config{}, storage)
	req := httptest.NewRequest(http.MethodPost, "/signout", nil)
	req.Header.Set("Authorization", "Bearer clear-access-token")
	rec := httptest.NewRecorder()

	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("signout status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if storage.revokeCalls != 1 || storage.revoked.TokenID != "session-jti" {
		t.Fatalf("atomic revocation = %d calls with %#v", storage.revokeCalls, storage.revoked)
	}
	if storage.denied != "" || storage.deletedToken != "" {
		t.Fatalf("signout used split writes: denied %q deleted refresh %q", storage.denied, storage.deletedToken)
	}
}

func TestUnimplementedVerificationAndResetEndpointsAreNotMounted(t *testing.T) {
	svc := newAuthService(config.Config{}, &authStorageStub{})

	for _, path := range []string{
		"/email/verification", "/email/verify", "/password/reset", "/password/verify",
	} {
		t.Run(path, func(t *testing.T) {
			rec := postJSON(t, svc, path, `{}`)
			if rec.Code != http.StatusNotFound {
				var response any
				_ = json.Unmarshal(rec.Body.Bytes(), &response)
				t.Fatalf("POST %s status = %d, want %d (body %#v)", path, rec.Code, http.StatusNotFound, response)
			}
		})
	}
}
