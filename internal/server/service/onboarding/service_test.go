package onboarding

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/logkit"
)

type bootstrapStorageStub struct {
	Storage
	record BootstrapRecord
	err    error
	calls  int
}

func (*bootstrapStorageStub) HasAdminUsers(context.Context) (bool, error) { return false, nil }

func (s *bootstrapStorageStub) Bootstrap(_ context.Context, record BootstrapRecord) error {
	s.calls++
	s.record = record

	return s.err
}

type bootstrapHasherStub struct{}

func (bootstrapHasherStub) HashPassword(string) (string, error) { return "password-hash", nil }
func (bootstrapHasherStub) CheckPassword(string, string) error  { return nil }

type bootstrapTokenManagerStub struct {
	tokens []*jwtkit.Token
}

func (m *bootstrapTokenManagerStub) Sign(token *jwtkit.Token) (string, error) {
	m.tokens = append(m.tokens, token)
	if len(m.tokens) == 1 {
		return "clear-access-token", nil
	}

	return "clear-refresh-token", nil
}

func (*bootstrapTokenManagerStub) Verify(string) error                       { return nil }
func (*bootstrapTokenManagerStub) ParseVerify(string) (*jwtkit.Token, error) { return nil, nil }
func (*bootstrapTokenManagerStub) ParseVerifyClaims(string, any) error       { return nil }

func newBootstrapService(storage Storage, tokens jwtkit.TokenManager) *Service {
	cfg := config.Config{
		AuthBootstrapSecret: strings.Repeat("b", 32),
		AuthJWTIssuer:       "plainq-server", AuthJWTAudience: "plainq-human",
		AuthAccessTokenTTL: time.Hour, AuthRefreshTokenTTL: 30 * 24 * time.Hour,
		AuthRequestMaxBytes: 32 << 10, AuthRateRequestsPerSecond: 1000, AuthRateBurst: 1000,
	}

	return NewService(&cfg, logkit.NewNop(), bootstrapHasherStub{}, tokens, storage)
}

func postBootstrap(t *testing.T, service http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/complete", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("User-Agent", "plainq-test")
	rec := httptest.NewRecorder()
	service.ServeHTTP(rec, req)

	return rec
}

func TestBootstrapRequiresConfiguredSecretBeforeStorage(t *testing.T) {
	storage := &bootstrapStorageStub{}
	service := newBootstrapService(storage, &bootstrapTokenManagerStub{})

	rec := postBootstrap(t, service,
		`{"bootstrap_secret":"wrong","email":"admin@example.test","password":"password123"}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("bootstrap with wrong secret returned success: %s", rec.Body.String())
	}
	if storage.calls != 0 {
		t.Fatalf("Bootstrap() calls = %d, want 0", storage.calls)
	}
}

func TestBootstrapPersistsCompleteTransactionWithoutRawCredentials(t *testing.T) {
	storage := &bootstrapStorageStub{}
	tokens := &bootstrapTokenManagerStub{}
	service := newBootstrapService(storage, tokens)

	rec := postBootstrap(t, service,
		`{"bootstrap_secret":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","email":"admin@example.test","password":"password123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if storage.calls != 1 {
		t.Fatalf("Bootstrap() calls = %d, want 1", storage.calls)
	}
	if storage.record.Admin.Password != "password-hash" || !storage.record.Admin.Verified {
		t.Fatalf("stored admin = %#v", storage.record.Admin)
	}
	wantHash := sha256.Sum256([]byte("clear-refresh-token"))
	if string(storage.record.RefreshToken.TokenHash) != string(wantHash[:]) {
		t.Fatal("storage did not receive SHA-256(refresh token)")
	}
	if string(storage.record.RefreshToken.TokenHash) == "clear-refresh-token" {
		t.Fatal("storage received the raw refresh token")
	}
	if storage.record.Audit.Action != "onboarding.bootstrap" || storage.record.Audit.SourceIP != "192.0.2.10" {
		t.Fatalf("audit = %#v", storage.record.Audit)
	}
	if len(tokens.tokens) != 2 {
		t.Fatalf("signed token count = %d, want 2", len(tokens.tokens))
	}
	access := tokens.tokens[0]
	if access.Claims.Subject == "" || len(access.Claims.Audience) != 1 ||
		access.Meta["token_use"] != "access" || access.Meta["tenant_id"] == "" {
		t.Fatalf("access claims = %#v meta=%#v", access.Claims, access.Meta)
	}

	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	admin := response["admin"].(map[string]any)
	if password, exists := admin["password"]; exists && password != "" {
		t.Fatalf("response disclosed password field: %#v", password)
	}
}

func TestBootstrapDoesNotReturnSessionWhenTransactionFails(t *testing.T) {
	storage := &bootstrapStorageStub{err: errors.New("transaction failed")}
	service := newBootstrapService(storage, &bootstrapTokenManagerStub{})

	rec := postBootstrap(t, service,
		`{"bootstrap_secret":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","email":"admin@example.test","password":"password123"}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("failed transaction returned session: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "clear-access-token") || strings.Contains(rec.Body.String(), "clear-refresh-token") {
		t.Fatalf("failed transaction disclosed tokens: %s", rec.Body.String())
	}
}

func TestBootstrapRateLimitsByIPAndAccount(t *testing.T) {
	storage := &bootstrapStorageStub{}
	cfg := config.Config{
		AuthBootstrapSecret: strings.Repeat("b", 32),
		AuthJWTIssuer:       "plainq-server", AuthJWTAudience: "plainq-human",
		AuthAccessTokenTTL: time.Hour, AuthRefreshTokenTTL: 30 * 24 * time.Hour,
		AuthRequestMaxBytes: 32 << 10, AuthRateRequestsPerSecond: 1, AuthRateBurst: 1,
	}
	service := NewService(
		&cfg, logkit.NewNop(), bootstrapHasherStub{}, &bootstrapTokenManagerStub{}, storage,
	)
	body := `{"bootstrap_secret":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","email":"admin@example.test","password":"password123"}`

	first := postBootstrap(t, service, body)
	if first.Code != http.StatusOK {
		t.Fatalf("first bootstrap status = %d, want %d: %s", first.Code, http.StatusOK, first.Body.String())
	}
	second := postBootstrap(t, service, body)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second bootstrap status = %d, want %d: %s", second.Code, http.StatusTooManyRequests, second.Body.String())
	}
}
