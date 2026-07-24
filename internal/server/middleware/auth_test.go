package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/maxatome/go-testdeep/td"
)

// fakeDenylist is a stub TokenDenylist whose answer is fixed per test case.
type fakeDenylist struct {
	denied bool
	err    error
}

func (f fakeDenylist) IsAccessTokenDenied(context.Context, string) (bool, error) {
	return f.denied, f.err
}

func newTokenManager(t *testing.T) jwtkit.TokenManager {
	t.Helper()

	secret := []byte("test-secret-please-ignore")

	signer, err := jwt.NewSignerHS(jwt.HS256, secret)
	td.Require(t).CmpNoError(err)

	verifier, err := jwt.NewVerifierHS(jwt.HS256, secret)
	td.Require(t).CmpNoError(err)

	return jwtkit.NewTokenManager(signer, verifier)
}

func signValidToken(t *testing.T, tm jwtkit.TokenManager) string {
	t.Helper()

	now := time.Now()

	token, err := tm.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Meta: map[string]any{
			"uid":   "user-1",
			"email": "user@example.com",
		},
	})
	td.Require(t).CmpNoError(err)

	return token
}

// TestAuthenticateJWTDenylist covers the revocation check: a cryptographically
// valid token must still be rejected once it has been signed out, and a lookup
// failure must fail closed rather than admit an unverifiable token.
func TestAuthenticateJWTDenylist(t *testing.T) {
	tm := newTokenManager(t)
	validToken := signValidToken(t, tm)

	tests := map[string]struct {
		denylist   TokenDenylist
		wantStatus int
		wantNext   bool
	}{
		"valid token passes when not denied": {
			denylist:   fakeDenylist{denied: false},
			wantStatus: http.StatusOK,
			wantNext:   true,
		},
		"signed-out token is rejected": {
			denylist:   fakeDenylist{denied: true},
			wantStatus: http.StatusUnauthorized,
			wantNext:   false,
		},
		"lookup error fails closed": {
			denylist:   fakeDenylist{err: errors.New("db unavailable")},
			wantStatus: http.StatusInternalServerError,
			wantNext:   false,
		},
		"nil denylist skips the revocation check": {
			denylist:   nil,
			wantStatus: http.StatusOK,
			wantNext:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			handler := AuthenticateJWT(tm, tc.denylist)(next)

			req := httptest.NewRequest(http.MethodGet, "/queue", nil)
			req.Header.Set("Authorization", "Bearer "+validToken)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			td.Cmp(t, rec.Code, tc.wantStatus)
			td.Cmp(t, nextCalled, tc.wantNext)
		})
	}
}
