package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestHoustonStaticHandler(t *testing.T) {
	pq := &PlainQ{logger: slog.Default()}

	r := chi.NewRouter()
	r.Get("/*", pq.houstonStaticHandler)

	cases := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string // substring expected in body
	}{
		{"root serves index.html", "/", http.StatusOK, "<!DOCTYPE html>"},
		{"asset", "/favicon.svg", http.StatusOK, "<svg"},
		{"deep SPA path falls back to parent index", "/queue/abc123", http.StatusOK, "<!DOCTYPE html>"},
		// An unknown route must not be dressed up as a successful page load.
		// The body is deliberately unchecked: it is the bundle's 404 page when
		// one is shipped and a plain fallback otherwise, but the status is the
		// contract either way.
		{"unknown route is not found", "/something-not-real", http.StatusNotFound, ""},
		// A route directory is served in place rather than via a 301.
		{"route directory serves its index", "/login", http.StatusOK, "<!DOCTYPE html>"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				body, _ := io.ReadAll(rec.Body)
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.wantStatus, body)
			}
			body, _ := io.ReadAll(rec.Body)
			if !strings.Contains(string(body), tc.wantBody) {
				t.Fatalf("body does not contain %q\nbody=%s", tc.wantBody, body[:min(400, len(body))])
			}
		})
	}
}
