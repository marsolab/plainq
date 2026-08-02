package main

import (
	"testing"
)

func TestParseTursoDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawURL    string
		authToken string
		wantURL   string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "libsql url with configured token",
			rawURL:    "libsql://plainq-org.turso.io",
			authToken: "token",
			wantURL:   "libsql://plainq-org.turso.io",
			wantToken: "token",
		},
		{
			name:      "https url without token",
			rawURL:    "https://plainq-org.turso.io",
			wantURL:   "https://plainq-org.turso.io",
			wantToken: "",
		},
		{
			name:      "token embedded as authToken is lifted out of the url",
			rawURL:    "libsql://plainq-org.turso.io?authToken=embedded",
			wantURL:   "libsql://plainq-org.turso.io",
			wantToken: "embedded",
		},
		{
			name:      "token embedded as auth_token is lifted out of the url",
			rawURL:    "libsql://plainq-org.turso.io?auth_token=embedded",
			wantURL:   "libsql://plainq-org.turso.io",
			wantToken: "embedded",
		},
		{
			name:      "token embedded as jwt is lifted out of the url",
			rawURL:    "libsql://plainq-org.turso.io?jwt=embedded",
			wantURL:   "libsql://plainq-org.turso.io",
			wantToken: "embedded",
		},
		{
			name:      "configured token wins over embedded one",
			rawURL:    "libsql://plainq-org.turso.io?authToken=embedded",
			authToken: "configured",
			wantURL:   "libsql://plainq-org.turso.io",
			wantToken: "configured",
		},
		{
			name:      "unrelated query parameters are preserved",
			rawURL:    "https://plainq-org.turso.io?authToken=embedded&foo=bar",
			wantURL:   "https://plainq-org.turso.io?foo=bar",
			wantToken: "embedded",
		},
		{
			name:    "empty url",
			rawURL:  "",
			wantErr: true,
		},
		{
			name:    "file url points at the sqlite driver",
			rawURL:  "file:///var/lib/plainq.db",
			wantErr: true,
		},
		{
			name:    "websocket scheme is rejected",
			rawURL:  "wss://plainq-org.turso.io",
			wantErr: true,
		},
		{
			name:    "unknown scheme is rejected",
			rawURL:  "postgres://localhost:5432/plainq",
			wantErr: true,
		},
		{
			name:    "unparsable url",
			rawURL:  "libsql://plainq\x7f.turso.io",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTursoDSN(tt.rawURL, tt.authToken)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseTursoDSN(%q, %q): want error, got url %q", tt.rawURL, tt.authToken, got.url)
				}

				return
			}

			if err != nil {
				t.Fatalf("parseTursoDSN(%q, %q): %v", tt.rawURL, tt.authToken, err)
			}

			if got.url != tt.wantURL {
				t.Errorf("url: got %q, want %q", got.url, tt.wantURL)
			}

			if got.authToken != tt.wantToken {
				t.Errorf("token: got %q, want %q", got.authToken, tt.wantToken)
			}
		})
	}
}
