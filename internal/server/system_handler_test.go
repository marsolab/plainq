package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/maxatome/go-testdeep/td"
)

func readConfig(t *testing.T, cfg config.Config) ConfigResponse {
	t.Helper()

	rec := httptest.NewRecorder()
	NewSystemHandler(&cfg).GetConfig(rec, httptest.NewRequest(http.MethodGet, "/system/config", nil))

	td.Require(t).Cmp(rec.Code, http.StatusOK)

	var got ConfigResponse
	td.Require(t).CmpNoError(json.Unmarshal(rec.Body.Bytes(), &got), "decode response")

	return got
}

func factIn(t *testing.T, response ConfigResponse, group, label string) ConfigFact {
	t.Helper()

	for _, candidate := range response.Groups {
		if candidate.Title != group {
			continue
		}

		for _, fact := range candidate.Facts {
			if fact.Label == label {
				return fact
			}
		}
	}

	t.Fatalf("no %q fact in the %q group", label, group)

	return ConfigFact{}
}

func hasFact(response ConfigResponse, group, label string) bool {
	for _, candidate := range response.Groups {
		if candidate.Title != group {
			continue
		}

		for _, fact := range candidate.Facts {
			if fact.Label == label {
				return true
			}
		}
	}

	return false
}

func TestConfigReportsTheRunningInstance(t *testing.T) {
	response := readConfig(t, config.Config{
		StorageDriver:       "sqlite",
		StorageDBPath:       "/var/lib/plainq/plainq.db",
		StorageGCTimeout:    60 * time.Second,
		AuthEnable:          true,
		AuthAccessTokenTTL:  15 * time.Minute,
		AuthRefreshTokenTTL: 720 * time.Hour,
		AuthJWTSecret:       "a-real-signing-secret",
		HTTPAddr:            ":8080",
		GRPCAddr:            ":9090",
	})

	td.Cmp(t, factIn(t, response, "Storage", "Driver").Value, "sqlite")
	td.Cmp(t, factIn(t, response, "Storage", "Database file").Value, "/var/lib/plainq/plainq.db")
	td.Cmp(t, factIn(t, response, "Network", "HTTP listen").Value, ":8080")
	td.Cmp(t, factIn(t, response, "Network", "gRPC listen").Value, ":9090")

	// Durations travel as a count of seconds so the browser formats them with
	// the same rules it uses everywhere else.
	ttl := factIn(t, response, "Authentication", "Access token TTL")
	td.Cmp(t, ttl.Value, "900")
	td.Cmp(t, ttl.Format, FormatDuration)

	td.CmpNot(t, response.ReadAt, td.Zero(), "the answer states when it was read")
}

func TestConfigNeverReturnsSecrets(t *testing.T) {
	cfg := config.Config{
		StorageDriver:      "postgres",
		StoragePostgresDSN: "postgres://plainq:hunter2@db.internal:5432/plainq?sslmode=require",
		AuthEnable:         true,
		AuthJWTSecret:      "top-secret-signing-key",
		OAuthEnable:        true,
		OAuthClientID:      "kn_client_8f3a",
		OAuthClientSecret:  "kn_secret_do_not_leak",
	}

	rec := httptest.NewRecorder()
	NewSystemHandler(&cfg).GetConfig(rec, httptest.NewRequest(http.MethodGet, "/system/config", nil))

	body := rec.Body.String()
	for _, secret := range []string{"hunter2", "top-secret-signing-key", "kn_secret_do_not_leak"} {
		td.CmpNot(t, body, td.Contains(secret), "the response must not carry %q", secret)
	}

	response := readConfig(t, cfg)

	dsn := factIn(t, response, "Storage", "DSN")
	td.Cmp(t, dsn.Redacted, true)
	td.Cmp(t, dsn.Value, td.Contains("db.internal:5432"), "the host stays, so the row is useful")
	td.Cmp(t, dsn.Value, td.Contains("plainq@"), "so does the account name")

	// "set" versus "not set" is the fact an operator needs: it tells a missing
	// secret from one that exists and is being withheld.
	signing := factIn(t, response, "Authentication", "Signing secret")
	td.Cmp(t, signing.Value, "set")
	td.Cmp(t, signing.Redacted, true)

	clientSecret := factIn(t, response, "Identity providers", "Client secret")
	td.Cmp(t, clientSecret.Value, "set")
	td.Cmp(t, clientSecret.Redacted, true)

	// A public identifier is not a secret; withholding it would hide
	// configuration without protecting anything.
	td.Cmp(t, factIn(t, response, "Identity providers", "Client ID").Value, "kn_client_8f3a")
}

func TestConfigReportsAZeroDurationAsUnset(t *testing.T) {
	response := readConfig(t, config.Config{StorageDriver: "sqlite"})

	// "0 s" reads as an interval of no time at all — a setting nobody chose
	// and no subsystem honours.
	gc := factIn(t, response, "Storage", "GC interval")
	td.Cmp(t, gc.Value, "not set")
	td.Cmp(t, gc.Format, "")
	td.CmpNot(t, gc.Note, "", "an absent value explains itself")
}

func TestConfigDistinguishesUnsetSecretsFromWithheldOnes(t *testing.T) {
	response := readConfig(t, config.Config{AuthEnable: true})

	signing := factIn(t, response, "Authentication", "Signing secret")
	td.Cmp(t, signing.Value, "not set")
	td.Cmp(t, signing.Redacted, true)
}

func TestConfigOmitsSubsystemsThatAreNotRunning(t *testing.T) {
	response := readConfig(t, config.Config{
		AuthEnable:       false,
		OAuthEnable:      false,
		TelemetryEnabled: false,
		LogEnable:        false,
	})

	// Token lifetimes for a server that issues no tokens would describe a
	// subsystem that is not running.
	td.Cmp(t, hasFact(response, "Authentication", "Access token TTL"), false)
	td.Cmp(t, factIn(t, response, "Authentication", "API access").Value, "unauthenticated")

	td.Cmp(t, factIn(t, response, "Identity providers", "Status").Value, "disabled")
	td.Cmp(t, hasFact(response, "Identity providers", "Client ID"), false)

	td.Cmp(t, factIn(t, response, "Telemetry", "Status").Value, "disabled")
	td.Cmp(t, hasFact(response, "Telemetry", "Retention"), false)

	td.Cmp(t, hasFact(response, "Logging", "Level"), false)
}

func TestRedactDSN(t *testing.T) {
	tests := map[string]struct {
		dsn  string
		want string
	}{
		"credentials removed": {
			dsn:  "postgres://plainq:hunter2@db:5432/plainq",
			want: "postgres://plainq@db:5432/plainq",
		},
		"no credentials to remove": {
			dsn:  "postgres://db:5432/plainq",
			want: "postgres://db:5432/plainq",
		},
		"empty is reported as unset": {
			dsn:  "",
			want: "not set",
		},
		// An unparseable string is exactly where a password would survive a
		// pass-through, so it is withheld rather than trusted.
		"unparseable is withheld": {
			dsn:  "postgres://plainq:hunter2@[::1:5432/plainq",
			want: "unreadable — withheld",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			td.Cmp(t, redactDSN(tc.dsn), tc.want)
		})
	}
}

func TestRedactDSNClearsSecretQueryParameters(t *testing.T) {
	redacted := redactDSN("postgres://plainq@db:5432/plainq?sslmode=require&sslpassword=hunter2")

	td.CmpNot(t, redacted, td.Contains("hunter2"))
	td.Cmp(t, redacted, td.Contains("sslmode=require"))
}
