package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"
)

func TestBootstrapCredentialIssueAndParse(t *testing.T) {
	t.Parallel()

	credentialID := "01J00000000000000000000001"
	issued, err := issueBootstrapCredential(credentialID, bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("issueBootstrapCredential() error = %v", err)
	}
	if issued.prefix != "pqac_"+credentialID || !strings.HasPrefix(issued.raw, issued.prefix+"_") {
		t.Fatalf("issued credential = (%q, %q)", issued.raw, issued.prefix)
	}
	if issued.hash != sha256.Sum256([]byte(issued.raw)) {
		t.Fatal("issued credential hash does not cover the complete credential")
	}
	parsed, err := parseBootstrapCredential(issued.raw)
	if err != nil {
		t.Fatalf("parseBootstrapCredential() error = %v", err)
	}
	if parsed.prefix != issued.prefix || parsed.hash != issued.hash {
		t.Fatalf(
			"parsed credential = (%q, %x), want (%q, %x)",
			parsed.prefix,
			parsed.hash,
			issued.prefix,
			issued.hash,
		)
	}
}

func TestBootstrapCredentialParsingIsStrict(t *testing.T) {
	t.Parallel()

	issued, err := issueBootstrapCredential(
		"01J00000000000000000000001",
		bytes.NewReader(bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	parts := strings.SplitN(issued.raw, "_", 3)
	nonCanonical := strings.TrimSuffix(issued.raw, parts[2]) + strings.TrimSuffix(parts[2], "8") + "9"

	tests := map[string]string{
		"empty":                 "",
		"wrong marker":          strings.Replace(issued.raw, "pqac_", "other_", 1),
		"short ID":              "pqac_01J_" + parts[2],
		"lowercase ULID":        "pqac_" + strings.ToLower("01J00000000000000000000001") + "_" + parts[2],
		"invalid ULID alphabet": "pqac_01J0000000000000000000000I_" + parts[2],
		"short secret":          strings.TrimSuffix(issued.raw, parts[2]) + parts[2][:42],
		"invalid base64":        strings.TrimSuffix(issued.raw, parts[2]) + parts[2][:42] + "*",
		"extra separator":       issued.raw + "_extra",
		"noncanonical base64":   nonCanonical,
	}
	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseBootstrapCredential(input); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("parseBootstrapCredential(%q) error = %v, want %v", input, err, ErrUnauthenticated)
			}
		})
	}
}

func TestBootstrapCredentialIssuePropagatesEntropyFailure(t *testing.T) {
	t.Parallel()

	_, err := issueBootstrapCredential("01J00000000000000000000001", io.LimitReader(strings.NewReader("x"), 1))
	if err == nil || !strings.Contains(err.Error(), "read credential entropy") {
		t.Fatalf("issueBootstrapCredential() error = %v", err)
	}
}

func TestCredentialNameValidation(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"a", "planner", "a1", "agent-runtime", "a" + strings.Repeat("b", 62)} {
		if _, err := validateCredentialName(value); err != nil {
			t.Errorf("validateCredentialName(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"", "A", "1agent", "agent-", "agent_name", "a" + strings.Repeat("b", 63)} {
		if _, err := validateCredentialName(value); err == nil {
			t.Errorf("validateCredentialName(%q) error = nil", value)
		}
	}
}

func TestPreAuthLimiterIsPerKeyAndMemoryBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	limiter, err := newPreAuthLimiter(PreAuthConfig{
		RequestsPerSecond: 1, Burst: 1, MaxEntries: 2,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newPreAuthLimiter() error = %v", err)
	}
	if !limiter.allow("ip:one", "credential:one") {
		t.Fatal("first request was rejected")
	}
	if limiter.allow("ip:one", "credential:one") {
		t.Fatal("burst-exhausted request was accepted")
	}
	now = now.Add(time.Second)
	if !limiter.allow("ip:two", "credential:two") {
		t.Fatal("independent keys were rejected")
	}
	if len(limiter.entries) > 2 {
		t.Fatalf("limiter entries = %d, want at most 2", len(limiter.entries))
	}
}

func TestPreAuthLimiterRejectsNonFiniteRate(t *testing.T) {
	t.Parallel()

	for _, rate := range []float64{math.NaN(), math.Inf(1)} {
		if _, err := newPreAuthLimiter(PreAuthConfig{
			RequestsPerSecond: rate, Burst: 1, MaxEntries: 2,
		}, time.Now); err == nil {
			t.Fatalf("newPreAuthLimiter(%v) error = nil", rate)
		}
	}
}

func TestCredentialActiveRequiresNoLifecycleMarker(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0).UTC()
	future := now.Add(time.Hour)
	past := now.Add(-time.Second)
	marker := now
	tests := map[string]struct {
		record CredentialRecord
		want   bool
	}{
		"no expiry":        {record: CredentialRecord{}, want: true},
		"future expiry":    {record: CredentialRecord{ExpiresAt: &future}, want: true},
		"expired":          {record: CredentialRecord{ExpiresAt: &past}},
		"revoked":          {record: CredentialRecord{RevokedAt: &marker}},
		"expiry accounted": {record: CredentialRecord{ExpiredAccountedAt: &marker}},
	}
	for name, testCase := range tests {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := credentialActive(testCase.record, now); got != testCase.want {
				t.Fatalf("credentialActive() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestNoncanonicalCredentialFixtureIsActuallyEquivalent(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0xff}, 32)
	canonical := base64.RawURLEncoding.EncodeToString(raw)
	if !strings.HasSuffix(canonical, "8") {
		t.Fatalf("fixture suffix = %q, want 8", canonical)
	}
	variant := strings.TrimSuffix(canonical, "8") + "9"
	decoded, err := base64.RawURLEncoding.DecodeString(variant)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("noncanonical fixture does not decode equivalently: %v", err)
	}
}
