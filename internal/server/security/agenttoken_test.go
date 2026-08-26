package security

import (
	"errors"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

var testAgentTokenSecret = []byte("0123456789abcdef0123456789abcdef")

func TestAgentTokenRejectsTTLAboveMaximum(t *testing.T) {
	t.Parallel()

	_, err := NewAgentTokenManager(AgentTokenConfig{
		Issuer: "plainq-test", Audience: "plainq-agent", Secret: testAgentTokenSecret,
		TTL: 15*time.Minute + time.Nanosecond,
	})
	if err == nil {
		t.Fatal("NewAgentTokenManager() accepted a TTL above 15 minutes")
	}
}

func TestAgentTokenRoundTripIncludesRequiredClaims(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 123_000_000).UTC()
	manager, err := NewAgentTokenManager(AgentTokenConfig{
		Issuer: "plainq-test", Audience: "plainq-agent", Secret: testAgentTokenSecret,
		Clock: func() time.Time { return now }, NextID: func() string { return "01J00000000000000000000099" },
	})
	if err != nil {
		t.Fatalf("NewAgentTokenManager() error = %v", err)
	}

	raw, expiresAt, err := manager.Issue(principal.Principal{
		Kind: principal.KindAgent, ID: "01J00000000000000000000001", TenantID: "tenant-a",
		Roles: []string{"agent"}, CredentialID: "01J00000000000000000000002", AuthVersion: 7,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if want := now.Truncate(time.Second).Add(DefaultAgentAccessTokenTTL); !expiresAt.Equal(want) {
		t.Fatalf("Issue() expiry = %v, want %v", expiresAt, want)
	}

	got, err := manager.Verify(raw)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got.Kind != principal.KindAgent || got.ID != "01J00000000000000000000001" ||
		got.TenantID != "tenant-a" || got.CredentialID != "01J00000000000000000000002" ||
		got.AuthVersion != 7 || got.TokenID != "01J00000000000000000000099" ||
		len(got.Roles) != 1 || got.Roles[0] != "agent" {
		t.Fatalf("Verify() principal = %#v", got)
	}
	if !got.ExpiresAt.Equal(time.Unix(expiresAt.Unix(), 0).UTC()) {
		t.Fatalf("Verify() expiry = %v, want JWT-second expiry %v", got.ExpiresAt, time.Unix(expiresAt.Unix(), 0).UTC())
	}
}

func TestAgentTokenVerificationRejectsInvalidClaimsAndSignature(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 500_000_000).UTC()
	manager, err := NewAgentTokenManager(AgentTokenConfig{
		Issuer: "plainq-test", Audience: "plainq-agent", Secret: testAgentTokenSecret,
		Clock: func() time.Time { return now }, NextID: func() string { return "01J00000000000000000000099" },
	})
	if err != nil {
		t.Fatalf("NewAgentTokenManager() error = %v", err)
	}

	valid := AgentTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: "01J00000000000000000000099", Audience: jwt.Audience{"plainq-agent"},
			Issuer: "plainq-test", Subject: "01J00000000000000000000001",
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now.Add(-time.Second)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
		},
		TenantID: "tenant-a", PrincipalKind: string(principal.KindAgent),
		CredentialID: "01J00000000000000000000002", AuthVersion: 1,
		TokenUse: AgentAccessTokenUse, Roles: []string{"agent"},
	}

	tests := map[string]func(*AgentTokenClaims){
		"wrong issuer":       func(c *AgentTokenClaims) { c.Issuer = "other" },
		"wrong audience":     func(c *AgentTokenClaims) { c.Audience = jwt.Audience{"other"} },
		"extra audience":     func(c *AgentTokenClaims) { c.Audience = jwt.Audience{"plainq-agent", "other"} },
		"expired":            func(c *AgentTokenClaims) { c.ExpiresAt = jwt.NewNumericDate(now) },
		"future not-before":  func(c *AgentTokenClaims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Minute)) },
		"future issued-at":   func(c *AgentTokenClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute)) },
		"wrong token use":    func(c *AgentTokenClaims) { c.TokenUse = "refresh" },
		"wrong kind":         func(c *AgentTokenClaims) { c.PrincipalKind = string(principal.KindHuman) },
		"missing subject":    func(c *AgentTokenClaims) { c.Subject = "" },
		"missing tenant":     func(c *AgentTokenClaims) { c.TenantID = "" },
		"missing credential": func(c *AgentTokenClaims) { c.CredentialID = "" },
		"missing JWT ID":     func(c *AgentTokenClaims) { c.ID = "" },
		"missing expiry":     func(c *AgentTokenClaims) { c.ExpiresAt = nil },
		"missing issued-at":  func(c *AgentTokenClaims) { c.IssuedAt = nil },
		"missing not-before": func(c *AgentTokenClaims) { c.NotBefore = nil },
		"zero auth version":  func(c *AgentTokenClaims) { c.AuthVersion = 0 },
		"missing agent role": func(c *AgentTokenClaims) { c.Roles = []string{"viewer"} },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims := valid
			claims.Audience = append(jwt.Audience(nil), valid.Audience...)
			claims.Roles = append([]string(nil), valid.Roles...)
			mutate(&claims)
			token, buildErr := manager.builder.Build(&claims)
			if buildErr != nil {
				t.Fatalf("build token: %v", buildErr)
			}
			_, verifyErr := manager.Verify(token.String())
			if !errors.Is(verifyErr, pqerr.ErrUnauthenticated) {
				t.Fatalf("Verify() error = %v, want %v", verifyErr, pqerr.ErrUnauthenticated)
			}
		})
	}

	other, err := NewAgentTokenManager(AgentTokenConfig{
		Issuer: "plainq-test", Audience: "plainq-agent",
		Secret: []byte("abcdef0123456789abcdef0123456789"), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new other manager: %v", err)
	}
	token, err := other.builder.Build(&valid)
	if err != nil {
		t.Fatalf("build other token: %v", err)
	}
	if _, err := manager.Verify(token.String()); !errors.Is(err, pqerr.ErrUnauthenticated) {
		t.Fatalf("Verify() wrong signature error = %v, want %v", err, pqerr.ErrUnauthenticated)
	}
}

func TestAgentTokenManagerValidatesConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]AgentTokenConfig{
		"missing issuer":   {Audience: "plainq-agent", Secret: testAgentTokenSecret},
		"missing audience": {Issuer: "plainq-test", Secret: testAgentTokenSecret},
		"short secret":     {Issuer: "plainq-test", Audience: "plainq-agent", Secret: []byte("short")},
		"negative TTL":     {Issuer: "plainq-test", Audience: "plainq-agent", Secret: testAgentTokenSecret, TTL: -time.Second},
	}
	for name, config := range tests {
		name, config := name, config
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewAgentTokenManager(config); err == nil {
				t.Fatal("NewAgentTokenManager() error = nil")
			}
		})
	}
}
