// Package security contains secret-safe agent authentication primitives.
package security

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
)

const (
	// DefaultAgentAccessTokenTTL is the short default lifetime for agent access tokens.
	DefaultAgentAccessTokenTTL = 5 * time.Minute
	// MaxAgentAccessTokenTTL is the immutable upper bound for agent access tokens.
	MaxAgentAccessTokenTTL = 15 * time.Minute
	// AgentAccessTokenUse distinguishes access tokens from other future token classes.
	AgentAccessTokenUse = "access"
)

// AgentTokenConfig configures signed agent access tokens.
type AgentTokenConfig struct {
	Issuer   string
	Audience string
	Secret   []byte
	TTL      time.Duration
	Clock    func() time.Time
	NextID   func() string
}

// AgentTokenClaims are the complete signed claims for an agent access token.
type AgentTokenClaims struct {
	jwt.RegisteredClaims
	TenantID      string   `json:"tenant_id"`
	PrincipalKind string   `json:"principal_kind"`
	CredentialID  string   `json:"credential_id"`
	AuthVersion   uint64   `json:"auth_version"`
	TokenUse      string   `json:"token_use"`
	Roles         []string `json:"roles"`
}

// AgentTokenIssuer issues short-lived agent access tokens.
type AgentTokenIssuer interface {
	Issue(p principal.Principal) (token string, expiresAt time.Time, err error)
}

// AgentTokenVerifier verifies signature and all required stateless token claims.
type AgentTokenVerifier interface {
	Verify(token string) (principal.Principal, error)
}

// AgentTokenManager issues and verifies agent access tokens.
type AgentTokenManager struct {
	issuer   string
	audience string
	ttl      time.Duration
	clock    func() time.Time
	nextID   func() string
	builder  *jwt.Builder
	verifier jwt.Verifier
}

type normalizedAgentTokenConfig struct {
	ttl    time.Duration
	clock  func() time.Time
	nextID func() string
}

var (
	_ AgentTokenIssuer   = (*AgentTokenManager)(nil)
	_ AgentTokenVerifier = (*AgentTokenManager)(nil)
)

// NewAgentTokenManager constructs an HS256 agent token manager.
func NewAgentTokenManager(config AgentTokenConfig) (*AgentTokenManager, error) {
	normalized, err := normalizeAgentTokenConfig(config)
	if err != nil {
		return nil, err
	}

	secret := append([]byte(nil), config.Secret...)

	signer, err := jwt.NewSignerHS(jwt.HS256, secret)
	if err != nil {
		return nil, fmt.Errorf("create agent token signer: %w", err)
	}

	verifier, err := jwt.NewVerifierHS(jwt.HS256, secret)
	if err != nil {
		return nil, fmt.Errorf("create agent token verifier: %w", err)
	}

	return &AgentTokenManager{
		issuer: config.Issuer, audience: config.Audience, ttl: normalized.ttl,
		clock: normalized.clock, nextID: normalized.nextID, builder: jwt.NewBuilder(signer), verifier: verifier,
	}, nil
}

func normalizeAgentTokenConfig(config AgentTokenConfig) (normalizedAgentTokenConfig, error) {
	if err := validateAgentTokenIdentityConfig(config); err != nil {
		return normalizedAgentTokenConfig{}, err
	}

	ttl := config.TTL
	if ttl == 0 {
		ttl = DefaultAgentAccessTokenTTL
	}

	if ttl < 0 || ttl > MaxAgentAccessTokenTTL {
		return normalizedAgentTokenConfig{}, fmt.Errorf(
			"agent access token TTL must be positive and at most %s",
			MaxAgentAccessTokenTTL,
		)
	}

	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	nextID := config.NextID
	if nextID == nil {
		nextID = idkit.ULID
	}

	return normalizedAgentTokenConfig{ttl: ttl, clock: clock, nextID: nextID}, nil
}

func validateAgentTokenIdentityConfig(config AgentTokenConfig) error {
	if config.Issuer == "" || strings.TrimSpace(config.Issuer) != config.Issuer {
		return errors.New("agent token issuer is required and cannot contain outer whitespace")
	}

	if config.Audience == "" || strings.TrimSpace(config.Audience) != config.Audience {
		return errors.New("agent token audience is required and cannot contain outer whitespace")
	}

	if len(config.Secret) < 32 {
		return errors.New("agent token secret must be at least 32 bytes")
	}

	return nil
}

// Issue signs an access token for an already authenticated agent principal.
func (m *AgentTokenManager) Issue(p principal.Principal) (string, time.Time, error) {
	if p.Kind != principal.KindAgent || p.ID == "" || p.TenantID == "" ||
		p.CredentialID == "" || p.AuthVersion == 0 || !hasOnlyAgentRole(p.Roles) {
		return "", time.Time{}, fmt.Errorf("issue agent token: %w", pqerr.ErrInvalidInput)
	}

	now := m.clock().UTC().Truncate(time.Second)
	expiresAt := now.Add(m.ttl)

	tokenID := m.nextID()
	if tokenID == "" {
		return "", time.Time{}, errors.New("issue agent token: empty JWT ID")
	}

	claims := AgentTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: tokenID, Audience: jwt.Audience{m.audience}, Issuer: m.issuer, Subject: p.ID,
			ExpiresAt: jwt.NewNumericDate(expiresAt), IssuedAt: jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		TenantID: p.TenantID, PrincipalKind: string(principal.KindAgent),
		CredentialID: p.CredentialID, AuthVersion: p.AuthVersion,
		TokenUse: AgentAccessTokenUse, Roles: []string{"agent"},
	}

	token, err := m.builder.Build(&claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build agent access token: %w", err)
	}

	return token.String(), expiresAt, nil
}

// Verify checks an access token's signature, purpose, audience, issuer, and time claims.
func (m *AgentTokenManager) Verify(raw string) (principal.Principal, error) {
	if raw == "" {
		return principal.Principal{}, pqerr.ErrUnauthenticated
	}

	var claims AgentTokenClaims
	if err := jwt.ParseClaims([]byte(raw), m.verifier, &claims); err != nil {
		return principal.Principal{}, pqerr.ErrUnauthenticated
	}

	now := m.clock().UTC()
	if !m.validClaims(&claims, now) {
		return principal.Principal{}, pqerr.ErrUnauthenticated
	}

	return principal.Principal{
		Kind: principal.KindAgent, ID: claims.Subject, TenantID: claims.TenantID,
		Roles: append([]string(nil), claims.Roles...), CredentialID: claims.CredentialID,
		AuthVersion: claims.AuthVersion, TokenID: claims.ID, ExpiresAt: claims.ExpiresAt.UTC(),
	}, nil
}

func (m *AgentTokenManager) validClaims(claims *AgentTokenClaims, now time.Time) bool {
	return requiredAgentClaims(claims) && m.validAgentIdentityClaims(claims) && validAgentTimeClaims(claims, now)
}

func requiredAgentClaims(claims *AgentTokenClaims) bool {
	if claims.ID == "" || claims.Subject == "" || claims.TenantID == "" ||
		claims.CredentialID == "" || claims.AuthVersion == 0 || claims.ExpiresAt == nil ||
		claims.IssuedAt == nil || claims.NotBefore == nil {
		return false
	}

	return true
}

func (m *AgentTokenManager) validAgentIdentityClaims(claims *AgentTokenClaims) bool {
	if !claims.IsIssuer(m.issuer) || len(claims.Audience) != 1 || !claims.IsForAudience(m.audience) ||
		claims.PrincipalKind != string(principal.KindAgent) || claims.TokenUse != AgentAccessTokenUse ||
		!hasOnlyAgentRole(claims.Roles) {
		return false
	}

	return true
}

func validAgentTimeClaims(claims *AgentTokenClaims, now time.Time) bool {
	if !claims.ExpiresAt.After(now) || claims.NotBefore.After(now) || claims.IssuedAt.After(now) {
		return false
	}

	return claims.ExpiresAt.After(claims.IssuedAt.Time)
}

func hasOnlyAgentRole(roles []string) bool {
	return len(roles) == 1 && roles[0] == "agent"
}
