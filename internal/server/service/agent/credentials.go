package agent

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
)

const credentialPrefixMarker = "pqac_"

var dummyCredentialHash = sha256.Sum256([]byte("plainq-agent-credential-dummy-hash"))

type issuedBootstrapCredential struct {
	raw    string
	prefix string
	hash   [sha256.Size]byte
}

type parsedBootstrapCredential struct {
	prefix string
	hash   [sha256.Size]byte
}

// PreAuthConfig bounds public bootstrap credential exchange attempts and memory use.
type PreAuthConfig struct {
	RequestsPerSecond float64
	Burst             int
	MaxEntries        int
}

func issueBootstrapCredential(
	credentialID string,
	random io.Reader,
) (issuedBootstrapCredential, error) {
	if err := validateULID(credentialID, "credential ID"); err != nil {
		return issuedBootstrapCredential{}, err
	}

	var secret [32]byte
	if _, err := io.ReadFull(random, secret[:]); err != nil {
		return issuedBootstrapCredential{}, fmt.Errorf("read credential entropy: %w", err)
	}

	prefix := credentialPrefixMarker + credentialID
	rawCredential := prefix + "_" + base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(rawCredential))

	return issuedBootstrapCredential{raw: rawCredential, prefix: prefix, hash: hash}, nil
}

func parseBootstrapCredential(rawCredential string) (parsedBootstrapCredential, error) {
	rest, ok := strings.CutPrefix(rawCredential, credentialPrefixMarker)
	if !ok {
		return parsedBootstrapCredential{}, ErrUnauthenticated
	}

	credentialID, secret, ok := strings.Cut(rest, "_")
	if !ok || len(credentialID) != 26 || len(secret) != 43 {
		return parsedBootstrapCredential{}, ErrUnauthenticated
	}

	if err := validateULID(credentialID, "credential ID"); err != nil {
		return parsedBootstrapCredential{}, ErrUnauthenticated
	}

	decoded, decodeErr := base64.RawURLEncoding.DecodeString(secret)
	if decodeErr != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != secret {
		return parsedBootstrapCredential{}, ErrUnauthenticated
	}

	prefix := credentialPrefixMarker + credentialID
	hash := sha256.Sum256([]byte(rawCredential))

	return parsedBootstrapCredential{prefix: prefix, hash: hash}, nil
}

// CreateAgentCredential issues a high-entropy bootstrap credential exactly once.
//
//nolint:cyclop // Credential issuance keeps validation, authorization, hashing, and one-time response handling explicit.
func (s *Service) CreateAgentCredential(
	ctx context.Context,
	req *agentv1.CreateAgentCredentialRequest,
) (*agentv1.CreateAgentCredentialResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, invalidInput("create credential request is required")
	}

	if err := validateULID(req.GetAgentId(), "agent ID"); err != nil {
		return nil, err
	}

	name, err := validateCredentialName(req.GetCredentialName())
	if err != nil {
		return nil, err
	}

	now := s.clock().UTC()

	expiresAt, err := validateExpiry(req.GetExpiresAt(), now, s.maxCredentialTTL)
	if err != nil {
		return nil, err
	}

	if _, err := s.registry.GetAgent(ctx, p.TenantID, req.GetAgentId()); err != nil {
		return nil, fmt.Errorf("get agent for credential creation: %w", err)
	}

	credentialID := s.nextID()
	if err := validateULID(credentialID, "generated credential ID"); err != nil {
		return nil, fmt.Errorf("generate credential ID: %w", err)
	}

	issued, err := issueBootstrapCredential(credentialID, s.random)
	if err != nil {
		return nil, fmt.Errorf("create agent credential: %w", err)
	}

	policy, err := s.mutationFor(ctx, p, authz.ActionCredentialCreate, authz.Resource{
		Type: authz.ResourceAgent, TenantID: p.TenantID, ID: req.GetAgentId(),
	}, req, now, nil)
	if err != nil {
		return nil, fmt.Errorf("build create credential policy: %w", err)
	}

	policy = bindMutationToGeneratedSecret(policy, credentialID)

	record, err := s.credentials.CreateCredential(ctx, CreateCredentialInput{
		CredentialID: credentialID, TenantID: p.TenantID, AgentID: req.GetAgentId(),
		Name: name, Prefix: issued.prefix, SecretHash: issued.hash, CreatedAt: now, ExpiresAt: expiresAt,
		Policy: policy,
	})
	if err != nil {
		return nil, fmt.Errorf("create agent credential: %w", err)
	}

	return &agentv1.CreateAgentCredentialResponse{
		CredentialId: record.CredentialID, BootstrapCredential: issued.raw,
		CreatedAt: timestamppb.New(record.CreatedAt), ExpiresAt: protoTime(record.ExpiresAt),
	}, nil
}

// ListAgentCredentials lists hash-only lifecycle metadata for one tenant-owned agent.
func (s *Service) ListAgentCredentials(
	ctx context.Context,
	req *agentv1.ListAgentCredentialsRequest,
) (*agentv1.ListAgentCredentialsResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, invalidInput("list credentials request is required")
	}

	if err := validateULID(req.GetAgentId(), "agent ID"); err != nil {
		return nil, err
	}

	if err := validateCredentialCursor(req.GetCursor()); err != nil {
		return nil, err
	}

	limit, err := pageSize(req.GetLimit())
	if err != nil {
		return nil, err
	}

	if _, err := s.registry.GetAgent(ctx, p.TenantID, req.GetAgentId()); err != nil {
		return nil, fmt.Errorf("get agent for credential list: %w", err)
	}

	page, err := s.credentials.ListCredentials(ctx, ListCredentialsInput{
		TenantID: p.TenantID, AgentID: req.GetAgentId(), AfterID: req.GetCursor(), Limit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list agent credentials: %w", err)
	}

	credentials := make([]*agentv1.AgentCredential, 0, len(page.Credentials))
	for _, record := range page.Credentials {
		credentials = append(credentials, toProtoCredential(record))
	}

	return &agentv1.ListAgentCredentialsResponse{
		Credentials: credentials, NextCursor: page.NextCursor, HasMore: page.HasMore,
	}, nil
}

// RegisterAgentCredential idempotently installs an externally generated SHA-256 credential hash.
//
//nolint:cyclop // Registration keeps validation, authorization, hashing, and idempotency checks explicit.
func (s *Service) RegisterAgentCredential(
	ctx context.Context,
	req *agentv1.RegisterAgentCredentialRequest,
) (*agentv1.RegisterAgentCredentialResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, invalidInput("register credential request is required")
	}

	if err := validateULID(req.GetAgentId(), "agent ID"); err != nil {
		return nil, err
	}

	if err := validateULID(req.GetCredentialId(), "credential ID"); err != nil {
		return nil, err
	}

	name, err := validateCredentialName(req.GetCredentialName())
	if err != nil {
		return nil, err
	}

	if len(req.GetSecretSha256()) != sha256.Size {
		return nil, invalidInput("credential hash must be exactly 32 bytes")
	}

	now := s.clock().UTC()

	expiresAt, err := validateExpiry(req.GetExpiresAt(), now, s.maxCredentialTTL)
	if err != nil {
		return nil, err
	}

	if _, err := s.registry.GetAgent(ctx, p.TenantID, req.GetAgentId()); err != nil {
		return nil, fmt.Errorf("get agent for credential registration: %w", err)
	}

	var hash [sha256.Size]byte
	copy(hash[:], req.GetSecretSha256())

	policy, err := s.mutationFor(ctx, p, authz.ActionCredentialRegister, authz.Resource{
		Type: authz.ResourceAgent, TenantID: p.TenantID, ID: req.GetAgentId(),
	}, req, now, nil)
	if err != nil {
		return nil, fmt.Errorf("build register credential policy: %w", err)
	}

	result, err := s.credentials.RegisterCredential(ctx, RegisterCredentialInput{
		CredentialID: req.GetCredentialId(), TenantID: p.TenantID, AgentID: req.GetAgentId(),
		Name: name, Prefix: credentialPrefixMarker + req.GetCredentialId(), SecretHash: hash,
		CreatedAt: now, ExpiresAt: expiresAt,
		Policy: policy,
	})
	if err != nil {
		return nil, fmt.Errorf("register agent credential: %w", err)
	}

	return &agentv1.RegisterAgentCredentialResponse{
		CredentialId: result.Credential.CredentialID, CreatedAt: timestamppb.New(result.Credential.CreatedAt),
		AlreadyExisted: result.AlreadyExisted, ExpiresAt: protoTime(result.Credential.ExpiresAt),
	}, nil
}

// RevokeAgentCredential immediately invalidates bootstrap exchange and access tokens for one credential.
func (s *Service) RevokeAgentCredential(
	ctx context.Context,
	req *agentv1.RevokeAgentCredentialRequest,
) (*agentv1.RevokeAgentCredentialResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, invalidInput("revoke credential request is required")
	}

	if err := validateULID(req.GetAgentId(), "agent ID"); err != nil {
		return nil, err
	}

	if err := validateULID(req.GetCredentialId(), "credential ID"); err != nil {
		return nil, err
	}

	if _, err := s.registry.GetAgent(ctx, p.TenantID, req.GetAgentId()); err != nil {
		return nil, fmt.Errorf("get agent for credential revocation: %w", err)
	}

	now := s.clock().UTC()

	policy, err := s.mutationFor(ctx, p, authz.ActionCredentialRevoke, authz.Resource{
		Type: authz.ResourceAgent, TenantID: p.TenantID, ID: req.GetAgentId(),
	}, req, now, nil)
	if err != nil {
		return nil, fmt.Errorf("build revoke credential policy: %w", err)
	}

	if err := s.credentials.RevokeCredential(ctx, RevokeCredentialInput{
		TenantID: p.TenantID, AgentID: req.GetAgentId(), CredentialID: req.GetCredentialId(),
		RevokedAt: now, Policy: policy,
	}); err != nil {
		return nil, fmt.Errorf("revoke agent credential: %w", err)
	}

	return &agentv1.RevokeAgentCredentialResponse{}, nil
}

// ExchangeAgentCredential verifies a bootstrap credential and returns a short-lived access token.
func (s *Service) ExchangeAgentCredential(
	ctx context.Context,
	req *agentv1.ExchangeAgentCredentialRequest,
) (*agentv1.ExchangeAgentCredentialResponse, error) {
	admitted, err := s.admitCredentialExchange(ctx, req)
	if err != nil {
		return nil, err
	}

	record, err := s.verifiedCredential(ctx, admitted.prefix, admitted.hash)
	if err != nil {
		return nil, err
	}

	agentRecord, err := s.activeCredentialAgent(ctx, record)
	if err != nil {
		return nil, err
	}

	now := s.clock().UTC()
	actor := principal.Principal{
		Kind: principal.KindAgent, ID: record.AgentID, TenantID: record.TenantID,
		Roles: []string{"agent"}, CredentialID: record.CredentialID, AuthVersion: agentRecord.AuthVersion,
	}

	policy, err := s.mutationFor(ctx, actor, authz.ActionCredentialExchange, authz.Resource{
		Type: authz.ResourceAgent, TenantID: record.TenantID, ID: record.AgentID,
		OwnerKind: principal.KindAgent, OwnerID: record.AgentID,
	}, req, now, nil)
	if err != nil {
		return nil, fmt.Errorf("build credential exchange policy: %w", err)
	}

	if err := s.credentials.TouchCredential(ctx, TouchCredentialInput{
		TenantID: record.TenantID, AgentID: record.AgentID, CredentialID: record.CredentialID, UsedAt: now,
		Policy: policy,
	}); err != nil {
		if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrNotFound) {
			return nil, ErrUnauthenticated
		}

		return nil, fmt.Errorf("touch agent credential: %w", err)
	}

	accessToken, expiresAt, err := s.tokens.Issue(principal.Principal{
		Kind: principal.KindAgent, ID: record.AgentID, TenantID: record.TenantID,
		Roles: []string{"agent"}, CredentialID: record.CredentialID, AuthVersion: agentRecord.AuthVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("issue agent access token: %w", err)
	}

	return &agentv1.ExchangeAgentCredentialResponse{
		AccessToken: accessToken, ExpiresAt: timestamppb.New(expiresAt), Agent: toProtoAgent(agentRecord),
	}, nil
}

func (s *Service) admitCredentialExchange(
	ctx context.Context,
	req *agentv1.ExchangeAgentCredentialRequest,
) (parsedBootstrapCredential, error) {
	if req == nil {
		s.preAuth.allow("ip:"+sourceIP(ctx), "credential:invalid")

		return parsedBootstrapCredential{}, ErrUnauthenticated
	}

	parsed, parseErr := parseBootstrapCredential(req.GetBootstrapCredential())

	limitPrefix := parsed.prefix
	if parseErr != nil {
		limitPrefix = "invalid"
	}

	if !s.preAuth.allow("ip:"+sourceIP(ctx), "credential:"+limitPrefix) || parseErr != nil {
		return parsedBootstrapCredential{}, ErrUnauthenticated
	}

	return parsed, nil
}

func (s *Service) verifiedCredential(
	ctx context.Context,
	prefix string,
	computedHash [sha256.Size]byte,
) (CredentialRecord, error) {
	record, err := s.credentials.GetCredentialByPrefix(ctx, prefix)
	if err != nil {
		_ = subtle.ConstantTimeCompare(dummyCredentialHash[:], computedHash[:])

		if errors.Is(err, ErrNotFound) {
			return CredentialRecord{}, ErrUnauthenticated
		}

		return CredentialRecord{}, fmt.Errorf("lookup agent credential: %w", err)
	}

	storedHash := record.SecretHash
	if len(storedHash) != sha256.Size {
		storedHash = dummyCredentialHash[:]
	}

	if subtle.ConstantTimeCompare(storedHash, computedHash[:]) != 1 || !credentialActive(record, s.clock().UTC()) {
		return CredentialRecord{}, ErrUnauthenticated
	}

	return record, nil
}

func (s *Service) activeCredentialAgent(ctx context.Context, record CredentialRecord) (AgentRecord, error) {
	agentRecord, err := s.registry.GetAgent(ctx, record.TenantID, record.AgentID)
	if errors.Is(err, ErrNotFound) {
		return AgentRecord{}, ErrUnauthenticated
	}

	if err != nil {
		return AgentRecord{}, fmt.Errorf("lookup credential agent: %w", err)
	}

	if agentRecord.Status != agentv1.AgentStatus_AGENT_STATUS_ACTIVE {
		return AgentRecord{}, ErrUnauthenticated
	}

	return agentRecord, nil
}

// Authenticate verifies stateless token claims and current credential and agent state.
//
//nolint:cyclop // Token, credential, agent, and live-version checks intentionally fail closed independently.
func (s *Service) Authenticate(ctx context.Context, raw string) (principal.Principal, error) {
	p, err := s.tokens.Verify(raw)
	if err != nil {
		return principal.Principal{}, ErrUnauthenticated
	}

	record, err := s.credentials.GetCredentialByPrefix(ctx, credentialPrefixMarker+p.CredentialID)
	if errors.Is(err, ErrNotFound) {
		return principal.Principal{}, ErrUnauthenticated
	}

	if err != nil {
		return principal.Principal{}, fmt.Errorf("lookup token credential: %w", err)
	}

	if record.TenantID != p.TenantID || record.AgentID != p.ID ||
		record.CredentialID != p.CredentialID || !credentialActive(record, s.clock().UTC()) {
		return principal.Principal{}, ErrUnauthenticated
	}

	projection, err := s.principals.GetAgentPrincipal(ctx, p.TenantID, p.ID)
	if errors.Is(err, ErrNotFound) {
		return principal.Principal{}, ErrUnauthenticated
	}

	if err != nil {
		return principal.Principal{}, fmt.Errorf("lookup token principal: %w", err)
	}

	if projection.TenantID != p.TenantID || projection.AgentID != p.ID ||
		projection.Status != agentv1.AgentStatus_AGENT_STATUS_ACTIVE || projection.AuthVersion != p.AuthVersion {
		return principal.Principal{}, ErrUnauthenticated
	}

	return p, nil
}

func credentialActive(record CredentialRecord, now time.Time) bool {
	if record.RevokedAt != nil || record.ExpiredAccountedAt != nil {
		return false
	}

	return record.ExpiresAt == nil || record.ExpiresAt.After(now)
}

func toProtoCredential(record CredentialRecord) *agentv1.AgentCredential {
	return &agentv1.AgentCredential{
		CredentialId: record.CredentialID, CredentialName: record.Name,
		CreatedAt: timestamppb.New(record.CreatedAt), ExpiresAt: protoTime(record.ExpiresAt),
		LastUsedAt: protoTime(record.LastUsedAt), RevokedAt: protoTime(record.RevokedAt),
	}
}

func protoTime(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}

	return timestamppb.New(value.UTC())
}

type preAuthLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxEntries int
	clock      func() time.Time
	entries    map[string]*preAuthEntry
	lru        *list.List
}

type preAuthEntry struct {
	key     string
	tokens  float64
	last    time.Time
	element *list.Element
}

func newPreAuthLimiter(config PreAuthConfig, clock func() time.Time) (*preAuthLimiter, error) {
	if config.RequestsPerSecond == 0 {
		config.RequestsPerSecond = 5
	}

	if config.Burst == 0 {
		config.Burst = 10
	}

	if config.MaxEntries == 0 {
		config.MaxEntries = 4096
	}

	if config.RequestsPerSecond <= 0 || math.IsNaN(config.RequestsPerSecond) || math.IsInf(config.RequestsPerSecond, 0) ||
		config.Burst < 1 || config.MaxEntries < 2 {
		return nil, errors.New("pre-auth limiter requires positive rate, burst, and at least two entries")
	}

	return &preAuthLimiter{
		rate: config.RequestsPerSecond, burst: float64(config.Burst), maxEntries: config.MaxEntries,
		clock: clock, entries: make(map[string]*preAuthEntry, config.MaxEntries), lru: list.New(),
	}, nil
}

func (l *preAuthLimiter) allow(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock().UTC()
	unique := make(map[string]struct{}, len(keys))

	entries := make([]*preAuthEntry, 0, len(keys))
	for _, key := range keys {
		if _, exists := unique[key]; exists {
			continue
		}

		unique[key] = struct{}{}

		entry := l.entry(key, now)

		elapsed := now.Sub(entry.last).Seconds()
		if elapsed > 0 {
			entry.tokens = min(l.burst, entry.tokens+elapsed*l.rate)
			entry.last = now
		}

		l.lru.MoveToFront(entry.element)
		entries = append(entries, entry)
	}

	for _, entry := range entries {
		if entry.tokens < 1 {
			return false
		}
	}

	for _, entry := range entries {
		entry.tokens--
	}

	return true
}

func (l *preAuthLimiter) entry(key string, now time.Time) *preAuthEntry {
	if entry, ok := l.entries[key]; ok {
		return entry
	}

	if len(l.entries) >= l.maxEntries {
		oldest := l.lru.Back()
		if oldest != nil {
			if entry, ok := oldest.Value.(*preAuthEntry); ok {
				delete(l.entries, entry.key)
			}

			l.lru.Remove(oldest)
		}
	}

	entry := &preAuthEntry{key: key, tokens: l.burst, last: now}
	entry.element = l.lru.PushFront(entry)
	l.entries[key] = entry

	return entry
}

func sourceIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}

	if tcp, ok := p.Addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}

	host, _, err := net.SplitHostPort(p.Addr.String())
	if err == nil && host != "" {
		return host
	}

	return p.Addr.String()
}
