package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marsolab/servekit/ctxkit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestCredentialIsReturnedOnceAndRevocationStopsExchange(t *testing.T) {
	t.Parallel()

	svc, store := newAgentServiceForTest(t)
	adminCtx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "admin-1", TenantID: "tenant-a", Roles: []string{"admin"},
	})

	created, err := svc.CreateAgent(adminCtx, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	credential, err := svc.CreateAgentCredential(adminCtx, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "runtime",
	})
	if err != nil {
		t.Fatalf("CreateAgentCredential() error = %v", err)
	}
	if matched := regexp.MustCompile(`^pqac_[0-9A-HJKMNP-TV-Z]{26}_[A-Za-z0-9_-]{43}$`).MatchString(credential.BootstrapCredential); !matched {
		t.Fatalf("bootstrap credential format = %q", credential.BootstrapCredential)
	}
	if strings.Contains(store.Dump(), credential.BootstrapCredential) {
		t.Fatal("store contains the clear bootstrap credential")
	}

	exchanged, err := svc.ExchangeAgentCredential(context.Background(), &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: credential.BootstrapCredential,
	})
	if err != nil {
		t.Fatalf("ExchangeAgentCredential() error = %v", err)
	}
	if exchanged.AccessToken == "" {
		t.Fatal("ExchangeAgentCredential() returned an empty access token")
	}

	_, err = svc.RevokeAgentCredential(adminCtx, &agentv1.RevokeAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialId: credential.CredentialId,
	})
	if err != nil {
		t.Fatalf("RevokeAgentCredential() error = %v", err)
	}
	_, err = svc.ExchangeAgentCredential(context.Background(), &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: credential.BootstrapCredential,
	})
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("exchange after revocation error = %v, want %v", err, ErrUnauthenticated)
	}
}

func TestRegistryAndCredentialMethodsRequireTenantAdmin(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	req := &agentv1.CreateAgentRequest{AgentName: "planner"}
	if _, err := svc.CreateAgent(context.Background(), req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("CreateAgent() anonymous error = %v, want %v", err, ErrUnauthenticated)
	}
	for name, p := range map[string]principal.Principal{
		"agent":           {Kind: principal.KindAgent, ID: "agent-1", TenantID: "tenant-a", Roles: []string{"agent"}},
		"non-admin human": {Kind: principal.KindHuman, ID: "human-1", TenantID: "tenant-a"},
	} {
		ctx := principal.With(context.Background(), p)
		if _, err := svc.CreateAgent(ctx, req); !errors.Is(err, ErrPermissionDenied) {
			t.Errorf("CreateAgent() %s error = %v, want %v", name, err, ErrPermissionDenied)
		}
	}
}

func TestExternalCredentialRegistrationIsCanonicalAndExchangeable(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	adminCtx := testAdminContext("tenant-a")
	created, err := svc.CreateAgent(adminCtx, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	credentialID := "01J00000000000000000000077"
	clear := "pqac_" + credentialID + "_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hash := sha256.Sum256([]byte(clear))
	req := &agentv1.RegisterAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialId: credentialID,
		CredentialName: "external", SecretSha256: hash[:],
	}
	first, err := svc.RegisterAgentCredential(adminCtx, req)
	if err != nil || first.AlreadyExisted {
		t.Fatalf("first RegisterAgentCredential() = %#v, %v", first, err)
	}
	second, err := svc.RegisterAgentCredential(adminCtx, req)
	if err != nil || !second.AlreadyExisted {
		t.Fatalf("repeat RegisterAgentCredential() = %#v, %v", second, err)
	}
	conflict := *req
	conflict.SecretSha256 = bytes.Repeat([]byte{9}, sha256.Size)
	if _, err := svc.RegisterAgentCredential(adminCtx, &conflict); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("conflicting RegisterAgentCredential() error = %v, want %v", err, ErrAlreadyExists)
	}
	exchanged, err := svc.ExchangeAgentCredential(context.Background(), &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: clear,
	})
	if err != nil || exchanged.AccessToken == "" {
		t.Fatalf("ExchangeAgentCredential() = %#v, %v", exchanged, err)
	}
}

func TestAgentAuthenticationRechecksCredentialStatusAgentStatusAndAuthVersion(t *testing.T) {
	t.Parallel()

	svc, store := newAgentServiceForTest(t)
	adminCtx := testAdminContext("tenant-a")
	created, err := svc.CreateAgent(adminCtx, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	first, err := svc.CreateAgentCredential(adminCtx, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "first",
	})
	if err != nil {
		t.Fatalf("create first credential: %v", err)
	}
	second, err := svc.CreateAgentCredential(adminCtx, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "second",
	})
	if err != nil {
		t.Fatalf("create second credential: %v", err)
	}
	firstToken := exchangeForTest(t, svc, first.BootstrapCredential)
	secondToken := exchangeForTest(t, svc, second.BootstrapCredential)
	if _, err := svc.Authenticate(context.Background(), firstToken); err != nil {
		t.Fatalf("authenticate first token: %v", err)
	}

	if _, err := svc.RevokeAgentCredential(adminCtx, &agentv1.RevokeAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialId: first.CredentialId,
	}); err != nil {
		t.Fatalf("revoke first credential: %v", err)
	}
	if _, err := svc.Authenticate(context.Background(), firstToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("authenticate revoked token error = %v, want %v", err, ErrUnauthenticated)
	}
	if _, err := svc.Authenticate(context.Background(), secondToken); err != nil {
		t.Fatalf("second rotation token was disrupted: %v", err)
	}

	if _, err := svc.SetAgentStatus(adminCtx, &agentv1.SetAgentStatusRequest{
		AgentId: created.Agent.AgentId, Status: agentv1.AgentStatus_AGENT_STATUS_DISABLED,
	}); err != nil {
		t.Fatalf("disable agent: %v", err)
	}
	if _, err := svc.Authenticate(context.Background(), secondToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("authenticate disabled agent error = %v, want %v", err, ErrUnauthenticated)
	}
	if _, err := svc.SetAgentStatus(adminCtx, &agentv1.SetAgentStatusRequest{
		AgentId: created.Agent.AgentId, Status: agentv1.AgentStatus_AGENT_STATUS_ACTIVE,
	}); err != nil {
		t.Fatalf("enable agent: %v", err)
	}
	store.BumpAuthVersion("tenant-a", created.Agent.AgentId)
	if _, err := svc.Authenticate(context.Background(), secondToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("authenticate stale auth version error = %v, want %v", err, ErrUnauthenticated)
	}
}

func TestAgentAuthenticationUsesPrincipalProjection(t *testing.T) {
	t.Parallel()

	svc, store := newAgentServiceForTest(t)
	adminCtx := testAdminContext("tenant-a")
	created, err := svc.CreateAgent(adminCtx, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	credential, err := svc.CreateAgentCredential(adminCtx, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "runtime",
	})
	if err != nil {
		t.Fatalf("CreateAgentCredential() error = %v", err)
	}
	token := exchangeForTest(t, svc, credential.BootstrapCredential)

	store.SetPrincipalStatusOnly("tenant-a", created.Agent.AgentId, agentv1.AgentStatus_AGENT_STATUS_DISABLED)
	if _, err := svc.Authenticate(context.Background(), token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate() disabled projection error = %v, want %v", err, ErrUnauthenticated)
	}

	store.SetPrincipalStatusOnly("tenant-a", created.Agent.AgentId, agentv1.AgentStatus_AGENT_STATUS_ACTIVE)
	store.BumpAuthVersion("tenant-a", created.Agent.AgentId)
	agentRecord, err := store.GetAgent(context.Background(), "tenant-a", created.Agent.AgentId)
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if agentRecord.Status != agentv1.AgentStatus_AGENT_STATUS_ACTIVE || agentRecord.AuthVersion != 1 {
		t.Fatalf("registry record changed with projection-only mutation: %#v", agentRecord)
	}
	if _, err := svc.Authenticate(context.Background(), token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate() stale projection auth version error = %v, want %v", err, ErrUnauthenticated)
	}
}

func TestStoreFailuresRemainUnavailableDuringCredentialAuthentication(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	adminCtx := testAdminContext("tenant-a")
	created, err := svc.CreateAgent(adminCtx, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	credential, err := svc.CreateAgentCredential(adminCtx, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "runtime",
	})
	if err != nil {
		t.Fatalf("CreateAgentCredential() error = %v", err)
	}
	token := exchangeForTest(t, svc, credential.BootstrapCredential)

	originalRegistry := svc.registry
	svc.registry = failingRegistryStore{RegistryStore: originalRegistry, err: pqerr.ErrUnavailable}
	transport, err := NewGRPCTransport(svc)
	if err != nil {
		t.Fatalf("NewGRPCTransport() error = %v", err)
	}
	if _, err := transport.ExchangeAgentCredential(context.Background(), &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: credential.BootstrapCredential,
	}); status.Code(err) != codes.Unavailable {
		t.Fatalf("ExchangeAgentCredential() status = %s, want %s", status.Code(err), codes.Unavailable)
	}
	svc.registry = originalRegistry

	originalCredentials := svc.credentials
	svc.credentials = failingCredentialStore{CredentialStore: originalCredentials, err: pqerr.ErrUnavailable}
	if _, err := transport.ExchangeAgentCredential(context.Background(), &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: credential.BootstrapCredential,
	}); status.Code(err) != codes.Unavailable {
		t.Fatalf("ExchangeAgentCredential() credential status = %s, want %s", status.Code(err), codes.Unavailable)
	}
	if _, err := svc.Authenticate(context.Background(), token); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("Authenticate() credential lookup error = %v, want %v", err, pqerr.ErrUnavailable)
	}
	svc.credentials = originalCredentials

	originalPrincipals := svc.principals
	svc.principals = failingPrincipalStore{PrincipalStore: originalPrincipals, err: pqerr.ErrUnavailable}
	if _, err := svc.Authenticate(context.Background(), token); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("Authenticate() principal lookup error = %v, want %v", err, pqerr.ErrUnavailable)
	}
}

func TestCredentialInputValidationAndCrossTenantHiding(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	adminA := testAdminContext("tenant-a")
	adminB := testAdminContext("tenant-b")
	created, err := svc.CreateAgent(adminA, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	if _, err := svc.GetAgent(adminB, &agentv1.GetAgentRequest{AgentId: created.Agent.AgentId}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant GetAgent() error = %v, want %v", err, ErrNotFound)
	}
	if _, err := svc.CreateAgentCredential(adminB, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "runtime",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant CreateAgentCredential() error = %v, want %v", err, ErrNotFound)
	}
	if _, err := svc.RegisterAgentCredential(adminA, &agentv1.RegisterAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialId: "not-a-ulid", CredentialName: "runtime",
		SecretSha256: make([]byte, 32),
	}); err == nil {
		t.Fatal("RegisterAgentCredential() accepted an invalid credential ID")
	}
	if _, err := svc.RegisterAgentCredential(adminA, &agentv1.RegisterAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialId: "01J00000000000000000000088", CredentialName: "runtime",
		SecretSha256: make([]byte, 31),
	}); err == nil {
		t.Fatal("RegisterAgentCredential() accepted a 31-byte hash")
	}
}

func TestGRPCTransportMapsAgentDomainErrors(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	transport, err := NewGRPCTransport(svc)
	if err != nil {
		t.Fatalf("NewGRPCTransport() error = %v", err)
	}
	var _ agentv1.AgentServiceServer = transport

	tests := map[string]struct {
		ctx  context.Context
		call func(context.Context) error
		want codes.Code
	}{
		"anonymous is unauthenticated": {
			ctx: context.Background(), want: codes.Unauthenticated,
			call: func(ctx context.Context) error {
				_, err := transport.CreateAgent(ctx, &agentv1.CreateAgentRequest{AgentName: "planner"})
				return err
			},
		},
		"agent is permission denied": {
			ctx: principal.With(context.Background(), principal.Principal{
				Kind: principal.KindAgent, ID: "agent-1", TenantID: "tenant-a", Roles: []string{"agent"},
			}),
			want: codes.PermissionDenied,
			call: func(ctx context.Context) error {
				_, err := transport.CreateAgent(ctx, &agentv1.CreateAgentRequest{AgentName: "planner"})
				return err
			},
		},
		"invalid name is invalid argument": {
			ctx: testAdminContext("tenant-a"), want: codes.InvalidArgument,
			call: func(ctx context.Context) error {
				_, err := transport.CreateAgent(ctx, &agentv1.CreateAgentRequest{AgentName: "Invalid"})
				return err
			},
		},
		"unknown credential is unauthenticated": {
			ctx: context.Background(), want: codes.Unauthenticated,
			call: func(ctx context.Context) error {
				_, err := transport.ExchangeAgentCredential(ctx, &agentv1.ExchangeAgentCredentialRequest{
					BootstrapCredential: "pqac_01J00000000000000000000077_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				})
				return err
			},
		},
	}
	for name, testCase := range tests {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := status.Code(testCase.call(testCase.ctx)); got != testCase.want {
				t.Fatalf("gRPC status = %s, want %s", got, testCase.want)
			}
		})
	}
}

func TestGRPCTransportHidesCrossTenantAgentAndMapsCredentialCap(t *testing.T) {
	t.Parallel()

	svc, _ := newAgentServiceForTest(t)
	transport, err := NewGRPCTransport(svc)
	if err != nil {
		t.Fatalf("NewGRPCTransport() error = %v", err)
	}
	adminA := testAdminContext("tenant-a")
	created, err := svc.CreateAgent(adminA, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	if _, err := transport.GetAgent(testAdminContext("tenant-b"), &agentv1.GetAgentRequest{
		AgentId: created.Agent.AgentId,
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-tenant GetAgent() status = %s, want %s", status.Code(err), codes.NotFound)
	}
	for _, name := range []string{"first", "second"} {
		if _, err := svc.CreateAgentCredential(adminA, &agentv1.CreateAgentCredentialRequest{
			AgentId: created.Agent.AgentId, CredentialName: name,
		}); err != nil {
			t.Fatalf("create %s credential: %v", name, err)
		}
	}
	if _, err := transport.CreateAgentCredential(adminA, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "third",
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("credential cap status = %s, want %s", status.Code(err), codes.FailedPrecondition)
	}
}

func TestCredentialExpiryPolicyAndRuntimeExpiry(t *testing.T) {
	t.Parallel()

	svc, store := newAgentServiceForTest(t)
	adminCtx := testAdminContext("tenant-a")
	created, err := svc.CreateAgent(adminCtx, &agentv1.CreateAgentRequest{AgentName: "planner"})
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	for name, expiry := range map[string]time.Time{
		"past":       store.now.Add(-time.Second),
		"policy cap": store.now.Add(24*time.Hour + time.Second),
	} {
		_, err := svc.CreateAgentCredential(adminCtx, &agentv1.CreateAgentCredentialRequest{
			AgentId: created.Agent.AgentId, CredentialName: name,
			ExpiresAt: timestamppb.New(expiry),
		})
		if err == nil {
			t.Errorf("CreateAgentCredential() accepted %s expiry", name)
		}
	}
	expiresAt := store.now.Add(time.Hour)
	credential, err := svc.CreateAgentCredential(adminCtx, &agentv1.CreateAgentCredentialRequest{
		AgentId: created.Agent.AgentId, CredentialName: "runtime", ExpiresAt: timestamppb.New(expiresAt),
	})
	if err != nil {
		t.Fatalf("CreateAgentCredential() valid expiry error = %v", err)
	}
	store.Advance(time.Hour + time.Second)
	if _, err := svc.ExchangeAgentCredential(context.Background(), &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: credential.BootstrapCredential,
	}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired ExchangeAgentCredential() error = %v, want %v", err, ErrUnauthenticated)
	}
}

func TestCredentialExchangeDoesNotLookupMalformedInputAndDoesNotLogSecrets(t *testing.T) {
	t.Parallel()

	svc, store := newAgentServiceForTest(t)
	transport, err := NewGRPCTransport(svc)
	if err != nil {
		t.Fatalf("NewGRPCTransport() error = %v", err)
	}
	clear := "pqac_not-a-credential"
	var logged error
	ctx := ctxkit.SetLogErrHook(context.Background(), func(err error) { logged = err })
	if _, err := transport.ExchangeAgentCredential(ctx, &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: clear,
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("malformed exchange status = %s, want %s", status.Code(err), codes.Unauthenticated)
	}
	if store.CredentialLookups() != 0 {
		t.Fatalf("malformed exchange storage lookups = %d, want 0", store.CredentialLookups())
	}
	if logged == nil {
		t.Fatal("transport error hook did not capture the mapped failure")
	}
	if strings.Contains(logged.Error(), "pqac_") || strings.Contains(logged.Error(), clear) {
		t.Fatalf("captured log error contains a bootstrap credential: %q", logged)
	}
}

func exchangeForTest(t *testing.T, svc *Service, clear string) string {
	t.Helper()
	response, err := svc.ExchangeAgentCredential(context.Background(), &agentv1.ExchangeAgentCredentialRequest{
		BootstrapCredential: clear,
	})
	if err != nil {
		t.Fatalf("exchange credential: %v", err)
	}
	return response.AccessToken
}

func testAdminContext(tenantID string) context.Context {
	return principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "admin-1", TenantID: tenantID, Roles: []string{"admin"},
	})
}

func newAgentServiceForTest(t *testing.T) (*Service, *memoryStore) {
	t.Helper()

	store := newMemoryStore()
	store.now = time.Unix(1_800_000_000, 123_000_000).UTC()
	tokens, err := security.NewAgentTokenManager(security.AgentTokenConfig{
		Issuer: "plainq-test", Audience: "plainq-agent",
		Secret: []byte("0123456789abcdef0123456789abcdef"),
		Clock:  func() time.Time { return store.now },
		NextID: func() string { return "01J00000000000000000000099" },
	})
	if err != nil {
		t.Fatalf("new token manager: %v", err)
	}
	ids := []string{
		"01J00000000000000000000001", "01J00000000000000000000002",
		"01J00000000000000000000003", "01J00000000000000000000004",
	}
	var idIndex int
	svc, err := NewService(ServiceConfig{
		Registry: store, Principals: store, Credentials: store, Tokens: tokens,
		Clock: func() time.Time { return store.now },
		NextID: func() string {
			id := ids[idIndex]
			idIndex++
			return id
		},
		Random:           bytes.NewReader(bytes.Repeat([]byte{7}, 32*len(ids))),
		MaxCredentialTTL: 24 * time.Hour,
		PreAuth:          PreAuthConfig{RequestsPerSecond: 1000, Burst: 1000, MaxEntries: 128},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return svc, store
}

type memoryStore struct {
	mu                 sync.Mutex
	now                time.Time
	agents             map[string]AgentRecord
	agentNames         map[string]string
	principalStatuses  map[string]agentv1.AgentStatus
	principalVersions  map[string]uint64
	credentialsByID    map[string]CredentialRecord
	credentialByPrefix map[string]string
	credentialLookups  int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		agents: make(map[string]AgentRecord), agentNames: make(map[string]string),
		principalStatuses: make(map[string]agentv1.AgentStatus), principalVersions: make(map[string]uint64),
		credentialsByID: make(map[string]CredentialRecord), credentialByPrefix: make(map[string]string),
	}
}

func memoryKey(tenantID, id string) string { return tenantID + "\x00" + id }

func (s *memoryStore) CreateAgent(_ context.Context, input CreateAgentInput) (AgentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryKey(input.TenantID, input.AgentID)
	nameKey := memoryKey(input.TenantID, input.Name)
	if _, exists := s.agents[key]; exists || s.agentNames[nameKey] != "" {
		return AgentRecord{}, ErrAlreadyExists
	}
	record := AgentRecord{
		AgentID: input.AgentID, TenantID: input.TenantID, Name: input.Name, Status: input.Status,
		AuthVersion: input.AuthVersion, CreatedAt: input.CreatedAt, UpdatedAt: input.UpdatedAt,
	}
	s.agents[key] = record
	s.agentNames[nameKey] = input.AgentID
	s.principalStatuses[key] = input.Status
	s.principalVersions[key] = input.AuthVersion
	return record, nil
}

func (s *memoryStore) GetAgent(_ context.Context, tenantID, agentID string) (AgentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.agents[memoryKey(tenantID, agentID)]
	if !ok {
		return AgentRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *memoryStore) GetAgentPrincipal(
	_ context.Context,
	tenantID string,
	agentID string,
) (AgentPrincipalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryKey(tenantID, agentID)
	status, ok := s.principalStatuses[key]
	if !ok {
		return AgentPrincipalRecord{}, ErrNotFound
	}

	return AgentPrincipalRecord{
		AgentID: agentID, TenantID: tenantID, Status: status, AuthVersion: s.principalVersions[key],
	}, nil
}

func (s *memoryStore) GetAgentByName(_ context.Context, tenantID, name string) (AgentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.agentNames[memoryKey(tenantID, name)]
	record, ok := s.agents[memoryKey(tenantID, id)]
	if !ok {
		return AgentRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *memoryStore) ListAgents(_ context.Context, input ListAgentsInput) (ListAgentsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]AgentRecord, 0)
	for _, record := range s.agents {
		if record.TenantID == input.TenantID && strings.HasPrefix(record.Name, input.NamePrefix) {
			all = append(all, record)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Name == all[j].Name {
			return all[i].AgentID < all[j].AgentID
		}
		return all[i].Name < all[j].Name
	})
	filtered := all[:0]
	for _, record := range all {
		if input.AfterName == "" || record.Name > input.AfterName ||
			(record.Name == input.AfterName && record.AgentID > input.AfterID) {
			filtered = append(filtered, record)
		}
	}
	result := ListAgentsResult{Agents: filtered, TotalCount: uint64(len(all))}
	if len(result.Agents) > int(input.Limit) {
		result.HasMore = true
		result.Agents = result.Agents[:input.Limit]
		last := result.Agents[len(result.Agents)-1]
		result.NextCursor = last.Name + "\x00" + last.AgentID
	}
	return result, nil
}

func (s *memoryStore) SetAgentStatus(_ context.Context, input SetAgentStatusInput) (AgentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryKey(input.TenantID, input.AgentID)
	record, ok := s.agents[key]
	if !ok {
		return AgentRecord{}, ErrNotFound
	}
	record.Status = input.Status
	record.UpdatedAt = input.UpdatedAt
	if input.Status == agentv1.AgentStatus_AGENT_STATUS_DISABLED {
		value := input.UpdatedAt
		record.DisabledAt = &value
	} else {
		record.DisabledAt = nil
	}
	s.agents[key] = record
	s.principalStatuses[key] = input.Status
	return record, nil
}

func (s *memoryStore) CreateCredential(_ context.Context, input CreateCredentialInput) (CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentialsByID[input.CredentialID]; exists {
		return CredentialRecord{}, ErrAlreadyExists
	}
	active := 0
	for _, record := range s.credentialsByID {
		if record.TenantID == input.TenantID && record.AgentID == input.AgentID && credentialActive(record, input.CreatedAt) {
			active++
		}
	}
	if active >= int(DefaultMaxActiveCredentials) {
		return CredentialRecord{}, ErrFailedPrecondition
	}
	record := CredentialRecord{
		CredentialID: input.CredentialID, TenantID: input.TenantID, AgentID: input.AgentID,
		Name: input.Name, Prefix: input.Prefix, SecretHash: append([]byte(nil), input.SecretHash[:]...),
		CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt,
	}
	s.credentialsByID[input.CredentialID] = record
	s.credentialByPrefix[input.Prefix] = input.CredentialID
	return record, nil
}

func (s *memoryStore) RegisterCredential(ctx context.Context, input RegisterCredentialInput) (RegisterCredentialResult, error) {
	s.mu.Lock()
	if existing, ok := s.credentialsByID[input.CredentialID]; ok {
		same := existing.TenantID == input.TenantID && existing.AgentID == input.AgentID &&
			existing.Name == input.Name && existing.Prefix == input.Prefix &&
			bytes.Equal(existing.SecretHash, input.SecretHash[:]) && testTimesEqual(existing.ExpiresAt, input.ExpiresAt)
		s.mu.Unlock()
		if !same {
			return RegisterCredentialResult{}, ErrAlreadyExists
		}
		return RegisterCredentialResult{Credential: existing, AlreadyExisted: true}, nil
	}
	s.mu.Unlock()
	record, err := s.CreateCredential(ctx, CreateCredentialInput(input))
	return RegisterCredentialResult{Credential: record}, err
}

func (s *memoryStore) ListCredentials(_ context.Context, input ListCredentialsInput) (ListCredentialsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]CredentialRecord, 0)
	for _, record := range s.credentialsByID {
		if record.TenantID == input.TenantID && record.AgentID == input.AgentID && record.CredentialID > input.AfterID {
			items = append(items, record)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CredentialID < items[j].CredentialID })
	result := ListCredentialsResult{Credentials: items}
	if len(items) > int(input.Limit) {
		result.HasMore = true
		result.Credentials = items[:input.Limit]
		result.NextCursor = result.Credentials[len(result.Credentials)-1].CredentialID
	}
	return result, nil
}

func (s *memoryStore) GetCredentialByPrefix(_ context.Context, prefix string) (CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentialLookups++
	id := s.credentialByPrefix[prefix]
	record, ok := s.credentialsByID[id]
	if !ok {
		return CredentialRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *memoryStore) CredentialLookups() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.credentialLookups
}

func (s *memoryStore) RevokeCredential(_ context.Context, input RevokeCredentialInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentialsByID[input.CredentialID]
	if !ok || record.TenantID != input.TenantID || record.AgentID != input.AgentID {
		return ErrNotFound
	}
	if record.RevokedAt == nil {
		value := input.RevokedAt
		record.RevokedAt = &value
		s.credentialsByID[input.CredentialID] = record
	}
	return nil
}

func (s *memoryStore) TouchCredential(_ context.Context, input TouchCredentialInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentialsByID[input.CredentialID]
	if !ok || record.TenantID != input.TenantID || record.AgentID != input.AgentID || !credentialActive(record, input.UsedAt) {
		return ErrUnauthenticated
	}
	value := input.UsedAt
	record.LastUsedAt = &value
	s.credentialsByID[input.CredentialID] = record
	return nil
}

func (s *memoryStore) Dump() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var builder strings.Builder
	for _, record := range s.credentialsByID {
		_, _ = fmt.Fprintf(&builder, "%s:%x", record.Prefix, record.SecretHash)
	}
	return builder.String()
}

func (s *memoryStore) BumpAuthVersion(tenantID, agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryKey(tenantID, agentID)
	s.principalVersions[key]++
}

func (s *memoryStore) SetPrincipalStatusOnly(tenantID, agentID string, status agentv1.AgentStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principalStatuses[memoryKey(tenantID, agentID)] = status
}

func (s *memoryStore) Advance(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(duration)
}

func testTimesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

type failingRegistryStore struct {
	RegistryStore
	err error
}

func (s failingRegistryStore) GetAgent(context.Context, string, string) (AgentRecord, error) {
	return AgentRecord{}, s.err
}

type failingCredentialStore struct {
	CredentialStore
	err error
}

func (s failingCredentialStore) GetCredentialByPrefix(context.Context, string) (CredentialRecord, error) {
	return CredentialRecord{}, s.err
}

type failingPrincipalStore struct {
	PrincipalStore
	err error
}

func (s failingPrincipalStore) GetAgentPrincipal(context.Context, string, string) (AgentPrincipalRecord, error) {
	return AgentPrincipalRecord{}, s.err
}
