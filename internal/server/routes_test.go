package server

import (
	"context"
	"testing"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/interceptor"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
	"github.com/marsolab/servekit/logkit"
	"github.com/maxatome/go-testdeep/td"
	"google.golang.org/grpc"
)

// healthCheckerStub satisfies the health-check dependency NewServer takes.
type healthCheckerStub struct{}

func (healthCheckerStub) Health(context.Context) error { return nil }

// Storage stubs. Each embeds the interface it stands in for, which satisfies
// the contract without implementing it — building the route tree never calls
// a storage method, and a test that did would panic loudly rather than
// silently pass.
type (
	queueStorageStub      struct{ queue.Storage }
	accountStorageStub    struct{ account.Storage }
	onboardingStorageStub struct{ onboarding.Storage }
	rbacStorageStub       struct{ rbac.Storage }
	oauthStorageStub      struct{ oauth.Storage }
)

type grpcMountStub struct{}

func (grpcMountStub) Mount(*grpc.Server) {}

type grpcAuthenticatorStub struct{}

func (grpcAuthenticatorStub) Authenticate(context.Context, string) (principal.Principal, error) {
	return principal.Principal{Kind: principal.KindAgent, ID: "agent-a", TenantID: "tenant-a"}, nil
}

type grpcResourceStub struct{}

func (grpcResourceStub) ResolveResource(
	context.Context,
	string,
	interceptor.ResourceSelector,
) (interceptor.Resource, error) {
	return interceptor.Resource{ID: "agent-a", OwnerAgentID: "agent-a"}, nil
}

func (grpcResourceStub) HasGrant(context.Context, interceptor.GrantCheck) (bool, error) {
	return true, nil
}

// Test_NewServer_mountsRoutes builds the whole route tree the way the binary
// does, in both telemetry modes.
//
// chi panics at *mount* time rather than request time when two blocks claim
// the same path, so a routing mistake takes the server down on start-up while
// every handler test still passes. That is not hypothetical: splitting the
// Prometheus catalog into its own `/metrics` block left two
// `Route("/metrics")` calls at the same level, and the entire suite stayed
// green against a binary that could not boot.
//
// Both telemetry modes are built because they take different branches —
// without a telemetry store the dashboard routes are skipped and only the
// catalog is mounted.
func Test_NewServer_mountsRoutes(t *testing.T) {
	cases := map[string]bool{
		"with telemetry":    true,
		"without telemetry": false,
	}

	for name, withTelemetry := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.Config{
				// Port zero, so two subtests never fight over an address.
				HTTPAddr:      "127.0.0.1:0",
				GRPCAddr:      "127.0.0.1:0",
				MetricsEnable: true,
				MetricsRoute:  "/metrics",
				HealthEnable:  true,
				HealthRoute:   "/health",
			}

			logger := logkit.NewNop()

			opts := []Option{}
			if withTelemetry {
				opts = append(opts, withCollectorForTest())
			}

			// A panic here is the failure being guarded against; without this
			// test it surfaces only when someone runs the binary.
			_, err := NewServer(
				&cfg,
				logger,
				healthCheckerStub{},
				nil,
				queue.NewService(&cfg, logger, queueStorageStub{}),
				account.NewService(&cfg, logger, nil, nil, accountStorageStub{}),
				onboarding.NewService(&cfg, logger, nil, nil, onboardingStorageStub{}),
				rbac.NewService(&cfg, logger, rbacStorageStub{}),
				oauth.NewService(&cfg, logger, oauthStorageStub{}),
				opts...,
			)

			td.CmpNoError(t, err, "the route tree must build")
		})
	}
}

func TestNewServerMountsAgentTransportOnlyWithCompleteSecurityDependencies(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		HTTPAddr: "127.0.0.1:0", GRPCAddr: "127.0.0.1:0",
		AgentEnable: true, AgentDevelopmentInsecureTransport: true,
	}
	logger := logkit.NewNop()
	queueService := queue.NewService(&cfg, logger, queueStorageStub{})
	accountService := account.NewService(&cfg, logger, nil, nil, accountStorageStub{})
	onboardingService := onboarding.NewService(&cfg, logger, nil, nil, onboardingStorageStub{})
	rbacService := rbac.NewService(&cfg, logger, rbacStorageStub{})
	oauthService := oauth.NewService(&cfg, logger, oauthStorageStub{})

	_, err := NewServer(
		&cfg, logger, healthCheckerStub{}, nil,
		queueService, accountService, onboardingService, rbacService, oauthService,
	)
	if err == nil {
		t.Fatal("NewServer() unexpectedly accepted agent APIs without security dependencies")
	}

	admission, err := interceptor.NewPrincipalAdmissionLimiter(100, 200)
	if err != nil {
		t.Fatalf("NewPrincipalAdmissionLimiter() error = %v", err)
	}

	_, err = NewServer(
		&cfg, logger, healthCheckerStub{}, nil,
		queueService, accountService, onboardingService, rbacService, oauthService,
		WithAgentMessaging(grpcMountStub{}, grpcAuthenticatorStub{}, grpcResourceStub{}, admission),
	)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
}

// withCollectorForTest wires a metrics handler without opening a telemetry
// database, so the dashboard branch of the route tree is exercised. The nil
// store is only read by background workers this test never starts.
func withCollectorForTest() Option {
	return func(pq *PlainQ) {
		pq.metricsHandler = NewMetricsHandler(collector.New(nil), nil)
	}
}
