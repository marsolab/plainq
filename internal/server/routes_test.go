package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/interceptor"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
	"github.com/marsolab/servekit/logkit"
	"github.com/maxatome/go-testdeep/td"
	"google.golang.org/grpc"
)

// healthCheckerStub satisfies the health-check dependency NewServer takes.
type healthCheckerStub struct{}

func (healthCheckerStub) Health(context.Context) error { return nil }

type failingHealthChecker struct {
	calls int
}

func (c *failingHealthChecker) Health(context.Context) error {
	c.calls++
	return errors.New("replica quarantined")
}

func TestLivenessStaysHealthyWhileQuarantinedReadinessFails(t *testing.T) {
	for _, reporter := range []string{"", "json", "html"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(reporter+"/"+method, func(t *testing.T) {
				checker := new(failingHealthChecker)
				readiness := httptest.NewRecorder()
				readinessHandler(checker, reporter).ServeHTTP(
					readiness,
					httptest.NewRequest(method, "/health", nil),
				)
				if readiness.Code != http.StatusServiceUnavailable {
					t.Fatalf("readiness status = %d, want 503", readiness.Code)
				}
				if method == http.MethodGet && reporter == "json" && !strings.Contains(readiness.Body.String(), `"status":"503 Service Unavailable"`) {
					t.Fatalf("JSON readiness body = %q", readiness.Body.String())
				}
				if method == http.MethodGet && reporter == "html" && !strings.Contains(readiness.Header().Get("Content-Type"), "text/html") {
					t.Fatalf("HTML readiness content type = %q", readiness.Header().Get("Content-Type"))
				}

				live := httptest.NewRecorder()
				livenessHandler().ServeHTTP(live, httptest.NewRequest(method, "/live", nil))
				if live.Code != http.StatusOK {
					t.Fatalf("liveness status = %d, want 200", live.Code)
				}
				if checker.calls != 1 {
					t.Fatalf("dependency checker calls = %d, want readiness only", checker.calls)
				}
			})
		}
	}
}

type telemetryRecorderStub struct {
	sends     int
	queueSets int
}

func (r *telemetryRecorderStub) RecordSend(string, uint64, uint64) { r.sends++ }
func (*telemetryRecorderStub) RecordReceive(string, uint64, bool)  {}
func (*telemetryRecorderStub) RecordDelete(string, uint64)         {}
func (*telemetryRecorderStub) RecordRedelivery(string, uint64)     {}
func (*telemetryRecorderStub) RecordDrop(string, uint64)           {}
func (*telemetryRecorderStub) RecordDLQ(string, uint64)            {}
func (*telemetryRecorderStub) IncrementQueues()                    {}
func (*telemetryRecorderStub) DecrementQueues()                    {}
func (r *telemetryRecorderStub) SetQueuesExist(int64)              { r.queueSets++ }

func TestAttachTelemetryObserversDeduplicatesStandaloneAndSuppressesClusterState(t *testing.T) {
	t.Run("standalone pointer is attached once with full state", func(t *testing.T) {
		observer := telemetry.NewObserver(metrics.BackendSQLite)
		recorder := new(telemetryRecorderStub)
		attachTelemetryObservers(observer, observer, recorder)
		observer.SetQueues(3)
		if recorder.queueSets != 1 {
			t.Fatalf("queue exact-state calls = %d, want 1", recorder.queueSets)
		}
	})

	t.Run("cluster logical state is suppressed but events forward", func(t *testing.T) {
		local := telemetry.NewObserver(metrics.BackendSQLite)
		logical := telemetry.NewObserver(metrics.BackendCluster)
		recorder := new(telemetryRecorderStub)
		attachTelemetryObservers(local, logical, recorder)
		local.SetQueues(3)
		logical.SetQueues(99)
		logical.Sent("queueone", 1, 1)
		if recorder.queueSets != 1 {
			t.Fatalf("queue exact-state calls = %d, want only local state", recorder.queueSets)
		}
		if recorder.sends != 1 {
			t.Fatalf("logical send events = %d, want 1", recorder.sends)
		}
	})
}

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

type securityAuditorStub struct{}

func (securityAuditorStub) Append(context.Context, securityaudit.Event) error { return nil }

func (securityAuditorStub) List(context.Context, securityaudit.Query) (securityaudit.Page, error) {
	return securityaudit.Page{}, nil
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
				HTTPAddr:            "127.0.0.1:0",
				GRPCAddr:            "127.0.0.1:0",
				MetricsEnable:       true,
				MetricsRoute:        "/metrics",
				HealthEnable:        true,
				HealthRoute:         "/health",
				HealthLivenessRoute: "/live",
			}

			logger := logkit.NewNop()
			observer := telemetry.NewObserver(metrics.BackendSQLite)
			queueStorage := queueStorageStub{}

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
				queue.NewService(&cfg, logger, queue.NewObservedStorage(queueStorage, observer), observer),
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

func TestTopicSubscriptionsRouteDiscoveryIsProtected(t *testing.T) {
	router := chi.NewRouter()
	authCalls := 0
	router.Route("/api/v1/metrics", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				authCalls++
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			})
		})
		mountTopicMetricsRoutes(r, NewMetricsHandler(collector.New(nil), nil, MetricsHandlerConfig{}))
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/topic/topic-1/subscriptions?range=1h", nil))
	td.Cmp(t, recorder.Code, http.StatusUnauthorized)
	td.Cmp(t, authCalls, 1)
}

func TestNewServerMountsAgentTransportOnlyWithCompleteSecurityDependencies(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		HTTPAddr: "127.0.0.1:0", GRPCAddr: "127.0.0.1:0",
		AgentEnable: true, AgentDevelopmentInsecureTransport: true,
	}
	logger := logkit.NewNop()
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	queueService := queue.NewService(&cfg, logger, queueStorageStub{}, observer)
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
		WithSecurityAuditor(securityAuditorStub{}),
	)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
}

func TestNewServerRequiresCompleteHumanGRPCSecurity(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		HTTPAddr: "127.0.0.1:0", GRPCAddr: "127.0.0.1:0",
		AuthEnable: true, AgentEnable: false, GRPCProtectLegacy: true,
	}
	logger := logkit.NewNop()
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	queueService := queue.NewService(&cfg, logger, queueStorageStub{}, observer)
	accountService := account.NewService(&cfg, logger, nil, nil, accountStorageStub{})
	onboardingService := onboarding.NewService(&cfg, logger, nil, nil, onboardingStorageStub{})
	rbacService := rbac.NewService(&cfg, logger, rbacStorageStub{})
	oauthService := oauth.NewService(&cfg, logger, oauthStorageStub{})

	_, err := NewServer(
		&cfg, logger, healthCheckerStub{}, nil,
		queueService, accountService, onboardingService, rbacService, oauthService,
	)
	if err == nil {
		t.Fatal("NewServer() unexpectedly accepted human gRPC without authentication and admission dependencies")
	}

	admission, err := interceptor.NewPrincipalAdmissionLimiter(100, 200)
	if err != nil {
		t.Fatalf("NewPrincipalAdmissionLimiter() error = %v", err)
	}

	_, err = NewServer(
		&cfg, logger, healthCheckerStub{}, nil,
		queueService, accountService, onboardingService, rbacService, oauthService,
		WithHumanGRPCSecurity(grpcAuthenticatorStub{}, admission),
		WithSecurityAuditor(securityAuditorStub{}),
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
		pq.metricsHandler = NewMetricsHandler(collector.New(nil), nil, MetricsHandlerConfig{})
	}
}
