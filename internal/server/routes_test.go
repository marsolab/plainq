package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
	"github.com/marsolab/servekit/logkit"
	"github.com/maxatome/go-testdeep/td"
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

// withCollectorForTest wires a metrics handler without opening a telemetry
// database, so the dashboard branch of the route tree is exercised. The nil
// store is only read by background workers this test never starts.
func withCollectorForTest() Option {
	return func(pq *PlainQ) {
		pq.metricsHandler = NewMetricsHandler(collector.New(nil), nil)
	}
}
