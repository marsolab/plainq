package server

import (
	"context"
	"log/slog"
	"testing"
	"time"

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
)

type telemetryWorkerForTest struct {
	started chan context.Context
	stopped chan struct{}
}

func (w *telemetryWorkerForTest) Start(ctx context.Context) { w.started <- ctx }

func (w *telemetryWorkerForTest) Stop() { close(w.stopped) }

func TestTelemetryListenerBindsCollectorToServeContext(t *testing.T) {
	worker := &telemetryWorkerForTest{
		started: make(chan context.Context),
		stopped: make(chan struct{}),
	}
	listener := &telemetryListener{worker: worker}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- listener.Serve(ctx) }()

	select {
	case startedCtx := <-worker.started:
		if startedCtx != ctx {
			t.Fatal("telemetry worker did not receive the listener Serve context")
		}
	case <-time.After(time.Second):
		t.Fatal("telemetry worker did not start")
	}

	select {
	case <-worker.stopped:
		t.Fatal("telemetry worker stopped before Serve context cancellation")
	default:
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve telemetry listener: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("telemetry listener did not return after context cancellation")
	}

	select {
	case <-worker.stopped:
	default:
		t.Fatal("telemetry worker was not stopped before Serve returned")
	}
}

func TestTelemetryConfigRejectsNonPositiveIntervals(t *testing.T) {
	tests := map[string]config.Config{
		"zero collection interval": telemetryConfigForTest(0, 10*time.Minute, 24*time.Hour),
		"negative collection interval": telemetryConfigForTest(
			-time.Millisecond, 10*time.Minute, 24*time.Hour,
		),
		"zero cleanup interval": telemetryConfigForTest(10*time.Second, 0, 24*time.Hour),
		"negative cleanup interval": telemetryConfigForTest(
			10*time.Second, -time.Second, 24*time.Hour,
		),
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateTelemetryConfig(cfg); err == nil {
				t.Fatal("validateTelemetryConfig returned nil, want interval error")
			}
		})
	}
}

func TestTelemetryConfigRejectsSubMillisecondCollection(t *testing.T) {
	cfg := telemetryConfigForTest(500*time.Microsecond, 10*time.Minute, 24*time.Hour)
	if err := validateTelemetryConfig(cfg); err == nil {
		t.Fatal("validateTelemetryConfig returned nil, want sub-millisecond collection error")
	}
}

func TestTelemetryConfigRejectsFractionalMillisecondCollection(t *testing.T) {
	cfg := telemetryConfigForTest(1500*time.Microsecond, 10*time.Minute, 24*time.Hour)
	if err := validateTelemetryConfig(cfg); err == nil {
		t.Fatal("validateTelemetryConfig returned nil, want fractional-millisecond collection error")
	}
}

func TestTelemetryConfigRejectsCollectionThatDoesNotTileMinute(t *testing.T) {
	cfg := telemetryConfigForTest(7*time.Second, 10*time.Minute, 24*time.Hour)
	if err := validateTelemetryConfig(cfg); err == nil {
		t.Fatal("validateTelemetryConfig returned nil, want non-tiling collection error")
	}
}

func TestTelemetryConfigRequiresAtLeastTwentyFourHoursRetention(t *testing.T) {
	cfg := telemetryConfigForTest(10*time.Second, 10*time.Minute, 24*time.Hour-time.Millisecond)
	if err := validateTelemetryConfig(cfg); err == nil {
		t.Fatal("validateTelemetryConfig returned nil, want retention error")
	}
}

func TestTelemetryConfigAcceptsValidAndDisabledConfigurations(t *testing.T) {
	valid := telemetryConfigForTest(10*time.Second, 10*time.Minute, 24*time.Hour)
	if err := validateTelemetryConfig(valid); err != nil {
		t.Fatalf("validate valid telemetry config: %v", err)
	}

	disabled := telemetryConfigForTest(0, 0, 0)
	disabled.TelemetryEnabled = false
	if err := validateTelemetryConfig(disabled); err != nil {
		t.Fatalf("validate disabled telemetry config: %v", err)
	}
}

func TestNewServerRejectsInvalidTelemetryConfig(t *testing.T) {
	cfg := telemetryConfigForTest(10*time.Second, 0, 24*time.Hour)
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.GRPCAddr = "127.0.0.1:0"

	if err := buildTelemetryServerForTest(&cfg); err == nil {
		t.Fatal("NewServer returned nil, want telemetry validation error")
	}
}

func TestServerPassesTelemetryConfigToCollector(t *testing.T) {
	cfg := telemetryConfigForTest(5*time.Second, 3*time.Minute, 36*time.Hour)
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.GRPCAddr = "127.0.0.1:0"

	var (
		called   bool
		settings telemetryCollectorSettings
	)
	withFactory := func(pq *PlainQ) {
		pq.metricsStore = collector.NewSQLiteStore(nil)
		pq.metricsCollectorFactory = func(
			_ *collector.SQLiteStore,
			_ *slog.Logger,
			got telemetryCollectorSettings,
		) *collector.Collector {
			called = true
			settings = got

			return collector.New(nil)
		}
	}

	if err := buildTelemetryServerForTest(&cfg, withFactory); err != nil {
		t.Fatalf("build server with telemetry: %v", err)
	}
	if !called {
		t.Fatal("telemetry collector factory was not called")
	}
	if settings.collectionInterval != cfg.TelemetryLiteScrapeTimeout {
		t.Fatalf("collection interval = %s, want %s", settings.collectionInterval, cfg.TelemetryLiteScrapeTimeout)
	}
	if settings.cleanupInterval != cfg.TelemetryLiteGCTimeout {
		t.Fatalf("cleanup interval = %s, want %s", settings.cleanupInterval, cfg.TelemetryLiteGCTimeout)
	}
	if settings.retentionPeriod != cfg.TelemetryLiteRetentionPeriod {
		t.Fatalf("retention period = %s, want %s", settings.retentionPeriod, cfg.TelemetryLiteRetentionPeriod)
	}
}

func telemetryConfigForTest(collection, cleanup, retention time.Duration) config.Config {
	return config.Config{
		TelemetryEnabled:             true,
		TelemetryLiteScrapeTimeout:   collection,
		TelemetryLiteGCTimeout:       cleanup,
		TelemetryLiteRetentionPeriod: retention,
	}
}

func buildTelemetryServerForTest(cfg *config.Config, opts ...Option) error {
	logger := logkit.NewNop()
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	queueStorage := queueStorageStub{}

	_, err := NewServer(
		cfg,
		logger,
		healthCheckerStub{},
		nil,
		queue.NewService(cfg, logger, queue.NewObservedStorage(queueStorage, observer), observer),
		account.NewService(cfg, logger, nil, nil, accountStorageStub{}),
		onboarding.NewService(cfg, logger, nil, nil, onboardingStorageStub{}),
		rbac.NewService(cfg, logger, rbacStorageStub{}),
		oauth.NewService(cfg, logger, oauthStorageStub{}),
		opts...,
	)

	return err
}
