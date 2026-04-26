package server

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/heartwilltell/hc"
	"github.com/marsolab/plainq/internal/houston"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
	"github.com/marsolab/servekit"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/grpckit"
	"github.com/marsolab/servekit/httpkit"
	_ "google.golang.org/grpc/encoding/proto"
)

// PlainQ represents plainq logic.
type PlainQ struct {
	cfg        *config.Config
	logger     *slog.Logger
	queue      *queue.Service
	account    *account.Service
	onboarding *onboarding.Service
	rbac       *rbac.Service
	oauth      *oauth.Service
	observer   telemetry.Observer

	// Telemetry components.
	metricsCollector *collector.Collector
	metricsStore     *collector.SQLiteStore
	metricsHandler   *MetricsHandler
}

// NewServer returns a pointer to a new instance of the PlainQ.
//
//nolint:funlen // server wiring assembles the full HTTP/gRPC stack in one place.
func NewServer(
	cfg *config.Config,
	logger *slog.Logger,
	checker hc.HealthChecker,
	queueSvc *queue.Service,
	accountSvc *account.Service,
	onboardingSvc *onboarding.Service,
	rbacSvc *rbac.Service,
	oauthSvc *oauth.Service,
	opts ...Option,
) (*servekit.Server, error) {
	// Create a server which holds and serve all listeners.
	server := servekit.NewServer(logger)

	pq := PlainQ{
		cfg:        cfg,
		logger:     logger,
		queue:      queueSvc,
		account:    accountSvc,
		onboarding: onboardingSvc,
		rbac:       rbacSvc,
		oauth:      oauthSvc,
		observer:   telemetry.NewObserver(),
	}

	// Apply server options.
	for _, opt := range opts {
		opt(&pq)
	}

	// Initialize metrics collector if telemetry database is provided.
	if pq.metricsStore != nil {
		pq.metricsCollector = collector.New(pq.metricsStore, collector.WithLogger(logger))
		pq.metricsHandler = NewMetricsHandler(pq.metricsCollector, pq.metricsStore)

		// Start the collector in background.
		go pq.metricsCollector.Start(context.Background())

		logger.Info("Telemetry metrics collector started")
	}

	// Create the HTTP listener.
	httpListener, httpListenerErr := listenerHTTP(cfg, logger, checker)
	if httpListenerErr != nil {
		return nil, httpListenerErr
	}

	// Initialize and mount the HTTP API routes.
	httpListener.MountGroup("/api", func(api chi.Router) {
		api.Use(middleware.Logging(logger))
		api.Use(cors.AllowAll().Handler)

		api.Route("/v1", func(v1 chi.Router) {
			if cfg.AuthEnable {
				v1.Route("/account", func(account chi.Router) {
					account.Mount("/", pq.account)
				})
			}

			// Queue related routes.
			v1.Route("/queue", func(queue chi.Router) {
				queue.Mount("/", pq.queue)
			})

			// Onboarding is intentionally public — it only accepts
			// requests before the first admin user exists.
			v1.Route("/onboarding", func(r chi.Router) {
				r.Mount("/", pq.onboarding)
			})

			v1.Route("/rbac", func(r chi.Router) {
				r.Mount("/", pq.rbac)
			})

			v1.Route("/oauth", func(r chi.Router) {
				r.Mount("/", pq.oauth)
			})

			// Metrics API routes for dashboard.
			if pq.metricsHandler != nil {
				v1.Route("/metrics", func(metrics chi.Router) {
					// Overview dashboard data.
					metrics.Get("/overview", pq.metricsHandler.GetDashboardOverview)

					// Time-series chart data.
					metrics.Get("/chart", pq.metricsHandler.GetMetricsChart)

					// System-wide rates.
					metrics.Get("/rates", pq.metricsHandler.GetRatesChart)

					// In-flight metrics.
					metrics.Get("/inflight", pq.metricsHandler.GetInFlightMetrics)

					// Available metrics list.
					metrics.Get("/available", pq.metricsHandler.GetAvailableMetrics)

					// Time range presets.
					metrics.Get("/time-ranges", pq.metricsHandler.GetTimeRangePresets)

					// Export metrics (for Metabase/custom charts).
					metrics.Get("/export", pq.metricsHandler.ExportMetrics)

					// Queue-specific metrics.
					metrics.Route("/queue/{id}", func(queueMetrics chi.Router) {
						queueMetrics.Get("/", pq.metricsHandler.GetQueueMetrics)
						queueMetrics.Get("/rates", pq.metricsHandler.GetRatesChart)
						queueMetrics.Get("/inflight", pq.metricsHandler.GetInFlightMetrics)
					})
				})
			}
		})
	})

	// Initialize and mount the Houston UI related routes.
	// There are routes responsible for static assets.
	httpListener.MountGroup("/", func(ui chi.Router) {
		// Static assets.
		ui.Get("/*", pq.houstonStaticHandler)
	})

	// Register the HTTP listener with a server.
	server.RegisterListener("HTTP", httpListener)

	grpcListener, grpcListenerErr := grpckit.NewListenerGRPC(cfg.GRPCAddr)
	if grpcListenerErr != nil {
		return nil, fmt.Errorf("create gRPC listener: %w", grpcListenerErr)
	}

	// Mount the queue gRPC routes to the gRPC listener.
	grpcListener.Mount(pq.queue)

	// Register the gRPC listener with a server.
	server.RegisterListener("GRPC", grpcListener)

	return server, nil
}

func (s *PlainQ) houstonStaticHandler(w http.ResponseWriter, r *http.Request) {
	routePattern := chi.RouteContext(r.Context()).RoutePattern()
	pathPrefix := strings.TrimSuffix(routePattern, "/*")

	s.logger.Debug("houston static handler",
		slog.String("path", r.URL.Path),
		slog.String("route_pattern", routePattern),
		slog.String("path_prefix", pathPrefix),
	)

	bundle := houston.Bundle()
	cleanPath := strings.TrimPrefix(r.URL.Path, pathPrefix)
	if cleanPath == "" || cleanPath == "/" {
		cleanPath = "/"
	}

	// Try to serve the requested file. If it doesn't exist and has no
	// file extension, attempt SPA-style fallback: first try serving the
	// parent path's index.html (e.g., /queue/abc → queue/index.html),
	// then fall back to the root index.html.
	trimmed := strings.TrimPrefix(cleanPath, "/")
	if _, err := fs.Stat(bundle, trimmed); err != nil && !strings.Contains(cleanPath, ".") {
		// Try parent directory: /queue/abc123 → queue/index.html
		parts := strings.SplitN(trimmed, "/", 2)
		if len(parts) > 1 {
			parent := parts[0] + "/index.html"
			if _, parentErr := fs.Stat(bundle, parent); parentErr == nil {
				r.URL.Path = pathPrefix + "/" + parent
				http.StripPrefix(pathPrefix, http.FileServerFS(bundle)).ServeHTTP(w, r)
				return
			}
		}

		r.URL.Path = pathPrefix + "/index.html"
	}

	http.StripPrefix(pathPrefix, http.FileServerFS(bundle)).
		ServeHTTP(w, r)
}

func listenerHTTP(cfg *config.Config, logger *slog.Logger, checker hc.HealthChecker) (*httpkit.ListenerHTTP, error) {
	httpListenerOpts := httpkit.NewListenerOption[httpkit.ListenerConfig](
		httpkit.WithLogger(logger),
		httpkit.WithHTTPServerTimeouts(
			httpkit.HTTPServerReadHeaderTimeout(cfg.HTTPReadHeaderTimeout),
			httpkit.HTTPServerReadTimeout(cfg.HTTPReadTimeout),
			httpkit.HTTPServerWriteTimeout(cfg.HTTPWriteTimeout),
			httpkit.HTTPServerIdleTimeout(cfg.HTTPIdleTimeout),
		),
	)

	if cfg.HealthEnable {
		httpListenerOpts = append(httpListenerOpts, httpkit.WithHealthCheck(
			httpkit.HealthCheckRoute(cfg.HealthRoute),
			httpkit.HealthChecker(checker),
		))
	}

	if cfg.MetricsEnable {
		httpListenerOpts = append(httpListenerOpts, httpkit.WithMetrics(
			httpkit.MetricsRoute(cfg.MetricsRoute),
			httpkit.MetricsAccessLog(cfg.MetricsRouteLogs),
			httpkit.MetricsMetricsForEndpoint(cfg.MetricsRouteMetrics),
		))
	}

	httpListener, err := httpkit.NewListenerHTTP(cfg.HTTPAddr, httpListenerOpts...)
	if err != nil {
		return nil, fmt.Errorf("create HTTP listener: %w", err)
	}

	return httpListener, nil
}

// Option configures the PlainQ server.
type Option func(*PlainQ)

// WithMetricsStore sets the metrics store for telemetry collection.
func WithMetricsStore(db *litekit.Conn) Option {
	return func(pq *PlainQ) {
		pq.metricsStore = collector.NewSQLiteStore(db)
	}
}

// GetMetricsCollector returns the metrics collector for external use.
func (s *PlainQ) GetMetricsCollector() *collector.Collector {
	return s.metricsCollector
}
