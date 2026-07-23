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
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/grpckit"
	"github.com/marsolab/servekit/httpkit"
	_ "google.golang.org/grpc/encoding/proto"
)

// PlainQ represents plainq logic.
type PlainQ struct {
	cfg          *config.Config
	logger       *slog.Logger
	queue        *queue.Service
	account      *account.Service
	onboarding   *onboarding.Service
	rbac         *rbac.Service
	oauth        *oauth.Service
	observer     telemetry.Observer
	tokenManager jwtkit.TokenManager

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
	tokenManager jwtkit.TokenManager,
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
		cfg:          cfg,
		logger:       logger,
		queue:        queueSvc,
		account:      accountSvc,
		onboarding:   onboardingSvc,
		rbac:         rbacSvc,
		oauth:        oauthSvc,
		observer:     telemetry.NewObserver(),
		tokenManager: tokenManager,
	}

	// Apply server options.
	for _, opt := range opts {
		opt(&pq)
	}

	// Initialize metrics collector if telemetry database is provided.
	if pq.metricsStore != nil {
		pq.metricsCollector = collector.New(pq.metricsStore, collector.WithLogger(logger))
		pq.queue.SetTopicMetricsRecorder(pq.metricsCollector)
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
			// Identity routes are always public: they are how a client obtains
			// or renews a token, so they cannot themselves demand one. Account
			// routes exist only when auth is enabled; onboarding bootstraps the
			// first admin and self-closes once one exists.
			if cfg.AuthEnable {
				v1.Route("/account", func(account chi.Router) {
					account.Mount("/", pq.account)
				})
			}

			// Onboarding is intentionally public — it only accepts
			// requests before the first admin user exists.
			v1.Route("/onboarding", func(r chi.Router) {
				r.Mount("/", pq.onboarding)
			})

			// protect gates a subtree behind a valid bearer token whenever auth
			// is enabled. With auth off the wrapper is a no-op, so the server is
			// open by deliberate configuration rather than by omission.
			protect := func(r chi.Router) {
				if cfg.AuthEnable {
					r.Use(middleware.AuthenticateJWT(pq.tokenManager, pq.account))
				}
			}

			// Queue related routes.
			v1.Route("/queue", func(queue chi.Router) {
				protect(queue)
				queue.Mount("/", pq.queue)
			})

			v1.Route("/rbac", func(r chi.Router) {
				protect(r)
				r.Mount("/", pq.rbac)
			})

			v1.Route("/oauth", func(r chi.Router) {
				protect(r)
				r.Mount("/", pq.oauth)
			})

			// Metrics API routes for dashboard.
			if pq.metricsHandler != nil {
				v1.Route("/metrics", func(metrics chi.Router) {
					protect(metrics)

					// Overview dashboard data.
					metrics.Get("/overview", pq.metricsHandler.GetDashboardOverview)
					metrics.Get("/topics/overview", pq.metricsHandler.GetTopicDashboardOverview)

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

					metrics.Route("/topic/{id}", func(topicMetrics chi.Router) {
						topicMetrics.Get("/", pq.metricsHandler.GetTopicMetrics)
						topicMetrics.Get("/rates", pq.metricsHandler.GetTopicRatesChart)
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
	fileServer := http.StripPrefix(pathPrefix, http.FileServerFS(bundle))

	cleanPath := strings.TrimPrefix(r.URL.Path, pathPrefix)
	trimmed := strings.TrimPrefix(cleanPath, "/")

	// Real file or root → let FileServer handle it (it serves a directory's
	// index.html when the URL ends in '/').
	if trimmed == "" {
		fileServer.ServeHTTP(w, r)

		return
	}

	if info, err := fs.Stat(bundle, trimmed); err == nil {
		// Astro emits each route as <route>/index.html. Asking FileServer for
		// the bare directory earns a 301 to the trailing-slash form, so add it
		// here and let a nav click cost one request instead of two.
		if info.IsDir() && !strings.HasSuffix(cleanPath, "/") {
			r.URL.Path = pathPrefix + "/" + trimmed + "/"
		}

		fileServer.ServeHTTP(w, r)

		return
	}

	// SPA fallback for extensionless paths. Rewrite to a directory URL
	// (trailing slash) rather than to <dir>/index.html — FileServer
	// 301-redirects requests ending in '/index.html' to './', which
	// would loop forever.
	if !strings.Contains(cleanPath, ".") {
		if parts := strings.SplitN(trimmed, "/", 2); len(parts) > 1 {
			if _, err := fs.Stat(bundle, parts[0]+"/index.html"); err == nil {
				r.URL.Path = pathPrefix + "/" + parts[0] + "/"
				fileServer.ServeHTTP(w, r)

				return
			}
		}

		// No such route. Answer 404 rather than rewriting to the root index:
		// serving Queues for a mistyped URL is a silent redirect dressed up as
		// success, and it hides typos from anyone reading logs or status codes.
		s.serveHoustonNotFound(w, r, bundle)

		return
	}

	fileServer.ServeHTTP(w, r)
}

// serveHoustonNotFound answers with the bundle's own not-found page when it
// ships one, falling back to a plain 404 otherwise. Either way the status code
// is the truth — that is what the caller acts on.
func (s *PlainQ) serveHoustonNotFound(w http.ResponseWriter, r *http.Request, bundle fs.FS) {
	page, err := fs.ReadFile(bundle, "404.html")
	if err != nil {
		http.NotFound(w, r)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)

	if _, writeErr := w.Write(page); writeErr != nil {
		s.logger.Error("write houston 404 page", slog.String("error", writeErr.Error()))
	}
}

func listenerHTTP(cfg *config.Config, logger *slog.Logger, checker hc.HealthChecker) (*httpkit.ListenerHTTP, error) {
	httpListenerOpts := httpkit.NewListenerOption(
		httpkit.WithLogger(logger),
		httpkit.WithHTTPServerTimeouts(
			httpkit.HTTPServerReadHeaderTimeout(cfg.HTTPReadHeaderTimeout),
			httpkit.HTTPServerReadTimeout(cfg.HTTPReadTimeout),
			httpkit.HTTPServerWriteTimeout(cfg.HTTPWriteTimeout),
			httpkit.HTTPServerIdleTimeout(cfg.HTTPIdleTimeout),
		),
	)

	if cfg.HealthEnable {
		healthOptions := []httpkit.ListenerOption[httpkit.HealthConfig]{
			httpkit.HealthCheckRoute(cfg.HealthRoute),
			httpkit.HealthCheckAccessLog(cfg.HealthRouteLogs),
			httpkit.HealthChecker(checker),
		}

		switch cfg.HealthReporter {
		case "json":
			healthOptions = append(healthOptions, httpkit.HealthCheckReportJSON())

		case "html":
			healthOptions = append(healthOptions, httpkit.HealthCheckReportHTML())
		}

		httpListenerOpts = append(httpListenerOpts, httpkit.WithHealthCheck(healthOptions...))
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
