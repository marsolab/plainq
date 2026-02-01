package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/heartwilltell/hc"
	"github.com/plainq/plainq/internal/server/auth"
	"github.com/plainq/plainq/internal/server/config"
	"github.com/plainq/plainq/internal/server/interceptor"
	"github.com/plainq/plainq/internal/server/middleware"
	v1 "github.com/plainq/plainq/internal/server/schema/v1"
	"github.com/plainq/plainq/internal/server/storage"
	"github.com/plainq/plainq/internal/server/telemetry"
	"github.com/plainq/plainq/internal/server/telemetry/collector"
	"github.com/plainq/servekit"
	"github.com/plainq/servekit/dbkit/litekit"
	"github.com/plainq/servekit/grpckit"
	"github.com/plainq/servekit/httpkit"
	vtgrpc "github.com/planetscale/vtprotobuf/codec/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto" // Register proto codec.
)

const (
	// jwtSecretLength is the length of the generated JWT secret in bytes.
	jwtSecretLength = 32
)

// PlainQ represents plainq logic.
type PlainQ struct {
	v1.UnimplementedPlainQServiceServer

	logger            *slog.Logger
	storage           storage.Storage
	observer          telemetry.Observer
	authService       *auth.AuthService
	authHandler       *auth.Handler
	permissionService *auth.PermissionService

	// Telemetry components.
	metricsCollector *collector.Collector
	metricsStore     *collector.SQLiteStore
	metricsHandler   *MetricsHandler
}

func (s *PlainQ) Mount(server *grpc.Server) { v1.RegisterPlainQServiceServer(server, s) }

// NewServer returns a pointer to a new instance of the PlainQ.
func NewServer(cfg *config.Config, logger *slog.Logger, stor storage.Storage, checker hc.HealthChecker, opts ...ServerOption) (*servekit.Server, error) {
	// Create a server which holds and serve all listeners.
	server := servekit.NewServer(logger)

	// Initialize authentication if enabled.
	var authService *auth.AuthService
	var authHandler *auth.Handler
	var permissionService *auth.PermissionService

	if cfg.AuthEnabled {
		// Generate a JWT secret if not provided.
		jwtSecret := cfg.AuthJWTSecret
		if jwtSecret == "" {
			logger.Warn("No JWT secret provided, generating random secret")
			jwtSecret = generateRandomSecret()
			logger.Info("Generated JWT secret (store this for production use)", slog.String("secret", jwtSecret))
		}

		// Create auth service.
		authStorage, ok := stor.(auth.AuthStorage)
		if !ok {
			return nil, errors.New("storage does not implement auth.AuthStorage interface")
		}

		authService = auth.NewAuthService(authStorage, jwtSecret, cfg.AuthIssuer)

		// Initialize deny list from storage.
		if err := authService.InitializeDenyList(context.Background()); err != nil {
			logger.Error("Failed to initialize token deny list", slog.String("error", err.Error()))
			// Continue anyway, deny list will be empty.
		}

		authHandler = auth.NewHandler(authService, authStorage)

		// Create OAuth service with configurable base URL.
		oauthService := auth.NewOAuthService(authStorage, authService, cfg.AuthOAuthBaseURL)
		authHandler.SetOAuthService(oauthService)

		// Create permission service.
		permissionService = auth.NewPermissionService(authStorage)

		logger.Info("Authentication enabled", slog.String("issuer", cfg.AuthIssuer))
	}

	pq := PlainQ{
		logger:            logger,
		storage:           stor,
		observer:          telemetry.NewObserver(),
		authService:       authService,
		authHandler:       authHandler,
		permissionService: permissionService,
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
			// Authentication routes (public).
			if cfg.AuthEnabled && pq.authHandler != nil {
				v1.Route("/auth", func(authRouter chi.Router) {
					// Setup routes (only available before setup is complete).
					authRouter.Get("/setup/status", pq.authHandler.SetupStatus)
					authRouter.Post("/setup", pq.authHandler.Setup)

					// Public auth routes.
					authRouter.Post("/login", pq.authHandler.Login)
					authRouter.Post("/signup", pq.authHandler.Signup)
					authRouter.Post("/refresh", pq.authHandler.Refresh)
					authRouter.Post("/logout", pq.authHandler.Logout)

					// OAuth routes.
					authRouter.Get("/oauth/providers", pq.authHandler.ListOAuthProviders)
					authRouter.Post("/oauth/init", pq.authHandler.OAuthInit)
					authRouter.Get("/oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
						provider := chi.URLParam(r, "provider")
						pq.authHandler.OAuthCallback(w, r, provider)
					})
				})
			}

			// Queue related routes (protected if auth is enabled).
			v1.Route("/queue", func(queue chi.Router) {
				// Apply auth middleware if enabled.
				if cfg.AuthEnabled && pq.authService != nil {
					queue.Use(middleware.Auth(pq.authService))
				}

				queue.Post("/", pq.createQueueHandler)
				queue.Get("/", pq.listQueuesHandler)
				queue.Get("/{id}", pq.describeQueueHandler)
				queue.Post("/{id}/purge", pq.purgeQueueHandler)
				queue.Delete("/{id}", pq.deleteQueueHandler)
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
	// There are routes responsible for static assets,
	// HTMX template parts, of full template pages.
	httpListener.MountGroup("/", func(ui chi.Router) {
		// Static assets.
		ui.Get("/*", pq.houstonStaticHandler)
	})

	// Register the HTTP listener with a server.
	server.RegisterListener("HTTP", httpListener)

	// Configure gRPC listener options.
	grpcOpts := []grpckit.Option[grpckit.ListenerConfig]{}

	// Add auth interceptor if authentication is enabled.
	if cfg.AuthEnabled && authService != nil {
		grpcOpts = append(grpcOpts, grpckit.WithUnaryInterceptors(
			interceptor.AuthInterceptor(authService),
		))
		logger.Info("gRPC authentication interceptor enabled")
	}

	grpcListener, grpcListenerErr := grpckit.NewListenerGRPC(cfg.GRPCAddr, grpcOpts...)
	if grpcListenerErr != nil {
		return nil, fmt.Errorf("create gRPC listener: %w", grpcListenerErr)
	}

	// Mount the plainq gRPC routes to the gRPC listener.
	grpcListener.Mount(&pq)

	// Register the gRPC listener with a server.
	server.RegisterListener("GRPC", grpcListener)

	return server, nil
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

func init() { encoding.RegisterCodec(vtgrpc.Codec{}) }

// generateRandomSecret generates a cryptographically secure random secret.
func generateRandomSecret() string {
	bytes := make([]byte, jwtSecretLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a less secure method if crypto/rand fails.
		panic("failed to generate random secret: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}

// ServerOption configures the PlainQ server.
type ServerOption func(*PlainQ)

// WithMetricsStore sets the metrics store for telemetry collection.
func WithMetricsStore(db *litekit.Conn) ServerOption {
	return func(pq *PlainQ) {
		pq.metricsStore = collector.NewSQLiteStore(db)
	}
}

// GetMetricsCollector returns the metrics collector for external use.
func (pq *PlainQ) GetMetricsCollector() *collector.Collector {
	return pq.metricsCollector
}
