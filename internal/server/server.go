package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/heartwilltell/hc"
	"github.com/plainq/plainq/internal/server/auth"
	"github.com/plainq/plainq/internal/server/config"
	"github.com/plainq/plainq/internal/server/middleware"
	v1 "github.com/plainq/plainq/internal/server/schema/v1"
	"github.com/plainq/plainq/internal/server/storage"
	"github.com/plainq/plainq/internal/server/telemetry"
	"github.com/plainq/servekit"
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

	logger      *slog.Logger
	storage     storage.Storage
	observer    telemetry.Observer
	authService *auth.AuthService
	authHandler *auth.Handler
}

func (s *PlainQ) Mount(server *grpc.Server) { v1.RegisterPlainQServiceServer(server, s) }

// NewServer returns a pointer to a new instance of the PlainQ.
func NewServer(cfg *config.Config, logger *slog.Logger, stor storage.Storage, checker hc.HealthChecker) (*servekit.Server, error) {
	// Create a server which holds and serve all listeners.
	server := servekit.NewServer(logger)

	// Initialize authentication if enabled.
	var authService *auth.AuthService
	var authHandler *auth.Handler

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

		logger.Info("Authentication enabled", slog.String("issuer", cfg.AuthIssuer))
	}

	pq := PlainQ{
		logger:      logger,
		storage:     stor,
		observer:    telemetry.NewObserver(),
		authService: authService,
		authHandler: authHandler,
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

	grpcListener, grpcListenerErr := grpckit.NewListenerGRPC(cfg.GRPCAddr)
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
