package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/heartwilltell/hc"
	"github.com/heartwilltell/scotty"
	"github.com/plainq/plainq/internal/server"
	"github.com/plainq/plainq/internal/server/config"
	"github.com/plainq/plainq/internal/server/mutations"
	"github.com/plainq/plainq/internal/server/storage/litestore"
	"github.com/plainq/servekit/dbkit/litekit"
	"github.com/plainq/servekit/logkit"
)

func serverCommand() *scotty.Command {
	var cfg config.Config

	cmd := scotty.Command{
		Name:  "server",
		Short: "Runs the PlainQ server",
		SetFlags: func(f *scotty.FlagSet) {
			// Storage.

			f.BoolVar(&cfg.StorageLogEnable, "storage.log.enable", false,
				"enable logging for storage engine",
			)

			f.StringVar(&cfg.StorageDBPath, "storage.path", "",
				"set path to SQLite database file",
			)

			f.DurationVar(&cfg.StorageGCTimeout, "storage.gc.timeout", 0,
				"set storage GC timeout",
			)

			f.StringVar(&cfg.StorageAccessMode, "storage.access-mode", "",
				"set the sqlite storage access mode",
			)

			f.StringVar(&cfg.StorageJournalMode, "storage.journal-mode", "",
				"set the sqlite storage journal mode",
			)

			// Logs.

			f.BoolVar(&cfg.LogEnable, "log.enable", true,
				"enable logging",
			)

			f.BoolVar(&cfg.LogAccessEnable, "log.access.enable", true,
				"enable access logging",
			)

			f.StringVar(&cfg.LogLevel, "log.level", "info",
				"set logging level: 'debug', 'info', 'warning', 'error'",
			)

			// Telemetry.

			f.BoolVar(&cfg.TelemetryEnabled, "telemetry.enable", true,
				"enable telemetry subsystem",
			)

			f.StringVar(&cfg.TelemetryProvider, "telemetry.provider", "sqlite",
				"set telemetry provider",
			)

			f.BoolVar(&cfg.TelemetryLogEnable, "telemetry.log.enable", false,
				"enable logging for telemetry subsystem",
			)

			f.DurationVar(&cfg.TelemetryLiteScrapeTimeout, "telemetry.sqlite.collection.timeout", 10*time.Second,
				"set telemetry collection timeout",
			)

			f.DurationVar(&cfg.TelemetryLiteGCTimeout, "telemetry.sqlite.gc.timeout", 10*time.Minute,
				"set telemetry GC timeout",
			)

			f.DurationVar(&cfg.TelemetryLiteRetentionPeriod, "telemetry.sqlite.retention.period", 14*24*time.Hour,
				"set telemetry retention period",
			)

			f.StringVar(&cfg.TelemetryPromBaseURL, "telemetry.prometheus.baseurl", "",
				"set Prometheus API base URL",
			)

			// Listeners & PlainQ.

			f.StringVar(&cfg.GRPCAddr, "grpc.addr", ":8080",
				"set gRPC listener address",
			)

			f.StringVar(&cfg.HTTPAddr, "http.addr", ":8081",
				"set HTTP listener address",
			)

			f.DurationVar(&cfg.HTTPReadHeaderTimeout, "http.read-header-timeout", 0,
				"",
			)

			f.DurationVar(&cfg.HTTPReadTimeout, "http.read-timeout", 0,
				"",
			)

			f.DurationVar(&cfg.HTTPWriteTimeout, "http.write-timeout", 0,
				"",
			)

			f.DurationVar(&cfg.HTTPIdleTimeout, "http.idle-timeout", 0,
				"",
			)

			// Metrics.

			f.BoolVar(&cfg.MetricsEnable, "metrics", true,
				"enable the metrics endpoint",
			)

			f.BoolVar(&cfg.MetricsRouteLogs, "metrics.route.logs", false,
				"turn on access logs for metrics endpoint",
			)

			f.BoolVar(&cfg.MetricsRouteMetrics, "metrics.route.metrics", false,
				"turn on metrics for metrics endpoint",
			)

			f.StringVar(&cfg.MetricsRoute, "metrics.route", "/metrics",
				"set given route as metrics endpoint route",
			)

			// Health.

			f.BoolVar(&cfg.HealthEnable, "health", true,
				"enable the metrics endpoint",
			)

			f.BoolVar(&cfg.HealthRouteLogs, "health.route.logs", false,
				"turn on access logs for metrics endpoint",
			)

			f.BoolVar(&cfg.HealthRouteMetrics, "health.route.metrics", false,
				"turn on metrics for metrics endpoint",
			)

			f.StringVar(&cfg.HealthRoute, "health.route", "/health",
				"set given route as metrics endpoint route",
			)

			// CORS.

			f.BoolVar(&cfg.CORSEnable, "cors", true,
				"enable CORS configuration for Houston API routes",
			)

			// Profiler.

			f.BoolVar(&cfg.ProfilerEnabled, "profiler", false,
				"enable the profiler endpoint",
			)

			// Authentication.

			f.BoolVar(&cfg.AuthEnabled, "auth.enable", true,
				"enable authentication and authorization",
			)

			f.StringVar(&cfg.AuthJWTSecret, "auth.jwt-secret", "",
				"JWT signing secret (required if auth is enabled)",
			)

			f.StringVar(&cfg.AuthIssuer, "auth.issuer", "plainq",
				"JWT issuer identifier",
			)

			f.StringVar(&cfg.AuthOAuthBaseURL, "auth.oauth-base-url", "http://localhost:8081",
				"Base URL for OAuth callbacks (e.g., https://example.com)",
			)
		},

		Run: func(_ *scotty.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			logger, loggerErr := initLogger(&cfg)
			if loggerErr != nil {
				return loggerErr
			}

			logger.Info("Starting plainq server")

			// Storage initialization.

			sqliteStorage, storageInitErr := initStorage(&cfg, logger)
			if storageInitErr != nil {
				return storageInitErr
			}

			defer func() {
				if err := sqliteStorage.Close(); err != nil {
					logger.Error("Failed to close storage database connection",
						slog.String("error", err.Error()),
					)
				}
			}()

			var checker hc.HealthChecker = hc.NewNopChecker()

			if cfg.HealthEnable {
				checker = hc.NewMultiChecker(sqliteStorage)
			}

			// Initialize telemetry database if enabled.
			var serverOpts []server.ServerOption
			if cfg.TelemetryEnabled {
				telemetryDB, telemetryErr := initTelemetryDB(&cfg, logger)
				if telemetryErr != nil {
					logger.Warn("Failed to initialize telemetry database, metrics dashboard will be disabled",
						slog.String("error", telemetryErr.Error()),
					)
				} else {
					serverOpts = append(serverOpts, server.WithMetricsStore(telemetryDB))
					logger.Info("Telemetry metrics database initialized")
				}
			}

			plainqServer, serverErr := server.NewServer(&cfg, logger, sqliteStorage, checker, serverOpts...)
			if serverErr != nil {
				return fmt.Errorf("create PlainQ server: %s", serverErr.Error())
			}

			logger.Info("Houston Web UI",
				slog.String("address", printAddrHTTP(cfg.HTTPAddr)),
			)

			return plainqServer.Serve(ctx)
		},
	}

	return &cmd
}

func initLogger(cfg *config.Config) (*slog.Logger, error) {
	logger := logkit.NewNop()

	if cfg.LogEnable {
		level, levelErr := logkit.ParseLevel(cfg.LogLevel)
		if levelErr != nil {
			return nil, levelErr
		}

		options := []logkit.Option{
			logkit.WithLevel(level),
		}

		logger = logkit.New(options...)

		logger.Debug("Logger has been initialized",
			slog.String("level", level.String()),
		)
	}

	return logger, nil
}

func initStorage(cfg *config.Config, logger *slog.Logger) (*litestore.Storage, error) {
	if cfg.StorageDBPath == "" {
		pwd, pwdErr := os.Getwd()
		if pwdErr != nil {
			return nil, fmt.Errorf("get current working derrectory: %w", pwdErr)
		}

		dbPath, err := filepath.Abs(filepath.Join(pwd, "plainq.db"))
		if err != nil {
			return nil, fmt.Errorf("create storage file: %w", err)
		}

		logger.Info("Storage has been initialized",
			slog.String("path", dbPath),
		)

		cfg.StorageDBPath = dbPath
	}

	connOption := make([]litekit.Option, 0, 2)
	if cfg.StorageAccessMode != "" {
		mode, err := litekit.AccessModeFromString(cfg.StorageAccessMode)
		if err != nil {
			return nil, err
		}

		connOption = append(connOption, litekit.WithAccessMode(mode))
	}

	if cfg.StorageJournalMode != "" {
		mode, err := litekit.JournalModeFromString(cfg.StorageJournalMode)
		if err != nil {
			return nil, err
		}

		connOption = append(connOption, litekit.WithJournalMode(mode))
	}

	conn, conErr := litekit.New(cfg.StorageDBPath, connOption...)
	if conErr != nil {
		return nil, fmt.Errorf("connect to database: %w", conErr)
	}

	evolver, evolverErr := litekit.NewEvolver(conn, mutations.StorageMutations())
	if evolverErr != nil {
		return nil, fmt.Errorf("create schema evolver: %w", evolverErr)
	}

	if err := evolver.MutateSchema(); err != nil {
		return nil, fmt.Errorf("schema mutation: %w", err)
	}

	storageOptions := make([]litestore.Option, 0, 2)

	if cfg.StorageLogEnable {
		storageOptions = append(storageOptions, litestore.WithLogger(logger))
	}

	if cfg.StorageGCTimeout != 0 {
		storageOptions = append(storageOptions, litestore.WithGCTimeout(cfg.StorageGCTimeout))
	}

	sqliteStorage, storageInitErr := litestore.New(conn, storageOptions...)
	if storageInitErr != nil {
		return nil, fmt.Errorf("create storage: %w", storageInitErr)
	}

	return sqliteStorage, nil
}

func printAddrHTTP(addr string) string {
	if strings.HasPrefix(addr, "http") {
		return addr
	}

	if strings.HasPrefix(addr, ":") {
		return fmt.Sprintf("http://localhost%s", addr)
	}

	return addr
}

func initTelemetryDB(cfg *config.Config, logger *slog.Logger) (*litekit.Conn, error) {
	// Use same path as storage but with _telemetry suffix, or use configured path.
	dbPath := cfg.TelemetryLiteDBPath
	if dbPath == "" {
		// Derive from storage path.
		if cfg.StorageDBPath != "" {
			dbPath = strings.TrimSuffix(cfg.StorageDBPath, ".db") + "_telemetry.db"
		} else {
			pwd, pwdErr := os.Getwd()
			if pwdErr != nil {
				return nil, fmt.Errorf("get current working directory: %w", pwdErr)
			}

			dbPath, _ = filepath.Abs(filepath.Join(pwd, "plainq_telemetry.db"))
		}
	}

	logger.Info("Initializing telemetry database", slog.String("path", dbPath))

	connOption := make([]litekit.Option, 0, 2)

	// Use WAL mode for better concurrent performance.
	connOption = append(connOption, litekit.WithJournalMode(litekit.JournalModeWAL))

	conn, conErr := litekit.New(dbPath, connOption...)
	if conErr != nil {
		return nil, fmt.Errorf("connect to telemetry database: %w", conErr)
	}

	// Apply telemetry schema migrations.
	evolver, evolverErr := litekit.NewEvolver(conn, mutations.TelemetryMutation())
	if evolverErr != nil {
		return nil, fmt.Errorf("create telemetry schema evolver: %w", evolverErr)
	}

	if err := evolver.MutateSchema(); err != nil {
		return nil, fmt.Errorf("telemetry schema mutation: %w", err)
	}

	return conn, nil
}
