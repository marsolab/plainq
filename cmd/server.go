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
	"github.com/marsolab/plainq/internal/server"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/queue"
	queuestore "github.com/marsolab/plainq/internal/server/service/queue/litestore"
	accountstore "github.com/marsolab/plainq/internal/server/service/account/litestore"
	"github.com/marsolab/servekit/authkit/hashkit"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/logkit"
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

			// Auth.

			f.BoolVar(&cfg.AuthEnable, "auth.enable", true,
				"enable authentication",
			)

			f.BoolVar(&cfg.AuthRegistrationEnable, "auth.registration.enable", true,
				"enable registration",
			)

			f.DurationVar(&cfg.AuthAccessTokenTTL, "auth.access.ttl", 60*time.Minute,
				"set access token TTL",
			)

			f.DurationVar(&cfg.AuthRefreshTokenTTL, "auth.refresh.ttl", 24*30*time.Hour,
				"set refresh token TTL",
			)

			f.BoolVar(&cfg.AuthEmailVerificationEnable, "auth.email.verification.enable", true,
				"enable email verification",
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
		},

		Run: func(cmd *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			logger, loggerErr := initLogger(&cfg)
			if loggerErr != nil {
				return loggerErr
			}

			logger.Info("Starting plainq server")

			var checker hc.HealthChecker = hc.NewNopChecker()

			if cfg.HealthEnable {
				checker = hc.NewMultiChecker()
			}

			// Storage initialization.

			conn, connErr := initDBConnection(&cfg, logger)
			if connErr != nil {
				return connErr
			}

			queueStorage, queueStorageInitErr := initQueueStorage(&cfg, logger, conn)
			if queueStorageInitErr != nil {
				return queueStorageInitErr
			}

			defer func() {
				if err := queueStorage.Close(); err != nil {
					logger.Error("Failed to close storage database connection",
						slog.String("error", err.Error()),
					)
				}
			}()

			queueService := queue.NewService(&cfg, logger, queueStorage)

			accountStorage, accountStorageInitErr := initAccountStorage(&cfg, logger, conn)
			if accountStorageInitErr != nil {
				return accountStorageInitErr
			}

			accountService := account.NewService(&cfg, logger, hashkit.NewBCryptHasher(), accountStorage)

			plainqServer, serverErr := server.NewServer(&cfg, logger, checker, queueService, accountService)
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

func initDBConnection(cfg *config.Config, logger *slog.Logger) (*litekit.Conn, error) {
	if cfg.StorageDBPath == "" {
		pwd, pwdErr := os.Getwd()
		if pwdErr != nil {
			return nil, fmt.Errorf("get current working derrectory: %w", pwdErr)
		}

		dbPath, err := filepath.Abs(filepath.Join(pwd, "plainq.db"))
		if err != nil {
			return nil, fmt.Errorf("create database file: %w", err)
		}

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

	logger.Info("Database connection has been initialized",
		slog.String("path", cfg.StorageDBPath),
	)

	evolver, evolverErr := litekit.NewEvolver(conn, mutations.StorageMutations())
	if evolverErr != nil {
		return nil, fmt.Errorf("create schema evolver: %w", evolverErr)
	}

	if err := evolver.MutateSchema(); err != nil {
		return nil, fmt.Errorf("schema mutation: %w", err)
	}

	logger.Info("Database schema has been initialized",
		slog.String("path", cfg.StorageDBPath),
	)

	return conn, nil
}

func initQueueStorage(cfg *config.Config, logger *slog.Logger, conn *litekit.Conn) (*queuestore.Storage, error) {
	storageOptions := make([]queuestore.Option, 0, 2)

	if cfg.StorageLogEnable {
		storageOptions = append(storageOptions, queuestore.WithLogger(logger))
	}

	if cfg.StorageGCTimeout != 0 {
		storageOptions = append(storageOptions, queuestore.WithGCTimeout(cfg.StorageGCTimeout))
	}

	sqliteStorage, storageInitErr := queuestore.New(conn, storageOptions...)
	if storageInitErr != nil {
		return nil, fmt.Errorf("create storage: %w", storageInitErr)
	}

	return sqliteStorage, nil
}

func initAccountStorage(cfg *config.Config, logger *slog.Logger, conn *litekit.Conn) (*accountstore.Storage, error) {
	storageOptions := make([]accountstore.Option, 0, 2)

	if cfg.StorageLogEnable {
		storageOptions = append(storageOptions, accountstore.WithLogger(logger))
	}

	sqliteStorage, storageInitErr := accountstore.NewStorage(conn, logger, storageOptions...)
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
