package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/heartwilltell/hc"
	"github.com/heartwilltell/scotty"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/service/account"
	accountstore "github.com/marsolab/plainq/internal/server/service/account/litestore"
	accountpg "github.com/marsolab/plainq/internal/server/service/account/pgstore"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	oauthstore "github.com/marsolab/plainq/internal/server/service/oauth/litestore"
	oauthpg "github.com/marsolab/plainq/internal/server/service/oauth/pgstore"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	onboardstore "github.com/marsolab/plainq/internal/server/service/onboarding/litestore"
	onboardpg "github.com/marsolab/plainq/internal/server/service/onboarding/pgstore"
	"github.com/marsolab/plainq/internal/server/service/queue"
	queuestore "github.com/marsolab/plainq/internal/server/service/queue/litestore"
	queuepg "github.com/marsolab/plainq/internal/server/service/queue/pgstore"
	"github.com/marsolab/plainq/internal/server/service/rbac"
	rbacstore "github.com/marsolab/plainq/internal/server/service/rbac/litestore"
	rbacpg "github.com/marsolab/plainq/internal/server/service/rbac/pgstore"
	"github.com/marsolab/servekit/authkit/hashkit"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/logkit"
)

// storageDriverSQLite and storageDriverPostgres are the accepted values
// for the --storage.driver flag.
const (
	storageDriverSQLite   = "sqlite"
	storageDriverPostgres = "postgres"
)

// storageBackend holds the underlying connection handle for whichever
// driver was selected. Exactly one of its fields is non-nil after
// initStorageBackend returns.
type storageBackend struct {
	driver string
	sqlite *litekit.Conn
	pgpool *pgxpool.Pool
}

func (b *storageBackend) Close() error {
	switch {
	case b.sqlite != nil:
		return b.sqlite.Close()

	case b.pgpool != nil:
		b.pgpool.Close()

		return nil
	}

	return nil
}

//nolint:cyclop,gocognit,funlen // CLI server setup wires the full dependency graph in one place.
func serverCommand() *scotty.Command {
	var cfg config.Config

	cmd := scotty.Command{
		Name:  "serve",
		Short: "Runs the PlainQ server",
		SetFlags: func(f *scotty.FlagSet) {
			// Storage.
			f.StringVar(&cfg.StorageDriver, "storage.driver", "sqlite",
				"storage driver: 'sqlite' (default) or 'postgres'",
			)

			f.StringVar(&cfg.StoragePostgresDSN, "storage.postgres.dsn", "",
				"PostgreSQL connection string (used when storage.driver=postgres)",
			)

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

			f.StringVar(&cfg.AuthJWTSecret, "auth.jwt.secret", "",
				"HMAC secret used to sign access/refresh tokens (required when auth.enable)",
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

		Run: func(_ *scotty.Command, _ []string) error {
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

			backend, backendErr := initStorageBackend(&cfg, logger)
			if backendErr != nil {
				return backendErr
			}

			defer func() {
				if err := backend.Close(); err != nil {
					logger.Error("Failed to close storage backend",
						slog.String("error", err.Error()),
					)
				}
			}()

			queueStorage, queueClose, queueStorageInitErr := initQueueStorage(&cfg, logger, backend)
			if queueStorageInitErr != nil {
				return queueStorageInitErr
			}

			defer func() {
				if err := queueClose(); err != nil {
					logger.Error("Failed to close queue storage",
						slog.String("error", err.Error()),
					)
				}
			}()

			queueService := queue.NewService(&cfg, logger, queueStorage)

			accountStorage, accountStorageInitErr := initAccountStorage(&cfg, logger, backend)
			if accountStorageInitErr != nil {
				return accountStorageInitErr
			}

			hasher := hashkit.NewBCryptHasher()

			tokenManager, tokenErr := initTokenManager(&cfg)
			if tokenErr != nil {
				return tokenErr
			}

			accountService := account.NewService(&cfg, logger, hasher, accountStorage)

			onboardingStorage, onboardingStorageErr := initOnboardingStorage(&cfg, logger, backend)
			if onboardingStorageErr != nil {
				return onboardingStorageErr
			}

			onboardingService := onboarding.NewService(&cfg, logger, hasher, tokenManager, onboardingStorage)

			rbacStorage, rbacStorageErr := initRBACStorage(&cfg, logger, backend)
			if rbacStorageErr != nil {
				return rbacStorageErr
			}

			rbacService := rbac.NewService(&cfg, logger, rbacStorage)

			oauthStorage, oauthStorageErr := initOAuthStorage(&cfg, logger, backend)
			if oauthStorageErr != nil {
				return oauthStorageErr
			}

			oauthService := oauth.NewService(&cfg, logger, oauthStorage)

			// Initialize telemetry database if enabled.
			var serverOpts []server.Option

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

			plainqServer, serverErr := server.NewServer(&cfg, logger, checker, queueService, accountService,
				onboardingService, rbacService, oauthService, serverOpts...,
			)
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

// initStorageBackend constructs the driver-specific connection handle and
// runs any pending schema migrations against it. Callers should defer
// backend.Close() as soon as the return value is non-nil.
func initStorageBackend(cfg *config.Config, logger *slog.Logger) (*storageBackend, error) {
	driver := cfg.StorageDriver
	if driver == "" {
		driver = storageDriverSQLite
	}

	switch driver {
	case storageDriverSQLite:
		conn, err := initSQLiteBackend(cfg, logger)
		if err != nil {
			return nil, err
		}

		return &storageBackend{driver: storageDriverSQLite, sqlite: conn}, nil

	case storageDriverPostgres:
		pool, err := initPostgresBackend(cfg, logger)
		if err != nil {
			return nil, err
		}

		return &storageBackend{driver: storageDriverPostgres, pgpool: pool}, nil

	default:
		return nil, fmt.Errorf("unsupported storage driver %q (want %q or %q)",
			driver, storageDriverSQLite, storageDriverPostgres,
		)
	}
}

//nolint:cyclop // Database initialization involves multiple setup steps.
func initSQLiteBackend(cfg *config.Config, logger *slog.Logger) (*litekit.Conn, error) {
	if cfg.StorageDBPath == "" {
		pwd, pwdErr := os.Getwd()
		if pwdErr != nil {
			return nil, fmt.Errorf("get current working directory: %w", pwdErr)
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

	logger.Info("SQLite database connection has been initialized",
		slog.String("path", cfg.StorageDBPath),
	)

	evolver, evolverErr := litekit.NewEvolver(conn, mutations.SqliteStorageMutations())
	if evolverErr != nil {
		return nil, fmt.Errorf("create schema evolver: %w", evolverErr)
	}

	if err := evolver.MutateSchema(); err != nil {
		return nil, fmt.Errorf("schema mutation: %w", err)
	}

	logger.Info("SQLite schema has been initialized",
		slog.String("path", cfg.StorageDBPath),
	)

	return conn, nil
}

func initPostgresBackend(cfg *config.Config, logger *slog.Logger) (*pgxpool.Pool, error) {
	if cfg.StoragePostgresDSN == "" {
		return nil, errors.New("storage.postgres.dsn must be set when storage.driver=postgres")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, poolErr := pgxpool.New(ctx, cfg.StoragePostgresDSN)
	if poolErr != nil {
		return nil, fmt.Errorf("connect to postgres: %w", poolErr)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()

		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	logger.Info("Postgres connection has been initialized")

	if err := newPgEvolver(pool, mutations.PostgresStorageMutations()).MutateSchema(); err != nil {
		pool.Close()

		return nil, fmt.Errorf("postgres schema mutation: %w", err)
	}

	logger.Info("Postgres schema has been initialized")

	return pool, nil
}

// initQueueStorage returns a queue.Storage along with a shutdown function
// that stops any background goroutines owned by the store (GC sweeper).
// The returned close fn is safe to call exactly once.
func initQueueStorage(cfg *config.Config, logger *slog.Logger, backend *storageBackend) (queue.Storage, func() error, error) {
	switch backend.driver {
	case storageDriverPostgres:
		opts := make([]queuepg.Option, 0, 2)

		if cfg.StorageLogEnable {
			opts = append(opts, queuepg.WithLogger(logger))
		}

		if cfg.StorageGCTimeout != 0 {
			opts = append(opts, queuepg.WithGCTimeout(cfg.StorageGCTimeout))
		}

		store, err := queuepg.New(backend.pgpool, opts...)
		if err != nil {
			return nil, nil, fmt.Errorf("create postgres queue storage: %w", err)
		}

		return store, store.Close, nil

	default:
		opts := make([]queuestore.Option, 0, 2)

		if cfg.StorageLogEnable {
			opts = append(opts, queuestore.WithLogger(logger))
		}

		if cfg.StorageGCTimeout != 0 {
			opts = append(opts, queuestore.WithGCTimeout(cfg.StorageGCTimeout))
		}

		store, err := queuestore.New(backend.sqlite, opts...)
		if err != nil {
			return nil, nil, fmt.Errorf("create sqlite queue storage: %w", err)
		}

		return store, store.Close, nil
	}
}

func initAccountStorage(cfg *config.Config, logger *slog.Logger, backend *storageBackend) (account.Storage, error) {
	switch backend.driver {
	case storageDriverPostgres:
		opts := make([]accountpg.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, accountpg.WithLogger(logger))
		}

		store, err := accountpg.NewStorage(backend.pgpool, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create postgres account storage: %w", err)
		}

		return store, nil

	default:
		opts := make([]accountstore.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, accountstore.WithLogger(logger))
		}

		store, err := accountstore.NewStorage(backend.sqlite, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create sqlite account storage: %w", err)
		}

		return store, nil
	}
}

func initRBACStorage(cfg *config.Config, logger *slog.Logger, backend *storageBackend) (rbac.Storage, error) {
	switch backend.driver {
	case storageDriverPostgres:
		opts := make([]rbacpg.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, rbacpg.WithLogger(logger))
		}

		store, err := rbacpg.NewStorage(backend.pgpool, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create postgres rbac storage: %w", err)
		}

		return store, nil

	default:
		opts := make([]rbacstore.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, rbacstore.WithLogger(logger))
		}

		store, err := rbacstore.NewStorage(backend.sqlite, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create sqlite rbac storage: %w", err)
		}

		return store, nil
	}
}

func initOnboardingStorage(cfg *config.Config, logger *slog.Logger, backend *storageBackend) (onboarding.Storage, error) {
	switch backend.driver {
	case storageDriverPostgres:
		opts := make([]onboardpg.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, onboardpg.WithLogger(logger))
		}

		store, err := onboardpg.NewStorage(backend.pgpool, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create postgres onboarding storage: %w", err)
		}

		return store, nil

	default:
		opts := make([]onboardstore.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, onboardstore.WithLogger(logger))
		}

		store, err := onboardstore.NewStorage(backend.sqlite, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create sqlite onboarding storage: %w", err)
		}

		return store, nil
	}
}

func initOAuthStorage(cfg *config.Config, logger *slog.Logger, backend *storageBackend) (oauth.Storage, error) {
	switch backend.driver {
	case storageDriverPostgres:
		opts := make([]oauthpg.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, oauthpg.WithLogger(logger))
		}

		store, err := oauthpg.NewStorage(backend.pgpool, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create postgres oauth storage: %w", err)
		}

		return store, nil

	default:
		opts := make([]oauthstore.Option, 0, 1)
		if cfg.StorageLogEnable {
			opts = append(opts, oauthstore.WithLogger(logger))
		}

		store, err := oauthstore.NewStorage(backend.sqlite, logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create sqlite oauth storage: %w", err)
		}

		return store, nil
	}
}

// initTokenManager builds a JWT token manager from the configured HMAC
// secret. Returns a clear error if the secret is missing — onboarding and
// account sessions depend on it to issue/verify tokens.
func initTokenManager(cfg *config.Config) (jwtkit.TokenManager, error) {
	if cfg.AuthJWTSecret == "" {
		return nil, errors.New("auth.jwt.secret is required for session issuance")
	}

	secret := []byte(cfg.AuthJWTSecret)

	signer, err := jwt.NewSignerHS(jwt.HS256, secret)
	if err != nil {
		return nil, fmt.Errorf("create jwt signer: %w", err)
	}

	verifier, err := jwt.NewVerifierHS(jwt.HS256, secret)
	if err != nil {
		return nil, fmt.Errorf("create jwt verifier: %w", err)
	}

	return jwtkit.NewTokenManager(signer, verifier), nil
}

func printAddrHTTP(addr string) string {
	if strings.HasPrefix(addr, "http") {
		return addr
	}

	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr
	}

	return addr
}

//nolint:nestif // path resolution for the telemetry DB has a few legitimate fallbacks.
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

			var absErr error

			dbPath, absErr = filepath.Abs(filepath.Join(pwd, "plainq_telemetry.db"))
			if absErr != nil {
				return nil, fmt.Errorf("resolve telemetry database path: %w", absErr)
			}
		}
	}

	logger.Info("Initializing telemetry database", slog.String("path", dbPath))

	connOption := make([]litekit.Option, 0, 2)

	// Use WAL mode for better concurrent performance.
	connOption = append(connOption, litekit.WithJournalMode(litekit.WAL))

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
