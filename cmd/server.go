package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/heartwilltell/hc"
	"github.com/heartwilltell/scotty"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/cluster"
	"github.com/marsolab/plainq/internal/server"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/interceptor"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/plainq/internal/server/service/account"
	accountstore "github.com/marsolab/plainq/internal/server/service/account/litestore"
	accountpg "github.com/marsolab/plainq/internal/server/service/account/pgstore"
	"github.com/marsolab/plainq/internal/server/service/agent"
	agentstore "github.com/marsolab/plainq/internal/server/service/agent/litestore"
	agentpg "github.com/marsolab/plainq/internal/server/service/agent/pgstore"
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
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/authkit/hashkit"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/logkit"
	"github.com/tursodatabase/libsql-client-go/libsql"
)

// storageDriverSQLite, storageDriverPostgres and storageDriverTurso are the
// accepted values for the --storage.driver flag.
const (
	storageDriverSQLite   = "sqlite"
	storageDriverPostgres = "postgres"
	storageDriverTurso    = "turso"
)

// storageBackend holds the underlying connection handle for whichever
// driver was selected. Exactly one of its fields is non-nil after
// initStorageBackend returns.
type storageBackend struct {
	driver string
	sqlite *litekit.Conn
	turso  *sql.DB
	pgpool *pgxpool.Pool
}

// lite returns the handle for the SQLite-dialect drivers — a local SQLite file
// or a remote Turso/libSQL database. It is nil when the Postgres driver is in
// use, and both are wired through the same litestore packages.
func (b *storageBackend) lite() pqlite.DB {
	switch {
	case b.sqlite != nil:
		return b.sqlite

	case b.turso != nil:
		return b.turso

	default:
		return nil
	}
}

func (b *storageBackend) Close() error {
	switch {
	case b.sqlite != nil:
		if err := b.sqlite.Close(); err != nil {
			return fmt.Errorf("close sqlite: %w", err)
		}

		return nil

	case b.turso != nil:
		if err := b.turso.Close(); err != nil {
			return fmt.Errorf("close turso: %w", err)
		}

		return nil

	case b.pgpool != nil:
		b.pgpool.Close()

		return nil
	}

	return nil
}

//nolint:cyclop,gocognit,funlen,gocyclo // CLI server setup wires the full dependency graph in one place.
func serverCommand() *commandSpec {
	var (
		cfg              config.Config
		clusterCfg       cluster.Config
		clusterDiscovery string
	)

	return &commandSpec{
		Name:     "serve",
		Short:    "Run the PlainQ server",
		Effect:   effectMutating,
		Blocking: true,
		Long: "Starts the queue server: the gRPC API every other command talks to, the\n" +
			"admin HTTP API, and the Houston web UI, all from this one process.\n\n" +
			"Storage defaults to an embedded SQLite database, so a server needs no\n" +
			"external dependencies to start. It runs until interrupted.\n\n" +
			"There are far more flags here than on any other command; run\n" +
			`"plainq serve -h" for the full list, or see the configuration guide.`,
		Examples: []exampleSpec{
			{
				Description: "Start a local server backed by SQLite.",
				Command:     `plainq serve --auth.jwt.secret="$(openssl rand -hex 32)"`,
			},
			{
				Description: "Start a server backed by PostgreSQL.",
				Command: "plainq serve -storage.driver=postgres \\\n" +
					`    -storage.postgres.dsn="postgres://user:pass@localhost:5432/plainq"`,
			},
		},
		SetFlags: func(f *scotty.FlagSet) {
			// Storage.
			f.StringVar(&cfg.StorageDriver, "storage.driver", "sqlite",
				"storage driver: 'sqlite' (default), 'postgres' or 'turso'",
			)

			f.StringVar(&cfg.StoragePostgresDSN, "storage.postgres.dsn", "",
				"PostgreSQL connection string (used when storage.driver=postgres)",
			)

			f.StringVar(&cfg.StorageTursoURL, "storage.turso.url", "",
				"Turso/libSQL database URL, e.g. libsql://db-org.turso.io (used when storage.driver=turso)",
			)

			f.StringVar(&cfg.StorageTursoAuthToken, "storage.turso.auth-token", "",
				"Turso auth token (used when storage.driver=turso; omit for unauthenticated sqld)",
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

			f.StringVar(&cfg.GRPCAdvertiseAddr, "grpc.advertise.addr", "",
				"routable gRPC address advertised to clustered followers",
			)

			f.StringVar(&cfg.GRPCProxyServerName, "grpc.proxy.server-name", "",
				"TLS server name used by clustered gRPC followers",
			)

			f.BoolVar(&cfg.GRPCProtectLegacy, "grpc.protect-legacy", false,
				"protect legacy v1 gRPC methods after their tenant migration is installed",
			)

			f.StringVar(&cfg.GRPCTLSMode, "grpc.tls.mode", "server",
				"gRPC TLS mode for agent APIs: server or mutual",
			)

			f.StringVar(&cfg.GRPCTLSCertFile, "grpc.tls.cert-file", "",
				"PEM certificate for the gRPC listener",
			)

			f.StringVar(&cfg.GRPCTLSKeyFile, "grpc.tls.key-file", "",
				"PEM private key for the gRPC listener certificate",
			)

			f.StringVar(&cfg.GRPCTLSClientCAFile, "grpc.tls.client-ca-file", "",
				"PEM client CA required by mutual gRPC TLS",
			)

			// Agent API. Enabling it is secure by default: unless the
			// development-only loopback exception is selected, TLS material is
			// required before any listener or storage is opened.
			f.BoolVar(&cfg.AgentEnable, "agent.enable", false,
				"enable agent-first gRPC messaging APIs",
			)

			f.BoolVar(&cfg.AgentDevelopmentInsecureTransport, "agent.development-insecure-transport", false,
				"allow plaintext agent gRPC transport only on an explicit loopback address",
			)

			f.StringVar(&cfg.AgentAuthIssuer, "agent.auth.issuer", "plainq",
				"issuer required in signed agent access tokens",
			)

			f.StringVar(&cfg.AgentAuthAudience, "agent.auth.audience", "plainq-agents",
				"audience required in signed agent access tokens",
			)

			f.StringVar(&cfg.AgentAuthJWTSecret, "agent.auth.jwt-secret", "",
				"HMAC secret for agent access tokens (at least 32 bytes)",
			)

			f.DurationVar(&cfg.AgentAccessTokenTTL, "agent.auth.access-token-ttl", 5*time.Minute,
				"short lifetime for agent access tokens (maximum 15 minutes)",
			)

			f.Float64Var(&cfg.AgentRateRequestsPerSecond, "agent.rate.requests-per-second", 100,
				"node-local authenticated request rate per tenant/principal",
			)

			f.IntVar(&cfg.AgentRateBurst, "agent.rate.burst", 200,
				"node-local authenticated request burst per tenant/principal",
			)

			f.StringVar(&cfg.HTTPAddr, "http.addr", ":8081",
				"set HTTP listener address",
			)

			f.DurationVar(&cfg.HTTPReadHeaderTimeout, "http.read-header-timeout", 0,
				"how long the HTTP server waits for request headers (0 means no limit)",
			)

			f.DurationVar(&cfg.HTTPReadTimeout, "http.read-timeout", 0,
				"how long the HTTP server waits for a whole request (0 means no limit)",
			)

			f.DurationVar(&cfg.HTTPWriteTimeout, "http.write-timeout", 0,
				"how long the HTTP server may take to write a response (0 means no limit)",
			)

			f.DurationVar(&cfg.HTTPIdleTimeout, "http.idle-timeout", 0,
				"how long an idle keep-alive connection is held open (0 means no limit)",
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
				"enable the health endpoint",
			)

			f.BoolVar(&cfg.HealthRouteLogs, "health.route.logs", false,
				"turn on access logs for health endpoint",
			)

			f.BoolVar(&cfg.HealthRouteMetrics, "health.route.metrics", false,
				"turn on metrics for health endpoint",
			)

			f.StringVar(&cfg.HealthRoute, "health.route", "/health",
				"set given route as health endpoint route",
			)

			f.StringVar(&cfg.HealthReporter, "health.reporter", "",
				"set health endpoint reporter",
			)

			// CORS.

			f.BoolVar(&cfg.CORSEnable, "cors", true,
				"enable CORS configuration for Houston API routes",
			)

			// Profiler.

			f.BoolVar(&cfg.ProfilerEnabled, "profiler", false,
				"enable the profiler endpoint",
			)

			// Cluster.

			setClusterFlags(f, &clusterCfg, &clusterDiscovery)
		},

		Run: func(_ *scotty.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			logger, loggerErr := initLogger(&cfg)
			if loggerErr != nil {
				return loggerErr
			}

			logger.Info("Starting plainq server")

			if err := validateAgentSecurity(&cfg, &clusterCfg); err != nil {
				return err
			}

			var checker hc.HealthChecker = hc.NewNopChecker()

			if cfg.HealthEnable {
				reporter := hc.NewServiceReport()
				checker = hc.NewMultiServiceChecker(reporter)
			}

			// Storage initialization.

			// A cluster member takes long-running read transactions to
			// snapshot its state. In rollback-journal mode those block every
			// writer for the duration; in WAL mode they do not. Cluster mode
			// therefore needs WAL, and asking for anything else is a
			// configuration error rather than something to quietly override.
			if clusterCfg.Enabled {
				switch strings.ToLower(cfg.StorageJournalMode) {
				case "":
					cfg.StorageJournalMode = "wal"

				case "wal":

				default:
					return fmt.Errorf(
						"cluster mode needs storage.journal-mode=wal, not %q: snapshots take long read "+
							"transactions, and outside WAL those stall every write",
						cfg.StorageJournalMode,
					)
				}
			}

			backend, backendErr := initStorageBackend(&cfg, logger)
			if backendErr != nil {
				return backendErr
			}

			// One observer, shared by the storage layer and — once the
			// telemetry store is open — by the collector behind Houston's
			// dashboards. Both then describe the same events instead of two
			// independently-wired approximations of them.
			observer := telemetry.NewObserver(backend.driver)

			registerRuntimeMetrics(backend)

			defer func() {
				if err := backend.Close(); err != nil {
					logger.Error("Failed to close storage backend",
						slog.String("error", err.Error()),
					)
				}
			}()

			queueStorage, queueClose, queueStorageInitErr := initQueueStorage(&cfg, &clusterCfg, logger, backend, observer)
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

			// In a cluster the queue service talks to the replicated store
			// instead of the local one. Everything above this line is
			// unchanged: the service does not know which it got.
			var clusterNode *cluster.Node

			if clusterCfg.Enabled {
				node, nodeErr := initClusterNode(&cfg, &clusterCfg, clusterDiscovery, logger, queueStorage)
				if nodeErr != nil {
					return nodeErr
				}

				clusterNode = node
				queueStorage = node.Store()

				defer func() {
					if err := clusterNode.Close(); err != nil {
						logger.Error("Failed to stop the cluster node",
							slog.String("error", err.Error()),
						)
					}
				}()

				if err := clusterNode.Start(ctx); err != nil {
					return fmt.Errorf("start cluster node: %w", err)
				}
			}

			// Wrapping here, after the cluster layer, means one seam measures
			// every backend: SQLite, Postgres and the replicated store alike.
			queueService := queue.NewService(&cfg, logger, queue.NewObservedStorage(queueStorage, observer))

			accountStorage, accountStorageInitErr := initAccountStorage(&cfg, logger, backend)
			if accountStorageInitErr != nil {
				return accountStorageInitErr
			}

			hasher := hashkit.NewBCryptHasher()

			tokenManager, tokenErr := initTokenManager(&cfg)
			if tokenErr != nil {
				return tokenErr
			}

			accountService := account.NewService(&cfg, logger, hasher, tokenManager, accountStorage)

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

			serverOpts = append(serverOpts, server.WithObserver(observer))
			serverOpts = append(serverOpts, server.WithServerVersion(Commit))

			if cfg.AgentEnable {
				agentOption, agentOptionErr := initAgentServerOption(&cfg, backend, tokenManager, accountStorage)
				if agentOptionErr != nil {
					return agentOptionErr
				}

				serverOpts = append(serverOpts, agentOption)
			}

			if clusterNode != nil {
				serverOpts = append(serverOpts, server.WithClusterNode(clusterNode))
			}

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

			plainqServer, serverErr := server.NewServer(&cfg, logger, checker, tokenManager, queueService, accountService,
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
}

//nolint:gocyclo,cyclop // validation mirrors the explicit security contract one rule at a time.
func validateAgentSecurity(cfg *config.Config, clusterCfg *cluster.Config) error {
	if !cfg.AgentEnable {
		return nil
	}

	if len(cfg.AgentAuthJWTSecret) < 32 {
		return errors.New("agent JWT secret must be at least 32 bytes")
	}

	if cfg.AgentAuthIssuer == "" || cfg.AgentAuthAudience == "" {
		return errors.New("agent token issuer and audience are required")
	}

	if cfg.AgentAccessTokenTTL <= 0 || cfg.AgentAccessTokenTTL > 15*time.Minute {
		return errors.New("agent access token TTL must be between zero and 15 minutes")
	}

	if err := cfg.ValidateAgentAdmission(); err != nil {
		return fmt.Errorf("validate agent admission: %w", err)
	}

	if cfg.AgentDevelopmentInsecureTransport {
		host, _, err := net.SplitHostPort(cfg.GRPCAddr)
		if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
			return errors.New("insecure agent transport requires a loopback gRPC address")
		}

		return nil
	}

	if cfg.GRPCTLSMode != "server" && cfg.GRPCTLSMode != "mutual" {
		return errors.New("agent APIs require server or mutual gRPC TLS mode")
	}

	if cfg.GRPCTLSCertFile == "" || cfg.GRPCTLSKeyFile == "" {
		return errors.New("agent APIs require a gRPC TLS certificate and key")
	}

	if cfg.GRPCTLSMode == "mutual" && cfg.GRPCTLSClientCAFile == "" {
		return errors.New("mutual gRPC TLS requires a client CA")
	}

	if clusterCfg != nil && clusterCfg.Enabled &&
		(cfg.GRPCAdvertiseAddr == "" || isWildcardAddress(cfg.GRPCAdvertiseAddr)) {
		return errors.New("clustered agent APIs require a routable gRPC advertise address")
	}

	return nil
}

func initAgentServerOption(
	cfg *config.Config,
	backend *storageBackend,
	humanTokens jwtkit.TokenManager,
	accountStorage account.Storage,
) (server.Option, error) {
	agentStorage, err := initAgentStorage(backend)
	if err != nil {
		return nil, err
	}

	agentTokens, err := security.NewAgentTokenManager(security.AgentTokenConfig{
		Issuer: cfg.AgentAuthIssuer, Audience: cfg.AgentAuthAudience,
		Secret: []byte(cfg.AgentAuthJWTSecret), TTL: cfg.AgentAccessTokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("create agent token manager: %w", err)
	}

	agentService, err := agent.NewService(agent.ServiceConfig{
		Registry: agentStorage, Principals: agentStorage, Credentials: agentStorage, Tokens: agentTokens,
		PreAuth: agent.PreAuthConfig{RequestsPerSecond: 5, Burst: 10, MaxEntries: 4096},
	})
	if err != nil {
		return nil, fmt.Errorf("create agent service: %w", err)
	}

	agentTransport, err := agent.NewGRPCTransport(agentService)
	if err != nil {
		return nil, fmt.Errorf("create agent gRPC transport: %w", err)
	}

	authenticator, err := interceptor.NewCompositeAuthenticator(
		agentService, humanTokens, accountStorage, accountStorage,
	)
	if err != nil {
		return nil, fmt.Errorf("create gRPC authenticator: %w", err)
	}

	resourceAuthorizer, err := interceptor.NewStoreResourceAuthorizer(agentStorage)
	if err != nil {
		return nil, fmt.Errorf("create resource authorizer: %w", err)
	}

	admission, err := interceptor.NewPrincipalAdmissionLimiter(
		cfg.AgentRateRequestsPerSecond, cfg.AgentRateBurst,
	)
	if err != nil {
		return nil, fmt.Errorf("create principal admission limiter: %w", err)
	}

	return server.WithAgentMessaging(agentTransport, authenticator, resourceAuthorizer, admission), nil
}

func isWildcardAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsUnspecified()
}

func initLogger(cfg *config.Config) (*slog.Logger, error) {
	logger := logkit.NewNop()

	if cfg.LogEnable {
		level, levelErr := logkit.ParseLevel(cfg.LogLevel)
		if levelErr != nil {
			return nil, fmt.Errorf("parse log level: %w", levelErr)
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

	case storageDriverTurso:
		conn, err := initTursoBackend(cfg, logger)
		if err != nil {
			return nil, err
		}

		return &storageBackend{driver: storageDriverTurso, turso: conn}, nil

	case storageDriverPostgres:
		pool, err := initPostgresBackend(cfg, logger)
		if err != nil {
			return nil, err
		}

		return &storageBackend{driver: storageDriverPostgres, pgpool: pool}, nil

	default:
		return nil, fmt.Errorf("unsupported storage driver %q (want %q, %q or %q)",
			driver, storageDriverSQLite, storageDriverPostgres, storageDriverTurso,
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
			return nil, fmt.Errorf("parse storage access mode: %w", err)
		}

		connOption = append(connOption, litekit.WithAccessMode(mode))
	}

	if cfg.StorageJournalMode != "" {
		mode, err := litekit.JournalModeFromString(cfg.StorageJournalMode)
		if err != nil {
			return nil, fmt.Errorf("parse storage journal mode: %w", err)
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

	validated, validationErr := mutations.ValidatedStorageFS(mutations.SqliteStorageMutations())
	if validationErr != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("validate sqlite schema mutations: %w", validationErr)
	}

	evolver, evolverErr := litekit.NewEvolver(conn, validated)
	if evolverErr != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("create schema evolver: %w", evolverErr)
	}

	if err := evolver.MutateSchema(); err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("schema mutation: %w", err)
	}

	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer verifyCancel()

	if err := verifySQLiteForeignKeys(verifyCtx, conn); err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("verify sqlite foreign keys: %w", err)
	}

	logger.Info("SQLite schema has been initialized",
		slog.String("path", cfg.StorageDBPath),
	)

	return conn, nil
}

// tursoMaxIdleConns caps the pooled libSQL connections kept warm between
// queries. Every connection is an HTTP session to a remote database, so the
// database/sql default of two would mean reconnecting under any real
// concurrency.
const tursoMaxIdleConns = 10

// initTursoBackend opens a Turso/libSQL database and brings its schema up to
// date. libSQL shares the SQLite dialect, so the same embedded mutations and
// the same litestore packages serve both drivers.
func initTursoBackend(cfg *config.Config, logger *slog.Logger) (*sql.DB, error) {
	dsn, dsnErr := parseTursoDSN(cfg.StorageTursoURL, cfg.StorageTursoAuthToken)
	if dsnErr != nil {
		return nil, dsnErr
	}

	connOptions := make([]libsql.Option, 0, 1)

	if dsn.authToken != "" {
		connOptions = append(connOptions, libsql.WithAuthToken(dsn.authToken))
	}

	connector, connectorErr := libsql.NewConnector(dsn.url, connOptions...)
	if connectorErr != nil {
		return nil, fmt.Errorf("create turso connector: %w", connectorErr)
	}

	db := sql.OpenDB(connector)
	db.SetMaxIdleConns(tursoMaxIdleConns)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close turso connection: %w", closeErr))
		}

		return nil, fmt.Errorf("connect to turso: %w", err)
	}

	logger.Info("Turso database connection has been initialized",
		slog.String("url", dsn.url),
	)

	if err := newTursoEvolver(db, mutations.SqliteStorageMutations()).MutateSchema(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close turso connection: %w", closeErr))
		}

		return nil, fmt.Errorf("turso schema mutation: %w", err)
	}

	if err := verifySQLiteForeignKeys(ctx, db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close turso connection: %w", closeErr))
		}

		return nil, fmt.Errorf("verify turso foreign keys: %w", err)
	}

	logger.Info("Turso schema has been initialized")

	return db, nil
}

// verifySQLiteForeignKeys proves that connection-local FK enforcement is
// active on two concurrently acquired pool connections. The orphan probes run
// in rolled-back transactions and therefore never leave startup data behind.
//
//nolint:cyclop // Both pooled connections are independently proven and cleaned up.
func verifySQLiteForeignKeys(ctx context.Context, db pqlite.DB) (vErr error) {
	connections := make([]*sql.Conn, 0, 2)
	defer func() {
		for _, conn := range connections {
			if err := conn.Close(); err != nil {
				vErr = errors.Join(vErr, fmt.Errorf("close foreign-key probe connection: %w", err))
			}
		}
	}()

	for range 2 {
		conn, err := db.Conn(ctx)
		if err != nil {
			return fmt.Errorf("acquire foreign-key probe connection: %w", err)
		}

		connections = append(connections, conn)
	}

	for index, conn := range connections {
		if err := pqlite.EnforceForeignKeys(ctx, conn); err != nil {
			return fmt.Errorf("connection %d: %w", index+1, err)
		}

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("connection %d begin orphan probe: %w", index+1, err)
		}

		_, insertErr := tx.ExecContext(ctx, `
			INSERT INTO agents (
				agent_id, tenant_id, agent_name, status, auth_version,
				created_by_kind, created_by_id, created_at_ns, updated_at_ns
			) VALUES (?, ?, ?, 1, 1, 'system', 'startup-probe', 0, 0)`,
			fmt.Sprintf("plainq-fk-probe-%d", index+1),
			fmt.Sprintf("plainq-missing-tenant-%d", index+1),
			fmt.Sprintf("plainq-fk-probe-%d", index+1),
		)

		rollbackErr := tx.Rollback()
		if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return fmt.Errorf("connection %d rollback orphan probe: %w", index+1, rollbackErr)
		}

		if insertErr == nil {
			return fmt.Errorf("connection %d accepted an orphan agent insert", index+1)
		}

		message := strings.ToUpper(insertErr.Error())
		if !strings.Contains(message, "FOREIGN KEY") &&
			!strings.Contains(message, "SQLITE_CONSTRAINT_FOREIGNKEY") {
			return fmt.Errorf("connection %d orphan probe failed unexpectedly: %w", index+1, insertErr)
		}
	}

	return nil
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
//
//nolint:cyclop // One branch per storage driver and per optional store setting.
func initQueueStorage(
	cfg *config.Config,
	clusterCfg *cluster.Config,
	logger *slog.Logger,
	backend *storageBackend,
	observer *telemetry.Observer,
) (queue.Storage, func() error, error) {
	switch backend.driver {
	case storageDriverTurso:
		if clusterCfg.Enabled {
			return nil, nil, errors.New(
				"cluster mode replicates the embedded store, so it needs storage.driver=sqlite. " +
					"A Turso database is already shared between nodes and replicating it " +
					"would write every message twice",
			)
		}

		opts := make([]queuestore.Option, 0, 3)

		opts = append(opts, queuestore.WithObserver(observer))

		if cfg.StorageLogEnable {
			opts = append(opts, queuestore.WithLogger(logger))
		}

		if cfg.StorageGCTimeout != 0 {
			opts = append(opts, queuestore.WithGCTimeout(cfg.StorageGCTimeout))
		}

		store, err := queuestore.New(backend.lite(), opts...)
		if err != nil {
			return nil, nil, fmt.Errorf("create turso queue storage: %w", err)
		}

		return store, store.Close, nil

	case storageDriverPostgres:
		if clusterCfg.Enabled {
			return nil, nil, errors.New(
				"cluster mode replicates the embedded store, so it needs storage.driver=sqlite. " +
					"With Postgres the database is already shared between nodes and replicating it " +
					"would write every message twice",
			)
		}

		opts := make([]queuepg.Option, 0, 3)

		opts = append(opts, queuepg.WithObserver(observer))

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
		opts := make([]queuestore.Option, 0, 4)

		opts = append(opts, queuestore.WithObserver(observer))

		if cfg.StorageLogEnable {
			opts = append(opts, queuestore.WithLogger(logger))
		}

		if cfg.StorageGCTimeout != 0 {
			opts = append(opts, queuestore.WithGCTimeout(cfg.StorageGCTimeout))
		}

		// A cluster member does not sweep on its own schedule — the leader
		// proposes eviction through the consensus log so every replica drops
		// the same rows.
		if clusterCfg.Enabled {
			opts = append(opts, queuestore.WithoutGC())
		}

		store, err := queuestore.New(backend.lite(), opts...)
		if err != nil {
			return nil, nil, fmt.Errorf("create %s queue storage: %w", backend.driver, err)
		}

		return store, store.Close, nil
	}
}

// initClusterNode assembles the cluster layer around the local store.
func initClusterNode(
	cfg *config.Config,
	clusterCfg *cluster.Config,
	discovery string,
	logger *slog.Logger,
	local queue.Storage,
) (*cluster.Node, error) {
	replicated, ok := local.(queue.ReplicatedStorage)
	if !ok {
		return nil, fmt.Errorf(
			"storage backend %T cannot be replicated: it does not support snapshot and restore", local,
		)
	}

	if discovery != "" {
		clusterCfg.Discovery = append(clusterCfg.Discovery, discovery)
	}

	if clusterCfg.DataDir == "" {
		clusterCfg.DataDir = filepath.Join(filepath.Dir(cfg.StorageDBPath), "cluster")
	}

	if clusterCfg.Version == "" {
		clusterCfg.Version = Commit
	}

	node, err := cluster.NewNode(*clusterCfg, replicated, logger)
	if err != nil {
		return nil, fmt.Errorf("create cluster node: %w", err)
	}

	return node, nil
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

		store, err := accountstore.NewStorage(backend.lite(), logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create %s account storage: %w", backend.driver, err)
		}

		return store, nil
	}
}

func initAgentStorage(backend *storageBackend) (agent.Store, error) {
	switch backend.driver {
	case storageDriverPostgres:
		store, err := agentpg.NewStorage(backend.pgpool)
		if err != nil {
			return nil, fmt.Errorf("create postgres agent storage: %w", err)
		}

		return store, nil

	default:
		store, err := agentstore.NewStorage(backend.lite())
		if err != nil {
			return nil, fmt.Errorf("create %s agent storage: %w", backend.driver, err)
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

		store, err := rbacstore.NewStorage(backend.lite(), logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create %s rbac storage: %w", backend.driver, err)
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

		store, err := onboardstore.NewStorage(backend.lite(), logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create %s onboarding storage: %w", backend.driver, err)
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

		store, err := oauthstore.NewStorage(backend.lite(), logger, opts...)
		if err != nil {
			return nil, fmt.Errorf("create %s oauth storage: %w", backend.driver, err)
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
