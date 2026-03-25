package config

import (
	"time"
)

// Config represents the configuration for the PlainQ server.
// See the cmd/server.go to understand the meanings of each field
// and default values.
type Config struct {
	LogEnable          bool
	LogAccessEnable    bool
	LogAccessEnableAll bool
	LogLevel           string

	GRPCAddr string
	HTTPAddr string

	HTTPReadTimeout       time.Duration
	HTTPReadHeaderTimeout time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration

	StorageLogEnable   bool
	StorageDBPath      string
	StorageGCTimeout   time.Duration
	StorageAccessMode  string
	StorageJournalMode string

	// Authentication configuration
	AuthEnable                  bool
	AuthRegistrationEnable      bool
	AuthAccessTokenTTL          time.Duration
	AuthRefreshTokenTTL         time.Duration
	AuthEmailVerificationEnable bool

	// OAuth configuration
	OAuthEnable           bool
	OAuthProvider         string // "kinde", "auth0", "okta", "google", etc.
	OAuthClientID         string
	OAuthClientSecret     string
	OAuthDomain           string
	OAuthAudience         string
	OAuthCallbackURL      string
	OAuthScope            string
	OAuthJWKSURL          string
	OAuthUserSyncEnable   bool // Whether to sync users from OAuth to local DB
	OAuthUserSyncInterval time.Duration
	OAuthRoleClaimName    string // JWT claim name for roles (e.g., "roles", "permissions")
	OAuthOrgClaimName     string // JWT claim name for organization (e.g., "org_code", "organization")
	OAuthTeamClaimName    string // JWT claim name for teams (e.g., "teams", "groups")

	// Organization and team features
	MultiTenancyEnable   bool   // Enable organization-based multi-tenancy
	DefaultOrganization  string // Default organization for single-tenant mode
	TeamBasedPermissions bool   // Enable team-based permissions

	TelemetryEnabled   bool
	TelemetryLogEnable bool
	TelemetryProvider  string

	TelemetryPromBaseURL string

	TelemetryLiteDBPath          string
	TelemetryLiteGCTimeout       time.Duration
	TelemetryLiteAccessMode      string
	TelemetryLiteJournalMode     string
	TelemetryLiteScrapeTimeout   time.Duration
	TelemetryLiteRetentionPeriod time.Duration

	CORSEnable bool

	HealthEnable       bool
	HealthRouteLogs    bool
	HealthRouteMetrics bool
	HealthRoute        string

	MetricsEnable       bool
	MetricsRouteLogs    bool
	MetricsRouteMetrics bool
	MetricsRoute        string

	ProfilerEnabled bool
}
