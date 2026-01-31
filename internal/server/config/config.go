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

	// Authentication settings
	AuthEnabled      bool
	AuthJWTSecret    string
	AuthIssuer       string
	AuthOAuthBaseURL string // Base URL for OAuth callbacks (e.g., "https://example.com")
}
