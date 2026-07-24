package server

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/servekit/httpkit"
)

// FormatDuration marks a fact whose value is a whole number of seconds, so a
// client formats it with the same rules it uses for every other duration
// instead of parsing prose.
const FormatDuration = "duration"

// ConfigFact is one setting of the running instance.
//
// A fact either carries a value or states why it does not. Redacted marks
// something the server holds and refuses to hand over — it is the difference
// between "there is no signing secret" and "there is one, and you may not read
// it", which an operator needs to tell apart.
type ConfigFact struct {
	Label    string `json:"label"`
	Value    string `json:"value,omitempty"`
	Format   string `json:"format,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
	Note     string `json:"note,omitempty"`
}

// ConfigGroup is a panel's worth of related facts.
type ConfigGroup struct {
	Title string       `json:"title"`
	Facts []ConfigFact `json:"facts"`
}

// ConfigResponse is the sanitized view of the effective runtime configuration.
type ConfigResponse struct {
	Groups []ConfigGroup `json:"groups"`

	// ReadAt is when the values were read off the running instance. Every
	// setting below is applied at startup, so this is the age of the answer,
	// not of the configuration.
	ReadAt time.Time `json:"read_at"`
}

// SystemHandler answers questions about the instance itself.
type SystemHandler struct {
	cfg *config.Config
}

// NewSystemHandler returns a handler reading from the effective configuration.
func NewSystemHandler(cfg *config.Config) *SystemHandler {
	return &SystemHandler{cfg: cfg}
}

// GetConfig answers with the sanitized runtime configuration.
//
// The values come from the config struct the server was built with, so what it
// reports is what the process is running — not a description of what a PlainQ
// configuration looks like. Nothing that could authenticate anybody is included:
// secrets are named and marked redacted, never masked into a lookalike string.
func (h *SystemHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg

	groups := []ConfigGroup{
		{Title: "Storage", Facts: storageFacts(cfg)},
		{Title: "Authentication", Facts: authFacts(cfg)},
		{Title: "Identity providers", Facts: oauthFacts(cfg)},
		{Title: "Telemetry", Facts: telemetryFacts(cfg)},
		{Title: "Network", Facts: networkFacts(cfg)},
		{Title: "Observability", Facts: observabilityFacts(cfg)},
		{Title: "Logging", Facts: loggingFacts(cfg)},
	}

	httpkit.JSON(w, r, ConfigResponse{Groups: groups, ReadAt: time.Now()})
}

// unsetNote is what an absent value means: the process did not choose one, so
// the subsystem's own default is in force. Naming that default here would be
// reporting a value nothing read.
const unsetNote = "Unset — the subsystem's own default applies."

func storageFacts(cfg *config.Config) []ConfigFact {
	facts := []ConfigFact{
		{Label: "Driver", Value: orUnset(cfg.StorageDriver)},
	}

	if cfg.StorageDriver == "postgres" {
		facts = append(facts, ConfigFact{
			Label:    "DSN",
			Value:    redactDSN(cfg.StoragePostgresDSN),
			Redacted: true,
			Note:     "Credentials removed.",
		})
	} else {
		facts = append(facts,
			ConfigFact{Label: "Database file", Value: orUnset(cfg.StorageDBPath)},
			noteWhenUnset(ConfigFact{Label: "Access mode", Value: orUnset(cfg.StorageAccessMode)}),
			noteWhenUnset(ConfigFact{Label: "Journal mode", Value: orUnset(cfg.StorageJournalMode)}),
		)
	}

	return append(facts,
		durationFact("GC interval", cfg.StorageGCTimeout),
		ConfigFact{Label: "Query log", Value: enabled(cfg.StorageLogEnable)},
	)
}

func authFacts(cfg *config.Config) []ConfigFact {
	facts := []ConfigFact{
		{Label: "Status", Value: enabled(cfg.AuthEnable)},
	}

	if !cfg.AuthEnable {
		// Reporting token lifetimes for a server that issues no tokens would
		// describe a subsystem that is not running.
		return append(facts, ConfigFact{
			Label: "API access",
			Value: "unauthenticated",
			Note:  "Authentication is off, so every API route is open.",
		})
	}

	return append(facts,
		ConfigFact{Label: "Registration", Value: enabled(cfg.AuthRegistrationEnable)},
		durationFact("Access token TTL", cfg.AuthAccessTokenTTL),
		durationFact("Refresh token TTL", cfg.AuthRefreshTokenTTL),
		ConfigFact{Label: "Email verification", Value: requiredOrNot(cfg.AuthEmailVerificationEnable)},
		ConfigFact{
			Label:    "Signing secret",
			Value:    presence(cfg.AuthJWTSecret != ""),
			Redacted: true,
			Note:     "Never returned.",
		},
	)
}

func oauthFacts(cfg *config.Config) []ConfigFact {
	facts := []ConfigFact{
		{Label: "Status", Value: enabled(cfg.OAuthEnable)},
	}

	if !cfg.OAuthEnable {
		return facts
	}

	facts = append(facts,
		ConfigFact{Label: "Provider", Value: orUnset(cfg.OAuthProvider)},
		ConfigFact{Label: "Domain", Value: orUnset(cfg.OAuthDomain)},
		ConfigFact{Label: "Audience", Value: orUnset(cfg.OAuthAudience)},
		ConfigFact{Label: "Client ID", Value: orUnset(cfg.OAuthClientID)},
		ConfigFact{
			Label:    "Client secret",
			Value:    presence(cfg.OAuthClientSecret != ""),
			Redacted: true,
			Note:     "Never returned.",
		},
		ConfigFact{Label: "Callback URL", Value: orUnset(cfg.OAuthCallbackURL)},
		ConfigFact{Label: "Scope", Value: orUnset(cfg.OAuthScope)},
		ConfigFact{Label: "JWKS URL", Value: orUnset(cfg.OAuthJWKSURL)},
		ConfigFact{Label: "User synchronization", Value: enabled(cfg.OAuthUserSyncEnable)},
	)

	if cfg.OAuthUserSyncEnable {
		facts = append(facts, durationFact("Synchronization interval", cfg.OAuthUserSyncInterval))
	}

	return append(facts,
		ConfigFact{Label: "Multi-tenancy", Value: enabled(cfg.MultiTenancyEnable)},
		ConfigFact{Label: "Default organization", Value: orUnset(cfg.DefaultOrganization)},
		ConfigFact{Label: "Team-based permissions", Value: enabled(cfg.TeamBasedPermissions)},
	)
}

func telemetryFacts(cfg *config.Config) []ConfigFact {
	facts := []ConfigFact{
		{Label: "Status", Value: enabled(cfg.TelemetryEnabled)},
	}

	if !cfg.TelemetryEnabled {
		return facts
	}

	facts = append(facts, ConfigFact{Label: "Provider", Value: orUnset(cfg.TelemetryProvider)})

	switch cfg.TelemetryProvider {
	case "prometheus":
		facts = append(facts, ConfigFact{Label: "Prometheus base URL", Value: orUnset(cfg.TelemetryPromBaseURL)})

	default:
		facts = append(facts,
			ConfigFact{Label: "Database file", Value: orUnset(cfg.TelemetryLiteDBPath)},
			durationFact("Collection interval", cfg.TelemetryLiteScrapeTimeout),
			durationFact("Retention", cfg.TelemetryLiteRetentionPeriod),
		)
	}

	return facts
}

func networkFacts(cfg *config.Config) []ConfigFact {
	return []ConfigFact{
		{Label: "HTTP listen", Value: orUnset(cfg.HTTPAddr)},
		{Label: "gRPC listen", Value: orUnset(cfg.GRPCAddr)},
		durationFact("Read timeout", cfg.HTTPReadTimeout),
		durationFact("Read header timeout", cfg.HTTPReadHeaderTimeout),
		durationFact("Write timeout", cfg.HTTPWriteTimeout),
		durationFact("Idle timeout", cfg.HTTPIdleTimeout),
		{Label: "CORS", Value: enabled(cfg.CORSEnable)},
	}
}

func observabilityFacts(cfg *config.Config) []ConfigFact {
	facts := []ConfigFact{
		{Label: "Health check", Value: enabled(cfg.HealthEnable)},
	}

	if cfg.HealthEnable {
		facts = append(facts,
			ConfigFact{Label: "Health route", Value: orUnset(cfg.HealthRoute)},
			ConfigFact{Label: "Health reporter", Value: orUnset(cfg.HealthReporter)},
		)
	}

	facts = append(facts, ConfigFact{Label: "Metrics endpoint", Value: enabled(cfg.MetricsEnable)})

	if cfg.MetricsEnable {
		facts = append(facts, ConfigFact{Label: "Metrics route", Value: orUnset(cfg.MetricsRoute)})
	}

	return append(facts, ConfigFact{
		Label: "Profiler",
		Value: exposure(cfg.ProfilerEnabled),
	})
}

func loggingFacts(cfg *config.Config) []ConfigFact {
	facts := []ConfigFact{
		{Label: "Status", Value: enabled(cfg.LogEnable)},
	}

	if !cfg.LogEnable {
		return facts
	}

	return append(facts,
		ConfigFact{Label: "Level", Value: orUnset(cfg.LogLevel)},
		ConfigFact{Label: "Access log", Value: enabled(cfg.LogAccessEnable)},
		ConfigFact{Label: "Access log for all routes", Value: enabled(cfg.LogAccessEnableAll)},
	)
}

// redactDSN removes the credentials from a database DSN, keeping the parts an
// operator needs to recognise which database the process opened.
//
// A DSN that cannot be parsed is not passed through on the chance that it is
// harmless — an unparseable string is exactly where a password would survive.
func redactDSN(dsn string) string {
	if dsn == "" {
		return "not set"
	}

	parsed, err := url.Parse(dsn)
	if err != nil {
		return "unreadable — withheld"
	}

	if parsed.User != nil {
		// User.Username() keeps the account name, which identifies the
		// connection; the password is dropped rather than masked so nothing
		// resembling a credential is ever rendered.
		parsed.User = url.User(parsed.User.Username())
	}

	if query := parsed.Query(); len(query) > 0 {
		for key := range query {
			if isSecretDSNParam(key) {
				query.Set(key, "")
			}
		}

		parsed.RawQuery = query.Encode()
	}

	return parsed.String()
}

func isSecretDSNParam(key string) bool {
	switch key {
	case "password", "sslpassword", "sslkey":
		return true

	default:
		return false
	}
}

// durationFact reports a timeout or interval.
//
// A zero duration is "not set", never "0 s": the second reads as an interval of
// no time at all, which is a setting nobody chose and no subsystem honours.
func durationFact(label string, d time.Duration) ConfigFact {
	if d <= 0 {
		return noteWhenUnset(ConfigFact{Label: label, Value: "not set"})
	}

	return ConfigFact{
		Label:  label,
		Value:  strconv.FormatInt(int64(d.Seconds()), 10),
		Format: FormatDuration,
	}
}

// noteWhenUnset explains an absent value rather than leaving it bare.
func noteWhenUnset(fact ConfigFact) ConfigFact {
	if fact.Value == "not set" {
		fact.Note = unsetNote
	}

	return fact
}

func enabled(on bool) string {
	if on {
		return "enabled"
	}

	return "disabled"
}

func requiredOrNot(on bool) string {
	if on {
		return "required"
	}

	return "not required"
}

func exposure(on bool) string {
	if on {
		return "exposed"
	}

	return "not exposed"
}

func presence(set bool) string {
	if set {
		return "set"
	}

	return "not set"
}

func orUnset(value string) string {
	if value == "" {
		return "not set"
	}

	return value
}
