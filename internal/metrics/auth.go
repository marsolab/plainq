package metrics

// Authentication and authorization label names.
const (
	labelScheme     = "scheme"
	labelOutcome    = "outcome"
	labelCheck      = "check"
	labelDecision   = "decision"
	labelPermission = "permission"
	labelProvider   = "provider"
	labelStage      = "stage"
)

// Authentication schemes.
const (
	SchemeJWT   = "jwt"
	SchemeOAuth = "oauth"
)

// Authentication outcomes.
//
// These are deliberately finer than ok/error. "Requests were rejected" is not
// actionable; "requests were rejected because the token was revoked" tells an
// operator whether they are looking at an attack, an expired secret, or a
// client that never sends credentials at all.
const (
	AuthOK                  = "ok"
	AuthMissingCredentials  = "missing_credentials"
	AuthMalformedHeader     = "malformed_header"
	AuthInvalidToken        = "invalid_token"
	AuthRevokedToken        = "revoked_token"
	AuthDenylistUnavailable = "denylist_unavailable"
	AuthIncompleteClaims    = "incomplete_claims"
	AuthSyncFailed          = "sync_failed"
)

// Authorization checks and decisions.
const (
	CheckRole            = "role"
	CheckQueuePermission = "queue_permission"

	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionError = "error"
)

// Authentication, authorization and onboarding metrics.
var (
	authentications = NewCounterVec(Definition{
		Name:   Namespace + "_auth_attempts_total",
		Help:   "Authentication attempts by scheme and outcome. A climbing invalid_token rate on a stable client set is worth a look.",
		Labels: []string{labelScheme, labelOutcome},
	})

	authorizations = NewCounterVec(Definition{
		Name:   Namespace + "_authz_decisions_total",
		Help:   "Authorization decisions by check and outcome. Denials are normal; errors mean the permission store is failing open or closed.",
		Labels: []string{labelCheck, labelPermission, labelDecision},
	})

	oauthRequests = NewCounterVec(Definition{
		Name:   Namespace + "_oauth_requests_total",
		Help:   "Calls out to an OAuth provider, by stage of the flow and outcome.",
		Labels: []string{labelProvider, labelStage, labelResult},
	})

	oauthDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_oauth_request_duration_seconds",
		Help:   "Latency of calls out to an OAuth provider. A slow provider becomes a slow login.",
		Labels: []string{labelProvider, labelStage},
	}, LatencyBuckets)

	onboardingChecks = NewCounterVec(Definition{
		Name:   Namespace + "_onboarding_checks_total",
		Help:   "Onboarding gate evaluations, by outcome. `required` means the server is still refusing traffic pending initial setup.",
		Labels: []string{labelOutcome},
	})

	securityAuditFailures = NewCounterVec(Definition{
		Name:   Namespace + "_security_audit_failures_total",
		Help:   "Authentication failures that could not be persisted to the security audit log.",
		Labels: []string{},
	})
)

// Onboarding gate outcomes.
const (
	OnboardingSatisfied = "satisfied"
	OnboardingRequired  = "required"
	OnboardingError     = "error"
)

// OAuth flow stages.
const (
	OAuthStageValidateToken = "validate_token"
	OAuthStageFetchKey      = "fetch_key"
	OAuthStageSyncUser      = "sync_user"
)

// RecordAuthentication records one authentication attempt.
func RecordAuthentication(scheme, outcome string) {
	authentications.With(scheme, outcome).Inc()
}

// RecordAuthorization records one authorization decision. permission is the
// specific right being checked, or the role name for a role check.
func RecordAuthorization(check, permission, decision string) {
	authorizations.With(check, permission, decision).Inc()
}

// RecordOAuthRequest records one call out to an OAuth provider.
func RecordOAuthRequest(provider, stage string, err error) {
	oauthRequests.With(provider, stage, resultOf(err)).Inc()
}

// RecordOnboardingCheck records one evaluation of the onboarding gate.
func RecordOnboardingCheck(outcome string) { onboardingChecks.With(outcome).Inc() }

// RecordSecurityAuditFailure records a best-effort authentication audit event
// that persistence could not durably append.
func RecordSecurityAuditFailure() { securityAuditFailures.With().Inc() }

// ObserveOAuthDuration records how long a provider call took.
func ObserveOAuthDuration(provider, stage string, seconds float64) {
	oauthDuration.Observe(seconds, provider, stage)
}
