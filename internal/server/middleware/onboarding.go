package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/marsolab/servekit/httpkit"
)

// OnboardingChecker interface for checking if onboarding is needed.
type OnboardingChecker interface {
	NeedsOnboarding(ctx context.Context) (bool, error)
}

// RequireOnboarding middleware ensures the system has been onboarded (admin users exist)
// If onboarding is needed, it returns an error indicating onboarding is required.
func RequireOnboarding(checker OnboardingChecker) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip onboarding check for onboarding endpoints themselves.
			if isOnboardingEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)

				return
			}

			// Skip onboarding check for health endpoints.
			if isHealthEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)

				return
			}

			needsOnboarding, err := checker.NeedsOnboarding(r.Context())
			if err != nil {
				httpkit.ErrorHTTP(w, r, err)

				return
			}

			if needsOnboarding {
				// Return a specific error indicating onboarding is needed.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionRequired) // 428 status code.

				response := map[string]any{
					"error":            "System requires onboarding",
					"needs_onboarding": true,
					"onboarding_url":   "/onboarding",
					"message":          "No admin users found. Please complete the initial setup.",
				}
				httpkit.JSON(w, r, response)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isOnboardingEndpoint checks if the request is for onboarding endpoints.
func isOnboardingEndpoint(path string) bool {
	onboardingPaths := []string{
		"/onboarding",
		"/onboarding/",
		"/onboarding/status",
		"/onboarding/complete",
	}

	for _, onboardingPath := range onboardingPaths {
		if strings.HasPrefix(path, onboardingPath) {
			return true
		}
	}

	return false
}

// isHealthEndpoint checks if the request is for health check endpoints.
func isHealthEndpoint(path string) bool {
	healthPaths := []string{
		"/health",
		"/healthz",
		"/ping",
		"/status",
	}

	for _, healthPath := range healthPaths {
		if strings.HasPrefix(path, healthPath) {
			return true
		}
	}

	return false
}

// OnboardingStatus represents the onboarding status response.
type OnboardingStatus struct {
	NeedsOnboarding bool   `json:"needs_onboarding"`
	HasAdminUsers   bool   `json:"has_admin_users"`
	OnboardingURL   string `json:"onboarding_url,omitempty"`
	Message         string `json:"message,omitempty"`
}
