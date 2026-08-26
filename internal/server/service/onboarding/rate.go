package onboarding

import (
	"net/http"

	"github.com/marsolab/plainq/internal/server/config"
	serversecurity "github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

const (
	defaultBootstrapRequestsPerSecond = 5
	defaultBootstrapRateBurst         = 10
	maxBootstrapRateEntries           = 4096
)

func newBootstrapRateLimiter(cfg *config.Config) *serversecurity.KeyedLimiter {
	rate, burst := float64(defaultBootstrapRequestsPerSecond), defaultBootstrapRateBurst
	if cfg != nil && cfg.AuthRateRequestsPerSecond > 0 && cfg.AuthRateBurst > 0 {
		rate, burst = cfg.AuthRateRequestsPerSecond, cfg.AuthRateBurst
	}

	limiter, err := serversecurity.NewKeyedLimiter(rate, burst, maxBootstrapRateEntries)
	if err != nil {
		return nil
	}

	return limiter
}

func (s *Service) allowBootstrapRequest(request *http.Request, account string) bool {
	return s.rateLimiter != nil && s.rateLimiter.Allow(
		serversecurity.OpaqueRateKey("bootstrap-ip", serversecurity.HTTPSourceIP(request)),
		serversecurity.OpaqueRateKey("bootstrap-account", account),
	)
}

func rejectBootstrapRate(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Retry-After", "1")
	httpkit.ErrorHTTP(w, request, errkit.ErrUnavailable, httpkit.WithStatus(http.StatusTooManyRequests))
}
