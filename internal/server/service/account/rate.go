package account

import (
	"net/http"

	"github.com/marsolab/plainq/internal/server/config"
	serversecurity "github.com/marsolab/plainq/internal/server/security"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

const (
	defaultAuthRequestsPerSecond = 5
	defaultAuthRateBurst         = 10
	maxAuthRateEntries           = 4096
)

func newAuthRateLimiter(cfg *config.Config) *serversecurity.KeyedLimiter {
	rate, burst := float64(defaultAuthRequestsPerSecond), defaultAuthRateBurst
	if cfg != nil && cfg.AuthRateRequestsPerSecond > 0 && cfg.AuthRateBurst > 0 {
		rate, burst = cfg.AuthRateRequestsPerSecond, cfg.AuthRateBurst
	}

	limiter, err := serversecurity.NewKeyedLimiter(rate, burst, maxAuthRateEntries)
	if err != nil {
		// Startup validation rejects invalid production configuration. Keep the
		// service fail-closed if it is constructed directly with one.
		return nil
	}

	return limiter
}

func (s *Service) allowIPAndAccount(request *http.Request, account string) bool {
	return s.rateLimiter != nil && s.rateLimiter.Allow(
		serversecurity.OpaqueRateKey("ip", serversecurity.HTTPSourceIP(request)),
		serversecurity.OpaqueRateKey("account", account),
	)
}

func (s *Service) allowIP(request *http.Request) bool {
	return s.rateLimiter != nil && s.rateLimiter.Allow(
		serversecurity.OpaqueRateKey("ip", serversecurity.HTTPSourceIP(request)),
	)
}

func (s *Service) allowAccount(account string) bool {
	return s.rateLimiter != nil && s.rateLimiter.Allow(serversecurity.OpaqueRateKey("account", account))
}

func rejectAuthRate(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Retry-After", "1")
	httpkit.ErrorHTTP(w, request, errkit.ErrUnavailable, httpkit.WithStatus(http.StatusTooManyRequests))
}

func authRequestMaxBytes(cfg *config.Config) int64 {
	if cfg != nil && cfg.AuthRequestMaxBytes > 0 {
		return cfg.AuthRequestMaxBytes
	}

	return maxAuthRequestBytes
}
