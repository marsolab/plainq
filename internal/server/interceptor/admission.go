package interceptor

import (
	"container/list"
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultPrincipalAdmissionEntries = 4096

// PrincipalAdmissionConfig configures a bounded, node-local token bucket for
// authenticated gRPC principals.
type PrincipalAdmissionConfig struct {
	RequestsPerSecond float64
	Burst             int
	MaxEntries        int
	Clock             func() time.Time
}

// PrincipalAdmissionLimiter owns one LRU-bounded token bucket per
// tenant/principal pair.
type PrincipalAdmissionLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxEntries int
	clock      func() time.Time
	entries    map[string]*principalAdmissionEntry
	lru        *list.List
}

type principalAdmissionEntry struct {
	key     string
	tokens  float64
	last    time.Time
	element *list.Element
}

// NewPrincipalAdmissionLimiter constructs the production admission limiter.
func NewPrincipalAdmissionLimiter(requestsPerSecond float64, burst int) (*PrincipalAdmissionLimiter, error) {
	return newPrincipalAdmissionLimiter(PrincipalAdmissionConfig{
		RequestsPerSecond: requestsPerSecond,
		Burst:             burst,
		MaxEntries:        defaultPrincipalAdmissionEntries,
		Clock:             time.Now,
	})
}

func newPrincipalAdmissionLimiter(config PrincipalAdmissionConfig) (*PrincipalAdmissionLimiter, error) {
	if config.RequestsPerSecond <= 0 || math.IsNaN(config.RequestsPerSecond) ||
		math.IsInf(config.RequestsPerSecond, 0) || config.Burst < 1 || config.MaxEntries < 2 {
		return nil, errors.New("principal admission requires a finite positive rate, burst, and at least two entries")
	}

	if config.Clock == nil {
		config.Clock = time.Now
	}

	return &PrincipalAdmissionLimiter{
		rate: config.RequestsPerSecond, burst: float64(config.Burst), maxEntries: config.MaxEntries,
		clock: config.Clock, entries: make(map[string]*principalAdmissionEntry, config.MaxEntries), lru: list.New(),
	}, nil
}

// UnaryAdmission consumes one token before an authenticated unary call.
func UnaryAdmission(limiter *PrincipalAdmissionLimiter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if methodAllowsAnonymous(info.FullMethod, PublicMethods()) {
			return handler(ctx, req)
		}

		p, ok := principal.From(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authenticated principal is required")
		}

		if limiter == nil || !limiter.allow(p) {
			return nil, status.Error(codes.ResourceExhausted, "principal request rate exceeded")
		}

		return handler(ctx, req)
	}
}

// StreamAdmission consumes one token when an authenticated stream is opened.
func StreamAdmission(limiter *PrincipalAdmissionLimiter) grpc.StreamServerInterceptor {
	return func(
		srv any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if methodAllowsAnonymous(info.FullMethod, PublicMethods()) {
			return handler(srv, stream)
		}

		p, ok := principal.From(stream.Context())
		if !ok {
			return status.Error(codes.Unauthenticated, "authenticated principal is required")
		}

		if limiter == nil || !limiter.allow(p) {
			return status.Error(codes.ResourceExhausted, "principal request rate exceeded")
		}

		return handler(srv, stream)
	}
}

func (l *PrincipalAdmissionLimiter) allow(p principal.Principal) bool {
	if p.Kind == "" || p.TenantID == "" || p.ID == "" {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock().UTC()
	key := string(p.Kind) + "\x00" + p.TenantID + "\x00" + p.ID

	entry, exists := l.entries[key]
	if !exists {
		if len(l.entries) >= l.maxEntries {
			l.evictOldest()
		}

		entry = &principalAdmissionEntry{key: key, tokens: l.burst, last: now}
		entry.element = l.lru.PushFront(entry)
		l.entries[key] = entry
	} else {
		elapsed := now.Sub(entry.last).Seconds()
		if elapsed > 0 {
			entry.tokens = min(l.burst, entry.tokens+elapsed*l.rate)
			entry.last = now
		}

		l.lru.MoveToFront(entry.element)
	}

	if entry.tokens < 1 {
		return false
	}

	entry.tokens--

	return true
}

func (l *PrincipalAdmissionLimiter) evictOldest() {
	oldest := l.lru.Back()
	if oldest == nil {
		return
	}

	entry, ok := oldest.Value.(*principalAdmissionEntry)
	if ok {
		delete(l.entries, entry.key)
	}

	l.lru.Remove(oldest)
}
