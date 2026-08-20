package interceptor

import (
	"context"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPrincipalAdmissionLimitsEachPrincipalIndependently(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	limiter, err := newPrincipalAdmissionLimiter(PrincipalAdmissionConfig{
		RequestsPerSecond: 1,
		Burst:             1,
		MaxEntries:        4,
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}

	interceptor := UnaryAdmission(limiter)
	info := &grpc.UnaryServerInfo{FullMethod: agentv1.AgentService_ReceiveInbox_FullMethodName}
	handler := func(context.Context, any) (any, error) { return "ok", nil }

	principalA := principal.Principal{
		Kind: principal.KindAgent, ID: "agent-a", TenantID: "tenant-a", Roles: []string{"agent"},
	}
	principalB := principal.Principal{
		Kind: principal.KindAgent, ID: "agent-b", TenantID: "tenant-a", Roles: []string{"agent"},
	}

	if _, err := interceptor(principal.With(context.Background(), principalA), nil, info, handler); err != nil {
		t.Fatalf("first call: %v", err)
	}

	if _, err := interceptor(principal.With(context.Background(), principalA), nil, info, handler); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second call code = %v, want %v", status.Code(err), codes.ResourceExhausted)
	}

	if _, err := interceptor(principal.With(context.Background(), principalB), nil, info, handler); err != nil {
		t.Fatalf("different principal call: %v", err)
	}

	now = now.Add(time.Second)
	if _, err := interceptor(principal.With(context.Background(), principalA), nil, info, handler); err != nil {
		t.Fatalf("refilled call: %v", err)
	}
}

func TestPrincipalAdmissionBoundsEntries(t *testing.T) {
	t.Parallel()

	limiter, err := newPrincipalAdmissionLimiter(PrincipalAdmissionConfig{
		RequestsPerSecond: 1,
		Burst:             1,
		MaxEntries:        2,
		Clock:             time.Now,
	})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}

	for _, id := range []string{"agent-a", "agent-b", "agent-c"} {
		if !limiter.allow(principal.Principal{Kind: principal.KindAgent, TenantID: "tenant-a", ID: id}) {
			t.Fatalf("first call for %q was rejected", id)
		}
	}

	limiter.mu.Lock()
	got := len(limiter.entries)
	limiter.mu.Unlock()
	if got != 2 {
		t.Fatalf("entry count = %d, want 2", got)
	}
}

func TestPrincipalAdmissionConfiguration(t *testing.T) {
	t.Parallel()

	for name, config := range map[string]PrincipalAdmissionConfig{
		"zero rate":     {RequestsPerSecond: 0, Burst: 1, MaxEntries: 2},
		"negative rate": {RequestsPerSecond: -1, Burst: 1, MaxEntries: 2},
		"zero burst":    {RequestsPerSecond: 1, Burst: 0, MaxEntries: 2},
		"small bound":   {RequestsPerSecond: 1, Burst: 1, MaxEntries: 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := newPrincipalAdmissionLimiter(config); err == nil {
				t.Fatal("new limiter unexpectedly succeeded")
			}
		})
	}
}
