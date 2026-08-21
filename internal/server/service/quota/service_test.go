package quota

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
)

type memoryWindowStore struct {
	reservations map[string]reservation
}

type reservation struct {
	key  string
	used uint64
}

func (s *memoryWindowStore) Reserve(
	_ context.Context,
	tenantID string,
	action authz.Action,
	limit, units uint64,
	idempotencyKey string,
	window time.Time,
) (ReservationResult, error) {
	if s.reservations == nil {
		s.reservations = make(map[string]reservation)
	}

	key := tenantID + ":" + string(action) + ":" + window.Format(time.RFC3339Nano)
	current := s.reservations[key]
	if current.key == idempotencyKey {
		return ReservationResult{AlreadyConsumed: true, Used: current.used}, nil
	}

	if current.used+units > limit {
		return ReservationResult{Used: current.used}, ErrExhausted
	}

	current.key = idempotencyKey
	current.used += units
	s.reservations[key] = current

	return ReservationResult{Used: current.used}, nil
}

func TestIdempotentRetryDoesNotConsumeQuotaTwice(t *testing.T) {
	limiter, err := NewLimiter(&memoryWindowStore{}, StaticLimits{authz.ActionAgentSend: 1})
	if err != nil {
		t.Fatalf("NewLimiter() error = %v", err)
	}

	now := time.Unix(10, 0)
	if err := limiter.Consume(context.Background(), "tenant-a", authz.ActionAgentSend, 1, "key-1", now); err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}

	if err := limiter.Consume(context.Background(), "tenant-a", authz.ActionAgentSend, 1, "key-1", now); err != nil {
		t.Fatalf("retry Consume() error = %v", err)
	}

	if err := limiter.Consume(context.Background(), "tenant-a", authz.ActionAgentSend, 1, "key-2", now); !errors.Is(err, ErrExhausted) {
		t.Fatalf("second key Consume() error = %v, want ErrExhausted", err)
	}
}

func TestExhaustionCarriesBoundedRetryDelay(t *testing.T) {
	limiter, err := NewLimiter(&memoryWindowStore{}, StaticLimits{authz.ActionAgentSend: 1})
	if err != nil {
		t.Fatalf("NewLimiter() error = %v", err)
	}

	now := time.Unix(10, int64(250*time.Millisecond))
	if err := limiter.Consume(context.Background(), "tenant-a", authz.ActionAgentSend, 1, "key-1", now); err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}

	err = limiter.Consume(context.Background(), "tenant-a", authz.ActionAgentSend, 1, "key-2", now)
	delay, ok := RetryDelay(err)
	if !ok {
		t.Fatalf("RetryDelay(%v) did not identify quota exhaustion", err)
	}
	if delay != 750*time.Millisecond {
		t.Fatalf("RetryDelay() = %s, want %s", delay, 750*time.Millisecond)
	}
}

type txStub struct {
	reserved bool
	applied  bool
	retryAt  time.Time
	err      error
}

func (s *txStub) ReserveRate(
	_ context.Context, _ string, _ authz.Action, _ uint64, _ time.Time,
) (time.Time, error) {
	s.reserved = true
	if s.err != nil {
		return s.retryAt, s.err
	}

	return time.Unix(11, 0), nil
}

func (s *txStub) ApplyActualUsage(_ context.Context, _ UsageDelta) error {
	s.applied = true

	return nil
}

func TestTransactionHelpersUseExistingUnitOfWork(t *testing.T) {
	tx := &txStub{}
	if _, err := ReserveRateTx(
		context.Background(), tx, "tenant-a", authz.ActionAgentSend, 1, time.Unix(10, 0),
	); err != nil {
		t.Fatalf("ReserveRateTx() error = %v", err)
	}

	if err := ApplyActualUsageTx(context.Background(), tx, UsageDelta{TenantID: "tenant-a", AgentCountAdded: 1}); err != nil {
		t.Fatalf("ApplyActualUsageTx() error = %v", err)
	}

	if !tx.reserved || !tx.applied {
		t.Fatalf("transaction calls = reserved %v, applied %v", tx.reserved, tx.applied)
	}
}

func TestTransactionExhaustionClampsRetryDelay(t *testing.T) {
	now := time.Unix(10, 0)
	tx := &txStub{retryAt: now.Add(5 * time.Second), err: ErrExhausted}

	_, err := ReserveRateTx(context.Background(), tx, "tenant-a", authz.ActionAgentSend, 1, now)
	delay, ok := RetryDelay(err)
	if !ok {
		t.Fatalf("RetryDelay(%v) did not identify quota exhaustion", err)
	}
	if delay != time.Second {
		t.Fatalf("RetryDelay() = %s, want bounded %s", delay, time.Second)
	}
}
