package raft

import (
	"context"
	"errors"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"
	"github.com/marsolab/plainq/internal/cluster/consensus"
)

type fixedFuture struct {
	err error
}

func (f fixedFuture) Error() error { return f.err }

func TestApplyLeadershipLossIsCommitUnknown(t *testing.T) {
	err := waitApplyFuture(context.Background(), fixedFuture{err: hraft.ErrLeadershipLost})
	if !errors.Is(err, consensus.ErrCommitUnknown) {
		t.Fatalf("Apply leadership-loss error = %v, want %v", err, consensus.ErrCommitUnknown)
	}
	if errors.Is(err, consensus.ErrNotLeader) {
		t.Fatalf("Apply leadership-loss error = %v, must not be retryable as %v", err, consensus.ErrNotLeader)
	}
}

func TestBarrierLeadershipLossRemainsSafeToRetry(t *testing.T) {
	err := waitFuture(context.Background(), fixedFuture{err: hraft.ErrLeadershipLost})
	if !errors.Is(err, consensus.ErrNotLeader) {
		t.Fatalf("Barrier leadership-loss error = %v, want %v", err, consensus.ErrNotLeader)
	}
	if errors.Is(err, consensus.ErrCommitUnknown) {
		t.Fatalf("Barrier leadership-loss error = %v, must not be commit-unknown", err)
	}
}

func TestApplyWithExpiredContextNeverTouchesRaft(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A nil raft handle makes any access observable as a panic. An already
	// canceled request must return before the adapter checks state or proposes.
	engine := new(Engine)
	result, err := engine.Apply(ctx, []byte("command"))
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply(expired context) = %#v, %v; want nil %v", result, err, context.Canceled)
	}
}

func TestApplyWithPastDeadlineNeverTouchesRaft(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	engine := new(Engine)
	result, err := engine.Apply(ctx, []byte("command"))
	if result != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Apply(past deadline) = %#v, %v; want nil %v", result, err, context.DeadlineExceeded)
	}
}

func TestBarrierWithExpiredContextNeverTouchesRaft(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	engine := new(Engine)
	if err := engine.Barrier(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Barrier(expired context) = %v, want %v", err, context.Canceled)
	}
}

func TestBarrierWithPastDeadlineNeverTouchesRaft(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	engine := new(Engine)
	if err := engine.Barrier(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Barrier(past deadline) = %v, want %v", err, context.DeadlineExceeded)
	}
}
