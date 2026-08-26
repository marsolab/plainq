package queue

import (
	"context"
	"sync/atomic"
)

type policyReplayContextKey struct{}

type policyReplayTracker struct {
	replayed atomic.Bool
}

func trackPolicyReplay(ctx context.Context) (context.Context, *policyReplayTracker) {
	if tracker, ok := ctx.Value(policyReplayContextKey{}).(*policyReplayTracker); ok && tracker != nil {
		return ctx, tracker
	}

	tracker := &policyReplayTracker{}

	return context.WithValue(ctx, policyReplayContextKey{}, tracker), tracker
}

// MarkPolicyReplay tells the application boundary that storage returned a
// previously committed idempotency result. Backends call it only after the
// stored request hash and response have both been validated.
func MarkPolicyReplay(ctx context.Context) {
	tracker, ok := ctx.Value(policyReplayContextKey{}).(*policyReplayTracker)
	if ok && tracker != nil {
		tracker.replayed.Store(true)
	}
}

func (t *policyReplayTracker) isReplay() bool {
	return t != nil && t.replayed.Load()
}
