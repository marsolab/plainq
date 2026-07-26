package queue

import (
	"context"
	"sync"
	"time"
)

// Determinism carries the values a replicated write must not invent for
// itself.
//
// A queue write is full of small decisions that look local — what time is it,
// what id does this message get — and each one is a place where two replicas
// applying the same command would reach different states. In a cluster the
// leader makes those decisions once, writes them into the consensus log, and
// every replica reads them back from here. Outside a cluster nothing carries a
// Determinism and storage uses the wall clock and a fresh id, exactly as it
// always has.
type Determinism struct {
	mu   sync.Mutex
	now  time.Time
	ids  []string
	next int
}

// NewDeterminism returns the values a single replicated command supplies. ids
// are handed out in order by NextID; now answers WriteTime.
func NewDeterminism(now time.Time, ids []string) *Determinism {
	return &Determinism{now: now.UTC(), ids: ids}
}

// Now returns the timestamp the leader stamped on the command.
func (d *Determinism) Now() time.Time {
	if d == nil {
		return time.Now().UTC()
	}

	return d.now
}

// NextID returns the next pre-assigned identifier. The second result is false
// once they are exhausted, which means the leader and this replica disagree
// about how many ids the command needs — a bug, and one the caller should
// surface rather than paper over with a locally generated id.
func (d *Determinism) NextID() (string, bool) {
	if d == nil {
		return "", false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.next >= len(d.ids) {
		return "", false
	}

	id := d.ids[d.next]
	d.next++

	return id, true
}

// Remaining reports how many pre-assigned ids are left. The FSM checks it
// after applying a command: leftovers mean the leader assigned ids for work
// the replica did not do.
func (d *Determinism) Remaining() int {
	if d == nil {
		return 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.ids) - d.next
}

// determinismKey is the context key under which a Determinism travels.
type determinismKey struct{}

// WithDeterminism returns a context that carries d. It is set by the cluster
// FSM around each Apply and read by the storage backend.
func WithDeterminism(ctx context.Context, d *Determinism) context.Context {
	return context.WithValue(ctx, determinismKey{}, d)
}

// DeterminismFrom returns the Determinism carried by ctx, if any.
func DeterminismFrom(ctx context.Context) (*Determinism, bool) {
	d, ok := ctx.Value(determinismKey{}).(*Determinism)

	return d, ok && d != nil
}

// WriteTime returns the timestamp a write should record: the leader's stamp
// under replication, the local clock otherwise.
func WriteTime(ctx context.Context) time.Time {
	if d, ok := DeterminismFrom(ctx); ok {
		return d.Now()
	}

	return time.Now().UTC()
}

// NextID returns the identifier a write should use: the one the leader
// assigned under replication, or a freshly generated one otherwise.
//
// Running out of pre-assigned ids falls back to generating one. That keeps a
// mismatch from stalling the FSM mid-command; the FSM reports the mismatch
// through Remaining, which is where it can be acted on.
func NextID(ctx context.Context, generate func() string) string {
	if d, ok := DeterminismFrom(ctx); ok {
		if id, taken := d.NextID(); taken {
			return id
		}
	}

	return generate()
}

// Replicated reports whether ctx belongs to a replicated apply. Storage uses
// it where the deterministic path costs an extra statement that a single-node
// write should not pay for.
func Replicated(ctx context.Context) bool {
	_, ok := DeterminismFrom(ctx)

	return ok
}
