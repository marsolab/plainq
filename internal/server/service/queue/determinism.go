package queue

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
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

	// seed distinguishes this command from every other one, so identifiers
	// derived beyond the pre-assigned list are unique across the log while
	// still being identical on every replica. The consensus log index is the
	// natural value: it is assigned once, cluster-wide.
	seed uint64
}

// NewDeterminism returns the values a single replicated command supplies. ids
// are handed out in order by NextID; now answers WriteTime.
//
// seed must be unique per command — the log index of the entry carrying it.
func NewDeterminism(now time.Time, ids []string, seed uint64) *Determinism {
	return &Determinism{now: now.UTC(), ids: ids, seed: seed}
}

// Now returns the timestamp the leader stamped on the command.
func (d *Determinism) Now() time.Time {
	if d == nil {
		return time.Now().UTC()
	}

	return d.now
}

// NextID returns the next identifier for this command.
//
// Normally that is the next one the leader pre-assigned. When those run out —
// because the leader sized the command against a slightly different view of
// the state than the one it is applied to, which a fan-out publish can do —
// the identifier is *derived* rather than generated.
//
// The distinction matters more than it looks. A generated identifier is random,
// so each replica would invent a different one and the replicas would diverge
// permanently. A derived one is a pure function of the command's seed and how
// many identifiers it has already used, so every replica derives the same
// value and the state stays identical.
func (d *Determinism) NextID() (string, bool) {
	if d == nil {
		return "", false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.next < len(d.ids) {
		id := d.ids[d.next]
		d.next++

		return id, true
	}

	id := d.derive(d.next - len(d.ids))
	d.next++

	return id, true
}

// Overflowed reports whether the command needed more identifiers than the
// leader assigned. The FSM logs it: the derived identifiers keep the replicas
// consistent, but a command that needs them was sized against state that had
// already moved.
func (d *Determinism) Overflowed() int {
	if d == nil {
		return 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.next <= len(d.ids) {
		return 0
	}

	return d.next - len(d.ids)
}

// derive produces the nth identifier past the pre-assigned list.
//
// It is a ULID whose timestamp is the command's and whose entropy is a hash of
// (seed, n) rather than randomness, so it sorts like any other message id and
// is byte-identical on every replica.
func (d *Determinism) derive(n int) string {
	var input [16]byte

	binary.BigEndian.PutUint64(input[0:8], d.seed)
	binary.BigEndian.PutUint64(input[8:16], uint64(n)) //nolint:gosec // n counts identifiers within one command.

	sum := sha256.Sum256(input[:])

	var entropy [10]byte

	copy(entropy[:], sum[:])

	return ulid.MustNew(uint64(d.now.UnixMilli()), readerOf(entropy[:])).String()
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

// NextID returns the identifier a write should use: a deterministic one under
// replication, a freshly generated one otherwise.
//
// The generator is never called during a replicated apply. It cannot be: it
// returns a different value on every node, and two replicas naming the same
// message differently is a divergence that never heals.
func NextID(ctx context.Context, generate func() string) string {
	if d, ok := DeterminismFrom(ctx); ok {
		if id, taken := d.NextID(); taken {
			return id
		}
	}

	return generate()
}

// readerOf adapts a fixed byte slice to the io.Reader ULID wants for entropy.
type readerOf []byte

func (r readerOf) Read(p []byte) (int, error) { return copy(p, r), nil }

// Replicated reports whether ctx belongs to a replicated apply. Storage uses
// it where the deterministic path costs an extra statement that a single-node
// write should not pay for.
func Replicated(ctx context.Context) bool {
	_, ok := DeterminismFrom(ctx)

	return ok
}
