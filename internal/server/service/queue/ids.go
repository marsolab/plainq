package queue

import (
	crand "crypto/rand"
	"sync"
	"time"

	"github.com/marsolab/servekit/idkit"
	"github.com/oklog/ulid/v2"
)

// NewBatchIDs returns a generator that mints message identifiers which sort in
// the order they were produced.
//
// A queue is expected to be first-in-first-out, and messages are claimed in
// `(created_at, msg_id)` order. Every message in one Send shares a created_at,
// so the identifier is what decides their order — and a plain ULID's entropy is
// random, which would shuffle a batch on its way out. A monotonic entropy
// source keeps identifiers minted in the same millisecond increasing, so the
// order a client sent a batch in is the order a consumer receives it.
//
// The returned function is safe for concurrent use, though a single Send calls
// it from one goroutine.
func NewBatchIDs(now time.Time) func() string {
	var (
		mu        sync.Mutex
		timestamp = ulid.Timestamp(now.UTC())
		entropy   = ulid.Monotonic(crand.Reader, 0)
	)

	return func() string {
		mu.Lock()
		defer mu.Unlock()

		id, err := ulid.New(timestamp, entropy)
		if err != nil {
			// The monotonic source refuses only when its increment would
			// overflow, which needs more identifiers in one millisecond than a
			// process can produce. Falling back keeps the write going; it costs
			// the ordering guarantee for that one identifier, which is a better
			// outcome than failing the Send.
			return idkit.ULID()
		}

		return id.String()
	}
}
