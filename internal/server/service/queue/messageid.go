package queue

import (
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Message identifiers are ULIDs: lexicographically sortable, and carrying the
// creation timestamp the queue reports as time-in-queue when a message is
// deleted.
//
// Minting and reading live together here on purpose. They used to sit in the
// storage backends, one calling idkit.ULID() and the other idkit.ParseXID(),
// and nothing tied the two formats together — every delete panicked on an id
// the same package had just created.

// NewMessageID returns an identifier for a newly sent message.
func NewMessageID() string { return ulid.Make().String() }

// MessageCreatedAt returns the creation time carried by a message identifier.
func MessageCreatedAt(id string) (time.Time, error) {
	parsed, err := ulid.Parse(id)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse message id %q: %w", id, err)
	}

	return ulid.Time(parsed.Time()).UTC(), nil
}
