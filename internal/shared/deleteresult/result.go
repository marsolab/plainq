// Package deleteresult defines the canonical internal delete-result envelope.
package deleteresult

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// FieldNumber is the version marker carried as an unknown field by the
	// unchanged public empty delete-response protobufs.
	FieldNumber protowire.Number = 51000

	// MaxEnvelopeBytes matches the peer RPC response ceiling.
	MaxEnvelopeBytes = 64 << 20
)

// CapacityError reports an internal delete result that cannot fit on the peer
// transport. It contains sizes only and never includes the serialized data.
// It intentionally has no domain-error classification: this is a server-side
// representation limit, not invalid client input and not a retryable failure.
type CapacityError struct {
	EncodedBytes int
	Limit        int
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf(
		"delete result exceeds transport capacity: encoded size %d bytes exceeds %d-byte limit",
		e.EncodedBytes,
		e.Limit,
	)
}

// Marshal returns the canonical protobuf envelope, including JSON escaping,
// after enforcing the exact encoded-byte limit.
func Marshal(result any, limit int) ([]byte, error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal delete result: %w", err)
	}

	encoded := protowire.AppendTag(nil, FieldNumber, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, payload)
	if len(encoded) > limit {
		return nil, &CapacityError{EncodedBytes: len(encoded), Limit: limit}
	}

	return encoded, nil
}
