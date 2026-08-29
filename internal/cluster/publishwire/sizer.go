// Package publishwire defines the bounded internal publish-result envelope.
package publishwire

import (
	"math"

	"github.com/marsolab/plainq/internal/cluster/command"
)

const (
	// FramingBytes covers the compact outcome field names, topic identifier,
	// booleans, maximum-width counters, brackets, and future compatible
	// framing. Identifier arrays are accounted for separately below.
	FramingBytes   = 4 << 10
	fixedJSONBytes = FramingBytes

	// QueueIDLength and MessageIDLength are the encoded lengths of the XIDs and
	// ULIDs PlainQ writes to a successful publish response.
	QueueIDLength   = 20
	MessageIDLength = 26

	// Each JSON array element needs two quotes and, conservatively, one comma.
	jsonArrayElementOverhead = 3
	queueIDJSONBytes         = QueueIDLength + jsonArrayElementOverhead
	messageIDJSONBytes       = MessageIDLength + jsonArrayElementOverhead

	// MaxResponseBytes is the finite v2 peer response envelope. Leader-local
	// proposal admission proves a valid compact publish outcome fits this same
	// ceiling before consensus Apply; peer transport still enforces it
	// defensively.
	MaxResponseBytes = 2*command.MaxEncodedBytes + FramingBytes
)

// FitsCompactOutcome reports a conservative compact v2 publish-outcome size
// and whether it fits limit. A successful destination contributes at most one
// fixed-width queue XID and one fixed-width message ULID for each message in a
// non-empty publish request. Arithmetic overflow is a terminal non-fit,
// represented by a saturated bound.
func FitsCompactOutcome(subscriptions, messages, limit uint64) (uint64, bool) {
	deliveries, ok := checkedMul(subscriptions, messages)
	if !ok {
		return math.MaxUint64, false
	}

	queueBytes, ok := checkedMul(subscriptions, queueIDJSONBytes)
	if !ok {
		return math.MaxUint64, false
	}

	messageBytes, ok := checkedMul(deliveries, messageIDJSONBytes)
	if !ok {
		return math.MaxUint64, false
	}

	bound, ok := checkedAdd(fixedJSONBytes, queueBytes)
	if !ok {
		return math.MaxUint64, false
	}

	bound, ok = checkedAdd(bound, messageBytes)
	if !ok {
		return math.MaxUint64, false
	}

	return bound, bound <= limit
}

func checkedMul(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}

	return left * right, true
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}

	return left + right, true
}
