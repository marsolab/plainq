package deleteresult

import (
	"encoding/json"
	"math"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

var invalidUTF8JSONBytes = func() int64 {
	encoded, err := json.Marshal(string([]byte{0xff}))
	if err != nil {
		panic("marshal invalid UTF-8 probe: " + err.Error())
	}

	return int64(len(encoded) - 2) // exclude the surrounding quotes
}()

const (
	deleteResultWrapperBytes      int64 = 27
	subscriptionFixedBytes        int64 = 54
	subscriptionMinimumBytes      int64 = 82
	queueNameFixedBytes           int64 = 13
	queueNameMinimumOverheadBytes int64 = 15
)

// Sizer incrementally computes the canonical delete-result envelope size
// without materializing a subscription slice, JSON payload, or protobuf
// envelope.
type Sizer struct {
	payloadBytes int64
	rows         int64
}

// NewSizer starts an exact sizer for an empty, non-nil subscriptions array.
func NewSizer() *Sizer {
	return &Sizer{payloadBytes: deleteResultWrapperBytes}
}

// AddSubscription adds one subscription using encoding/json's default field
// order, omitempty behavior, HTML escaping, and invalid-UTF-8 replacement.
func (s *Sizer) AddSubscription(
	subscriptionID string,
	topicID string,
	queueID string,
	queueName string,
	createdAt time.Time,
) error {
	createdAtJSON, err := createdAt.MarshalJSON()
	if err != nil {
		return err
	}

	if s.rows > 0 {
		s.payloadBytes = saturatingAdd(s.payloadBytes, 1)
	}
	s.payloadBytes = saturatingAdd(s.payloadBytes, subscriptionFixedBytes)
	s.payloadBytes = saturatingAdd(s.payloadBytes, jsonStringBytes(subscriptionID))
	s.payloadBytes = saturatingAdd(s.payloadBytes, jsonStringBytes(topicID))
	s.payloadBytes = saturatingAdd(s.payloadBytes, jsonStringBytes(queueID))
	s.payloadBytes = saturatingAdd(s.payloadBytes, int64(len(createdAtJSON)))
	if queueName != "" {
		s.payloadBytes = saturatingAdd(s.payloadBytes, queueNameFixedBytes)
		s.payloadBytes = saturatingAdd(s.payloadBytes, jsonStringBytes(queueName))
	}
	s.rows = saturatingAdd(s.rows, 1)

	return nil
}

// EnvelopeBytes returns the exact protobuf-envelope byte count for all rows
// added so far.
func (s *Sizer) EnvelopeBytes() int {
	encodedBytes := envelopeBytes(s.payloadBytes)
	maxInt := int64(^uint(0) >> 1)
	if encodedBytes > maxInt {
		return int(maxInt)
	}

	return int(encodedBytes)
}

// CheckLimit compares the current envelope with limit. exact must be false
// when more rows may remain, so the diagnostic does not claim a partial size
// is the final encoded size.
func (s *Sizer) CheckLimit(limit int, exact bool) error {
	return checkEnvelopeLimit(envelopeBytes(s.payloadBytes), limit, exact)
}

// MinimumPayloadBytes returns a safe raw-byte lower bound for the canonical
// JSON payload. rawStringBytes is the sum of the four string columns and
// nonEmptyQueueNames is the number of rows where queueName is emitted.
func MinimumPayloadBytes(subscriptionCount, rawStringBytes, nonEmptyQueueNames int64) int64 {
	bytes := saturatingAdd(deleteResultWrapperBytes, rawStringBytes)
	if subscriptionCount <= 0 {
		return bytes
	}

	bytes = saturatingAdd(bytes, saturatingMul(subscriptionMinimumBytes, subscriptionCount))
	bytes = saturatingAdd(bytes, subscriptionCount-1)
	bytes = saturatingAdd(bytes, saturatingMul(queueNameMinimumOverheadBytes, nonEmptyQueueNames))

	return bytes
}

// CheckPayloadLimit compares a known JSON payload byte count or lower bound
// with the protobuf envelope limit.
func CheckPayloadLimit(payloadBytes int64, limit int, exact bool) error {
	return checkEnvelopeLimit(envelopeBytes(payloadBytes), limit, exact)
}

func checkEnvelopeLimit(encodedBytes int64, limit int, exact bool) error {
	if encodedBytes <= int64(limit) {
		return nil
	}

	return &CapacityError{
		EncodedBytes: encodedBytes,
		Limit:        int64(limit),
		LowerBound:   !exact,
	}
}

func envelopeBytes(payloadBytes int64) int64 {
	if payloadBytes < 0 {
		return math.MaxInt64
	}

	bytes := saturatingAdd(int64(protowire.SizeTag(FieldNumber)), int64(protowire.SizeVarint(uint64(payloadBytes))))
	return saturatingAdd(bytes, payloadBytes)
}

func saturatingAdd(left, right int64) int64 {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return math.MaxInt64
	}

	return left + right
}

func saturatingMul(left, right int64) int64 {
	if left < 0 || right < 0 || (left != 0 && right > math.MaxInt64/left) {
		return math.MaxInt64
	}

	return left * right
}

// jsonStringBytes is the allocation-free size counterpart of encoding/json's
// default appendString(..., escapeHTML=true).
func jsonStringBytes(value string) int64 {
	bytes := int64(2) // surrounding quotes
	for i := 0; i < len(value); {
		c := value[i]
		if c < utf8.RuneSelf {
			switch c {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				bytes += 2
			case '<', '>', '&':
				bytes += 6
			default:
				if c < 0x20 {
					bytes += 6
				} else {
					bytes++
				}
			}
			i++

			continue
		}

		r, size := utf8.DecodeRuneInString(value[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Match the encoding/json implementation selected for this binary.
			bytes += invalidUTF8JSONBytes
		case r == '\u2028' || r == '\u2029':
			bytes += 6
		default:
			bytes += int64(size)
		}
		i += size
	}

	return bytes
}
