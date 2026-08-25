// Package deletewire carries internal delete effects across mixed-version
// cluster peers without changing the public protobuf schema.
package deletewire

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// This high, non-reserved unknown field is the version marker for the
	// first internal delete-result envelope. Older generated protobuf codecs
	// preserve it while continuing to expose an empty public response.
	resultFieldNumber protowire.Number = 51000

	// Leave enough room for the protobuf tag and length inside the peer RPC's
	// 64 MiB response ceiling.
	maxPayloadBytes = (64 << 20) - 16
)

// Encode wraps a JSON delete result in a length-delimited protobuf unknown
// field. The public empty response types accept and preserve this field.
func Encode(result any) ([]byte, error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal delete result: %w", err)
	}
	if len(payload) > maxPayloadBytes {
		return nil, fmt.Errorf("delete result payload is too large: %d bytes", len(payload))
	}

	encoded := protowire.AppendTag(nil, resultFieldNumber, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, payload)

	return encoded, nil
}

// Decode unwraps a delete result. An empty body is the legacy response from
// an older leader and is deliberately reported as not found. Any non-empty
// body must carry exactly one supported envelope so effects cannot be lost
// silently.
func Decode(data []byte, result any) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}

	var (
		payload []byte
		seen    bool
	)
	for len(data) > 0 {
		number, wireType, tagLen := protowire.ConsumeTag(data)
		if tagLen < 0 {
			return false, fmt.Errorf("malformed delete result envelope tag: %w", protowire.ParseError(tagLen))
		}
		data = data[tagLen:]

		if number != resultFieldNumber {
			fieldLen := protowire.ConsumeFieldValue(number, wireType, data)
			if fieldLen < 0 {
				return false, fmt.Errorf("malformed delete result envelope field: %w", protowire.ParseError(fieldLen))
			}
			data = data[fieldLen:]

			continue
		}

		if wireType != protowire.BytesType {
			return false, fmt.Errorf("delete result envelope has wire type %d, want bytes", wireType)
		}
		if seen {
			return false, fmt.Errorf("duplicate delete result envelope field %d", resultFieldNumber)
		}
		seen = true

		payloadLen, lengthLen := protowire.ConsumeVarint(data)
		if lengthLen < 0 {
			return false, fmt.Errorf("malformed delete result envelope length: %w", protowire.ParseError(lengthLen))
		}
		if payloadLen > maxPayloadBytes {
			return false, fmt.Errorf("delete result payload is too large: %d bytes", payloadLen)
		}
		data = data[lengthLen:]
		if payloadLen > uint64(len(data)) {
			return false, fmt.Errorf("malformed delete result envelope payload: declared %d bytes, have %d", payloadLen, len(data))
		}

		payload = data[:int(payloadLen)]
		data = data[int(payloadLen):]
	}

	if !seen {
		return false, fmt.Errorf("delete result response is missing envelope field %d", resultFieldNumber)
	}
	if err := json.Unmarshal(payload, result); err != nil {
		return false, fmt.Errorf("unmarshal delete result: %w", err)
	}

	return true, nil
}
