// Package deletewire carries internal delete effects across mixed-version
// cluster peers without changing the public protobuf schema.
package deletewire

import (
	"encoding/json"
	"fmt"

	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// This high, non-reserved unknown field is the version marker for the
	// first internal delete-result envelope. Older generated protobuf codecs
	// preserve it while continuing to expose an empty public response.
	resultFieldNumber = deleteresult.FieldNumber

	maxEnvelopeBytes = deleteresult.MaxEnvelopeBytes
)

// Encode wraps a JSON delete result in a length-delimited protobuf unknown
// field. The public empty response types accept and preserve this field.
func Encode(result any) ([]byte, error) {
	encoded, err := deleteresult.Marshal(result, maxEnvelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("encode delete result envelope: %w", err)
	}

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

	if len(data) > maxEnvelopeBytes {
		return false, fmt.Errorf("delete result envelope is too large: %d bytes", len(data))
	}

	payload, err := decodeEnvelopeFields(data)
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(payload, result); err != nil {
		return false, fmt.Errorf("unmarshal delete result: %w", err)
	}

	return true, nil
}

func decodeEnvelopeFields(data []byte) ([]byte, error) {
	var payload []byte

	seen := false

	for len(data) > 0 {
		number, wireType, tagLen := protowire.ConsumeTag(data)
		if tagLen < 0 {
			return nil, fmt.Errorf("malformed delete result envelope tag: %w", protowire.ParseError(tagLen))
		}

		data = data[tagLen:]
		if number != resultFieldNumber {
			remaining, err := skipEnvelopeField(number, wireType, data)
			if err != nil {
				return nil, err
			}

			data = remaining

			continue
		}

		decoded, err := decodeResultField(wireType, data, seen)
		if err != nil {
			return nil, err
		}

		data = decoded.remaining
		payload = decoded.payload
		seen = true
	}

	if !seen {
		return nil, fmt.Errorf("delete result response is missing envelope field %d", resultFieldNumber)
	}

	return payload, nil
}

func skipEnvelopeField(number protowire.Number, wireType protowire.Type, data []byte) ([]byte, error) {
	fieldLen := protowire.ConsumeFieldValue(number, wireType, data)
	if fieldLen < 0 {
		return nil, fmt.Errorf("malformed delete result envelope field: %w", protowire.ParseError(fieldLen))
	}

	return data[fieldLen:], nil
}

type decodedResultField struct {
	remaining []byte
	payload   []byte
}

func decodeResultField(wireType protowire.Type, data []byte, seen bool) (decodedResultField, error) {
	if wireType != protowire.BytesType {
		return decodedResultField{}, fmt.Errorf("delete result envelope has wire type %d, want bytes", wireType)
	}

	if seen {
		return decodedResultField{}, fmt.Errorf("duplicate delete result envelope field %d", resultFieldNumber)
	}

	payloadLen, lengthLen := protowire.ConsumeVarint(data)
	if lengthLen < 0 {
		return decodedResultField{}, fmt.Errorf(
			"malformed delete result envelope length: %w",
			protowire.ParseError(lengthLen),
		)
	}

	if payloadLen > maxEnvelopeBytes {
		return decodedResultField{}, fmt.Errorf("delete result payload is too large: %d bytes", payloadLen)
	}

	data = data[lengthLen:]
	if payloadLen > uint64(len(data)) {
		return decodedResultField{}, fmt.Errorf(
			"malformed delete result envelope payload: declared %d bytes, have %d",
			payloadLen,
			len(data),
		)
	}

	return decodedResultField{
		remaining: data[int(payloadLen):],
		payload:   data[:int(payloadLen)],
	}, nil
}
