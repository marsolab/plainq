package deletewire

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestDeleteResultWireRoundTrip(t *testing.T) {
	want := &queue.DeleteQueueResult{RemovedSubscriptions: []queue.Subscription{{
		SubscriptionID: "subscription-1",
		TopicID:        "topic-1",
		QueueID:        "queue-1",
	}}}
	encoded, err := Encode(want)
	if err != nil {
		t.Fatalf("encode delete result: %v", err)
	}
	var got queue.DeleteQueueResult
	found, err := Decode(encoded, &got)
	if err != nil {
		t.Fatalf("decode delete result: %v", err)
	}
	if !found || !reflect.DeepEqual(&got, want) {
		t.Fatalf("decoded delete result found=%t got=%#v, want %#v", found, got, want)
	}
}

func TestDeleteResultWireUsesCanonicalEnvelopeBytesAndLimit(t *testing.T) {
	result := &queue.DeleteQueueResult{RemovedSubscriptions: []queue.Subscription{{
		SubscriptionID: "subscription-1",
		TopicID:        "topic-1",
		QueueID:        "queue-1",
		QueueName:      `<legacy & "uncapped">`,
	}}}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal expected JSON payload: %v", err)
	}
	want := protowire.AppendTag(nil, resultFieldNumber, protowire.BytesType)
	want = protowire.AppendBytes(want, payload)

	canonical, err := deleteresult.Marshal(result, deleteresult.MaxEnvelopeBytes)
	if err != nil {
		t.Fatalf("marshal canonical delete result: %v", err)
	}
	if !reflect.DeepEqual(canonical, want) {
		t.Fatalf("canonical Marshal() bytes differ from JSON protobuf envelope: got %d bytes, want %d", len(canonical), len(want))
	}
	got, err := Encode(result)
	if err != nil {
		t.Fatalf("encode delete result: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Encode() bytes differ from canonical Marshal(): got %d bytes, want %d", len(got), len(want))
	}

	tooSmall := len(want) - 1
	_, err = deleteresult.Marshal(result, tooSmall)
	var capacityErr *deleteresult.CapacityError
	if !errors.Is(err, pqerr.ErrInvalidInput) || !errors.As(err, &capacityErr) {
		t.Fatalf("Marshal() error = %v, want typed invalid-input capacity error", err)
	}
	if capacityErr.EncodedBytes != len(want) || capacityErr.Limit != tooSmall {
		t.Fatalf("capacity error = %#v, want encoded=%d limit=%d", capacityErr, len(want), tooSmall)
	}
}

func TestDeleteResultWireRecognizesLegacyEmptyResponse(t *testing.T) {
	var got queue.DeleteTopicResult
	found, err := Decode(nil, &got)
	if err != nil {
		t.Fatalf("decode legacy empty response: %v", err)
	}
	if found {
		t.Fatal("legacy empty response unexpectedly contained delete effects")
	}
}

func TestDeleteResultWireRejectsInvalidEnvelopes(t *testing.T) {
	valid, err := Encode(&queue.DeleteQueueResult{})
	if err != nil {
		t.Fatalf("encode valid envelope: %v", err)
	}

	tests := map[string]struct {
		data    []byte
		wantErr string
	}{
		"malformed protobuf": {
			data:    []byte{0x80},
			wantErr: "malformed",
		},
		"envelope has wrong wire type": {
			data:    protowire.AppendVarint(protowire.AppendTag(nil, resultFieldNumber, protowire.VarintType), 1),
			wantErr: "wire type",
		},
		"duplicate envelopes": {
			data:    append(append([]byte(nil), valid...), valid...),
			wantErr: "duplicate",
		},
		"unsupported non-empty response": {
			data:    protowire.AppendBytes(protowire.AppendTag(nil, resultFieldNumber+1, protowire.BytesType), []byte(`{}`)),
			wantErr: "missing",
		},
		"oversized envelope": {
			data: protowire.AppendVarint(
				protowire.AppendTag(nil, resultFieldNumber, protowire.BytesType),
				uint64(maxEnvelopeBytes+1),
			),
			wantErr: "too large",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got queue.DeleteQueueResult
			found, err := Decode(tc.data, &got)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Decode() found=%t error=%v, want error containing %q", found, err, tc.wantErr)
			}
			if found {
				t.Fatal("invalid envelope reported a delete result")
			}
		})
	}
}
