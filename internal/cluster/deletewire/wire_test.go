package deletewire

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/server/service/queue"
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
				uint64(maxPayloadBytes+1),
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
