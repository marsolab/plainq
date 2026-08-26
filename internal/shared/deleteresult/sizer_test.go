package deleteresult

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/service/queue"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestSizerMatchesCanonicalMarshalForZeroRows(t *testing.T) {
	canonical, err := Marshal(&queue.DeleteTopicResult{RemovedSubscriptions: []queue.Subscription{}}, MaxEnvelopeBytes)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got := NewSizer().EnvelopeBytes(); got != len(canonical) {
		t.Fatalf("zero-row Sizer bytes = %d, canonical bytes = %d", got, len(canonical))
	}
}

func TestSizerMatchesCanonicalMarshalForEscapedAndInvalidSubscriptions(t *testing.T) {
	createdAt := time.Date(2026, 8, 26, 3, 4, 5, 123456789, time.FixedZone("test", 5*60*60+30*60))
	subscriptions := []queue.Subscription{
		{
			SubscriptionID: "plain",
			TopicID:        "topic",
			QueueID:        "queue",
			CreatedAt:      createdAt,
		},
		{
			SubscriptionID: "quote\" slash\\ controls\b\f\n\r\t\x00\x1f",
			TopicID:        "html<>&-valid-\ufffd",
			QueueID:        "unicode-\u2028-\u2029-😀",
			QueueName:      "invalid-" + string([]byte{0xff, 0xc0, 0x80}) + "-utf8",
			CreatedAt:      createdAt.UTC(),
		},
	}

	canonical, err := Marshal(&queue.DeleteTopicResult{RemovedSubscriptions: subscriptions}, MaxEnvelopeBytes)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	sizer := NewSizer()
	for i, subscription := range subscriptions {
		if err := sizer.AddSubscription(
			subscription.SubscriptionID,
			subscription.TopicID,
			subscription.QueueID,
			subscription.QueueName,
			subscription.CreatedAt,
		); err != nil {
			t.Fatalf("AddSubscription() error = %v", err)
		}
		prefix, err := Marshal(&queue.DeleteTopicResult{RemovedSubscriptions: subscriptions[:i+1]}, MaxEnvelopeBytes)
		if err != nil {
			t.Fatalf("Marshal(prefix %d) error = %v", i+1, err)
		}
		if got := sizer.EnvelopeBytes(); got != len(prefix) {
			t.Fatalf("Sizer bytes after row %d = %d, canonical bytes = %d", i+1, got, len(prefix))
		}
	}
	if got := sizer.EnvelopeBytes(); got != len(canonical) {
		t.Fatalf("Sizer envelope bytes = %d, canonical Marshal bytes = %d", got, len(canonical))
	}
	if err := sizer.CheckLimit(len(canonical), true); err != nil {
		t.Fatalf("exact-boundary CheckLimit() error = %v", err)
	}
	err = sizer.CheckLimit(len(canonical)-1, true)
	var capacityErr *CapacityError
	if !errors.As(err, &capacityErr) || capacityErr.LowerBound {
		t.Fatalf("one-over CheckLimit() error = %#v, want exact CapacityError", err)
	}
}

func TestSizerReturnsCanonicalTimeMarshalError(t *testing.T) {
	invalid := time.Date(10_000, 1, 1, 0, 0, 0, 0, time.UTC)
	sizer := NewSizer()
	err := sizer.AddSubscription("subscription", "topic", "queue", "", invalid)
	if err == nil {
		t.Fatal("AddSubscription() error = nil, want invalid-year error")
	}
	_, canonicalErr := Marshal(&queue.DeleteTopicResult{RemovedSubscriptions: []queue.Subscription{{
		SubscriptionID: "subscription",
		TopicID:        "topic",
		QueueID:        "queue",
		CreatedAt:      invalid,
	}}}, MaxEnvelopeBytes)
	if canonicalErr == nil {
		t.Fatal("Marshal() error = nil, want invalid-year error")
	}
}

func TestEnvelopeSizeMatchesProtobufVarintBoundaries(t *testing.T) {
	for _, payloadBytes := range []int64{0, 1, 126, 127, 128, 16_382, 16_383, 16_384} {
		err := CheckPayloadLimit(payloadBytes, 0, true)
		var capacityErr *CapacityError
		if !errors.As(err, &capacityErr) {
			t.Fatalf("CheckPayloadLimit(%d) error = %v, want CapacityError", payloadBytes, err)
		}
		want := int64(protowire.SizeTag(FieldNumber) + protowire.SizeBytes(int(payloadBytes)))
		if capacityErr.EncodedBytes != want {
			t.Fatalf("CheckPayloadLimit(%d) encoded bytes = %d, want %d", payloadBytes, capacityErr.EncodedBytes, want)
		}
	}
}

func TestSizerArithmeticSaturatesInsteadOfWrapping(t *testing.T) {
	if got := MinimumPayloadBytes(math.MaxInt64, math.MaxInt64, math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("MinimumPayloadBytes(max) = %d, want saturated MaxInt64", got)
	}
	err := CheckPayloadLimit(math.MaxInt64, MaxEnvelopeBytes, false)
	var capacityErr *CapacityError
	if !errors.As(err, &capacityErr) || capacityErr.EncodedBytes != math.MaxInt64 || !capacityErr.LowerBound {
		t.Fatalf("CheckPayloadLimit(max) error = %#v, want saturated lower-bound CapacityError", err)
	}
}

func TestSizerMatchesCanonicalMarshalForManyLargeRows(t *testing.T) {
	const rows = 2_000
	queueName := strings.Repeat(`<large & "escaped">`, 128)
	createdAt := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	subscriptions := make([]queue.Subscription, 0, rows)
	sizer := NewSizer()
	for i := range rows {
		subscription := queue.Subscription{
			SubscriptionID: strings.Repeat("s", 26) + string(rune('a'+i%26)),
			TopicID:        strings.Repeat("t", 26),
			QueueID:        strings.Repeat("q", 26),
			QueueName:      queueName,
			CreatedAt:      createdAt.Add(time.Duration(i) * time.Microsecond),
		}
		subscriptions = append(subscriptions, subscription)
		if err := sizer.AddSubscription(
			subscription.SubscriptionID,
			subscription.TopicID,
			subscription.QueueID,
			subscription.QueueName,
			subscription.CreatedAt,
		); err != nil {
			t.Fatalf("AddSubscription(%d) error = %v", i, err)
		}
	}

	canonical, err := Marshal(&queue.DeleteQueueResult{RemovedSubscriptions: subscriptions}, MaxEnvelopeBytes)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got := sizer.EnvelopeBytes(); got != len(canonical) {
		t.Fatalf("many-row Sizer bytes = %d, canonical bytes = %d", got, len(canonical))
	}
}

func TestLowerBoundCapacityErrorDoesNotClaimExactSize(t *testing.T) {
	payloadLowerBound := MinimumPayloadBytes(50_000, 3_000_000, 50_000)
	err := CheckPayloadLimit(payloadLowerBound, 128, false)
	var capacityErr *CapacityError
	if !errors.As(err, &capacityErr) || !capacityErr.LowerBound {
		t.Fatalf("lower-bound CheckPayloadLimit() error = %#v, want lower-bound CapacityError", err)
	}
	if !strings.Contains(err.Error(), "at least") || strings.Contains(err.Error(), "encoded size ") {
		t.Fatalf("lower-bound CapacityError text = %q, must not claim an exact size", err)
	}
}
