package queue

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
)

func TestFanOutSucceedsWithNoSubscriptions(t *testing.T) {
	response, err := FanOut(context.Background(), "topic-1", nil, []PublishMessage{{Body: []byte("message")}}, func(context.Context, *v1.SendRequest) (*v1.SendResponse, error) {
		t.Fatal("FanOut called the sender without a subscription")

		return nil, nil
	})
	if err != nil {
		t.Fatalf("FanOut() error = %v, want nil", err)
	}

	if response.TopicID != "topic-1" {
		t.Fatalf("FanOut() topic ID = %q, want topic-1", response.TopicID)
	}
	if response.DeliveredCount != 0 {
		t.Fatalf("FanOut() delivered count = %d, want 0", response.DeliveredCount)
	}
	if response.QueueIDs == nil || response.MessageIDs == nil {
		t.Fatalf("FanOut() response slices = %#v, want non-nil empty slices", response)
	}
}

func TestFanOutAttemptsEverySelectedDestination(t *testing.T) {
	var calls []string
	response, err := FanOut(
		context.Background(),
		"topic-1",
		[]Subscription{{QueueID: "queue-a"}, {QueueID: "queue-b"}, {QueueID: "queue-c"}},
		[]PublishMessage{{Body: []byte("first")}, {Body: []byte("second")}},
		func(_ context.Context, input *v1.SendRequest) (*v1.SendResponse, error) {
			calls = append(calls, input.GetQueueId())
			switch input.GetQueueId() {
			case "queue-a":
				return &v1.SendResponse{MessageIds: []string{"a-1", "a-2"}}, nil
			case "queue-b":
				return nil, errors.Join(pqerr.ErrUnavailable, errkit.ErrUnavailable)
			case "queue-c":
				return &v1.SendResponse{MessageIds: []string{"c-1", "c-2"}}, nil
			default:
				t.Fatalf("sender called for unexpected queue %q", input.GetQueueId())
				return nil, nil
			}
		},
	)

	if !reflect.DeepEqual(calls, []string{"queue-a", "queue-b", "queue-c"}) {
		t.Fatalf("FanOut() call order = %v, want [queue-a queue-b queue-c]", calls)
	}
	if response.DeliveredCount != 4 {
		t.Fatalf("FanOut() delivered count = %d, want 4", response.DeliveredCount)
	}
	if !errors.Is(err, pqerr.ErrPartialFanout) {
		t.Fatalf("FanOut() error = %v, want %v", err, pqerr.ErrPartialFanout)
	}
	if !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("FanOut() error = %v, want nested %v for diagnostics", err, pqerr.ErrUnavailable)
	}
	mapped := pqerr.AsTransport(err)
	if mapped == err {
		t.Fatal("AsTransport(FanOut error) returned the original error, want a transport-safe facade")
	}
	if !errors.Is(mapped, pqerr.ErrUnavailable) {
		t.Fatalf("AsTransport(FanOut error) = %v, want nested %v for diagnostics", mapped, pqerr.ErrUnavailable)
	}
	if errors.Is(mapped, errkit.ErrUnavailable) {
		t.Fatalf("AsTransport(FanOut error) unexpectedly matched %v", errkit.ErrUnavailable)
	}

	var partial *PartialPublishError
	if !errors.As(err, &partial) {
		t.Fatalf("FanOut() error = %v, want PartialPublishError", err)
	}
	var mappedPartial *PartialPublishError
	if !errors.As(mapped, &mappedPartial) {
		t.Fatalf("AsTransport(FanOut error) = %v, want PartialPublishError diagnostic", mapped)
	}
	if mappedPartial != partial {
		t.Fatal("AsTransport(FanOut error) returned a different PartialPublishError diagnostic")
	}
	if partial.Outcome.FailedDeliveries != 2 {
		t.Fatalf("FanOut() failed deliveries = %d, want 2", partial.Outcome.FailedDeliveries)
	}
}

func TestFanOutRetainsSuccessfulCopiesAfterFailure(t *testing.T) {
	response, err := FanOut(
		context.Background(),
		"topic-1",
		[]Subscription{{QueueID: "queue-a"}, {QueueID: "queue-b"}},
		[]PublishMessage{{Body: []byte("secret message")}},
		func(_ context.Context, input *v1.SendRequest) (*v1.SendResponse, error) {
			if input.GetQueueId() == "queue-a" {
				return &v1.SendResponse{MessageIds: []string{"a-1"}}, nil
			}

			return nil, errors.New("destination rejected publish")
		},
	)
	if err == nil {
		t.Fatal("FanOut() error = nil, want partial publish error")
	}
	if !reflect.DeepEqual(response.QueueIDs, []string{"queue-a", "queue-b"}) {
		t.Fatalf("FanOut() queue IDs = %v, want [queue-a queue-b]", response.QueueIDs)
	}
	if !reflect.DeepEqual(response.MessageIDs, []string{"a-1"}) {
		t.Fatalf("FanOut() message IDs = %v, want [a-1]", response.MessageIDs)
	}

	var partial *PartialPublishError
	if !errors.As(err, &partial) {
		t.Fatalf("FanOut() error = %v, want PartialPublishError", err)
	}
	if partial.Outcome.Response != response {
		t.Fatal("FanOut() partial outcome did not retain the response")
	}
	if !reflect.DeepEqual(partial.Outcome.DeliveryFailures, []PublishDeliveryFailure{{
		QueueID:  "queue-b",
		Messages: 1,
		Cause:    "destination rejected publish",
	}}) {
		t.Fatalf("FanOut() failures = %#v, want queue-b failure", partial.Outcome.DeliveryFailures)
	}
	if got := err.Error(); got == "" || containsMessageBody(got, "secret message") {
		t.Fatalf("FanOut() error = %q, must not include a message body", got)
	}
}

func containsMessageBody(value, body string) bool {
	return strings.Contains(value, body)
}
