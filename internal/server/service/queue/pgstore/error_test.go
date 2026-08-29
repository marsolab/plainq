package pgstore

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestPubSubErrorNormalization(t *testing.T) {
	tests := map[string]struct {
		err       error
		operation pubSubErrorContext
		want      error
	}{
		"legacy create unique violation is duplicate": {&pgconn.PgError{Code: "23505", ConstraintName: "topic_name_uindex"}, pubSubCreateTopic, pqerr.ErrAlreadyExists},
		"tenant create unique violation is duplicate": {&pgconn.PgError{Code: "23505", ConstraintName: "topic_tenant_name_uindex"}, pubSubCreateTopic, pqerr.ErrAlreadyExists},
		"subscribe unique violation is duplicate":     {&pgconn.PgError{Code: "23505", ConstraintName: "topic_subscriptions_topic_queue_uindex"}, pubSubSubscribe, pqerr.ErrAlreadyExists},
		"shutdown is unavailable":                     {&pgconn.PgError{Code: "57P01"}, pubSubListTopics, pqerr.ErrUnavailable},
		"serialization failure is unavailable":        {&pgconn.PgError{Code: "40001"}, pubSubDeleteQueue, pqerr.ErrUnavailable},
		"deadlock is unavailable":                     {&pgconn.PgError{Code: "40P01"}, pubSubDeleteTopic, pqerr.ErrUnavailable},
		"deadline is unavailable":                     {context.DeadlineExceeded, pubSubPublish, pqerr.ErrUnavailable},
		"closed connection is unavailable":            {pgconn.ErrConnClosed, pubSubInventory, pqerr.ErrUnavailable},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := normalizePubSubError(tc.err, tc.operation)
			if !errors.Is(got, tc.want) {
				t.Fatalf("normalizePubSubError(%v, %q) = %v, want %v", tc.err, tc.operation, got, tc.want)
			}
		})
	}
	unknown := errors.New("unknown")
	for _, operation := range []pubSubErrorContext{
		pubSubListTopics, pubSubCreateTopic, pubSubDeleteQueue, pubSubSubscribe,
		pubSubDeleteTopic, pubSubUnsubscribe, pubSubPublish, pubSubInventory,
	} {
		if got := normalizePubSubError(pgconn.ErrConnClosed, operation); !errors.Is(got, pqerr.ErrUnavailable) {
			t.Fatalf("connection error for %q = %v, want %v", operation, got, pqerr.ErrUnavailable)
		}
		if got := normalizePubSubError(unknown, operation); got != unknown {
			t.Fatalf("unknown error for %q = %v, want original %v", operation, got, unknown)
		}
	}
}

func TestPubSubErrorNormalizationPreservesOpaqueNetError(t *testing.T) {
	err := testNetError{}
	if got := normalizePubSubError(err, pubSubPublish); got != err {
		t.Fatalf("normalizePubSubError(%v) = %v, want original error", err, got)
	}
}

func TestPubSubErrorNormalizationMapsTemporaryNetErrorUnavailable(t *testing.T) {
	err := testNetError{temporary: true}
	if got := normalizePubSubError(err, pubSubPublish); !errors.Is(got, pqerr.ErrUnavailable) {
		t.Fatalf("normalizePubSubError(%v) = %v, want %v", err, got, pqerr.ErrUnavailable)
	}
}

type testNetError struct {
	temporary bool
}

func (testNetError) Error() string     { return "network failure" }
func (testNetError) Timeout() bool     { return false }
func (e testNetError) Temporary() bool { return e.temporary }
