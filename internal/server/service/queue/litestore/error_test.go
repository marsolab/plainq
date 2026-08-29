package litestore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestPubSubErrorNormalization(t *testing.T) {
	tests := map[string]struct {
		err       error
		operation pubSubErrorContext
		want      error
	}{
		"bad connection is unavailable":    {driver.ErrBadConn, pubSubPublish, pqerr.ErrUnavailable},
		"closed connection is unavailable": {sql.ErrConnDone, pubSubDeleteTopic, pqerr.ErrUnavailable},
		"deadline is unavailable":          {context.DeadlineExceeded, pubSubDeleteQueue, pqerr.ErrUnavailable},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := normalizePubSubError(tc.err, tc.operation)
			if !errors.Is(got, tc.want) {
				t.Fatalf("normalizePubSubError(%v, %q) = %v, want %v", tc.err, tc.operation, got, tc.want)
			}
		})
	}

	unknown := errors.New("opaque hrana error")
	for _, operation := range []pubSubErrorContext{
		pubSubListTopics, pubSubCreateTopic, pubSubDeleteQueue, pubSubSubscribe,
		pubSubDeleteTopic, pubSubUnsubscribe, pubSubPublish, pubSubInventory,
	} {
		if got := normalizePubSubError(driver.ErrBadConn, operation); !errors.Is(got, pqerr.ErrUnavailable) {
			t.Fatalf("connection error for %q = %v, want %v", operation, got, pqerr.ErrUnavailable)
		}
		if got := normalizePubSubError(unknown, operation); got != unknown {
			t.Fatalf("unknown error for %q = %v, want original %v", operation, got, unknown)
		}
	}
}
