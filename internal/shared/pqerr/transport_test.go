package pqerr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/grpckit"
	"github.com/marsolab/servekit/httpkit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAsTransportMapsStorageErrorsOntoTransportSentinels(t *testing.T) {
	tests := map[string]struct {
		err  error
		want error
	}{
		"not found":       {err: ErrNotFound, want: errkit.ErrNotFound},
		"already exists":  {err: ErrAlreadyExists, want: errkit.ErrAlreadyExists},
		"invalid input":   {err: ErrInvalidInput, want: errkit.ErrInvalidArgument},
		"invalid id":      {err: ErrInvalidID, want: errkit.ErrInvalidArgument},
		"unauthenticated": {err: ErrUnauthenticated, want: errkit.ErrUnauthenticated},
		"unauthorized":    {err: ErrUnauthorized, want: errkit.ErrUnauthorized},
		"unavailable":     {err: ErrUnavailable, want: errkit.ErrUnavailable},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Wrapped the way storage actually returns them, so the mapping is
			// exercised through errors.Is rather than through equality.
			wrapped := fmt.Errorf("get role: %w", tc.err)

			got := AsTransport(wrapped)

			if !errors.Is(got, tc.want) {
				t.Fatalf("AsTransport(%v) does not match %v", wrapped, tc.want)
			}

			// The original error has to survive: it is what the access log
			// records, and losing it would leave only a status code.
			if !errors.Is(got, tc.err) {
				t.Fatalf("AsTransport(%v) dropped the storage error", wrapped)
			}
		})
	}
}

func TestAsTransportLeavesUnrecognisedErrorsAlone(t *testing.T) {
	original := errors.New("database unavailable")

	got := AsTransport(original)

	// An unrecognised failure really is a 500; inventing a sentinel for it
	// would turn a server fault into a client error.
	if !errors.Is(got, original) {
		t.Fatalf("AsTransport(%v) = %v, want the original error", original, got)
	}

	for _, sentinel := range []error{
		errkit.ErrNotFound,
		errkit.ErrInvalidArgument,
		errkit.ErrUnauthorized,
	} {
		if errors.Is(got, sentinel) {
			t.Fatalf("AsTransport(%v) unexpectedly matched %v", original, sentinel)
		}
	}
}

func TestAsTransportPassesNilThrough(t *testing.T) {
	if got := AsTransport(nil); got != nil {
		t.Fatalf("AsTransport(nil) = %v, want nil", got)
	}
}

func TestCapacityIsNotMisclassifiedAsInvalidArgumentOrRetryable(t *testing.T) {
	original := fmt.Errorf("encoded command: %w", ErrCapacityExceeded)
	got := AsTransport(original)
	if !errors.Is(got, ErrCapacityExceeded) {
		t.Fatalf("AsTransport(capacity) = %v, want capacity sentinel", got)
	}
	if errors.Is(got, errkit.ErrInvalidArgument) || errors.Is(got, errkit.ErrUnavailable) {
		t.Fatalf("AsTransport(capacity) = %v, must remain its own non-retryable class", got)
	}
}

func TestPartialFanoutAlwaysMapsToInternal(t *testing.T) {
	unknownCause := errors.New("queue connection reset")
	partial := &partialFanoutError{causes: []error{
		ErrPartialFanout,
		ErrUnavailable,
		errkit.ErrUnavailable,
		unknownCause,
	}}

	got := AsTransport(partial)
	if got == partial {
		t.Fatalf("AsTransport(%v) returned the original error, want a transport-safe facade", partial)
	}
	if got.Error() != partial.Error() {
		t.Fatalf("AsTransport(%v) error string = %q, want %q", partial, got.Error(), partial.Error())
	}
	if !errors.Is(got, ErrPartialFanout) {
		t.Fatalf("AsTransport(%v) = %v, want partial fan-out marker preserved", partial, got)
	}
	if !errors.Is(got, ErrUnavailable) {
		t.Fatalf("AsTransport(%v) = %v, want nested %v preserved for diagnostics", partial, got, ErrUnavailable)
	}
	if !errors.Is(got, unknownCause) {
		t.Fatalf("AsTransport(%v) = %v, want unknown diagnostic cause preserved", partial, got)
	}
	for _, sentinel := range []error{
		errkit.ErrAlreadyExists,
		errkit.ErrNotFound,
		errkit.ErrUnauthenticated,
		errkit.ErrUnauthorized,
		errkit.ErrInvalidArgument,
		errkit.ErrUnavailable,
	} {
		if errors.Is(got, sentinel) {
			t.Fatalf("AsTransport(%v) unexpectedly matched transport sentinel %v", partial, sentinel)
		}
	}

	w := httptest.NewRecorder()
	httpkit.ErrorHTTP(w, httptest.NewRequest(http.MethodPost, "/publish", nil), got)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("ErrorHTTP(AsTransport(%v)) status = %d, want %d", partial, w.Code, http.StatusInternalServerError)
	}

	_, grpcErr := grpckit.ErrorGRPC[struct{}](context.Background(), got)
	if code := status.Code(grpcErr); code != codes.Internal {
		t.Fatalf("ErrorGRPC(AsTransport(%v)) code = %v, want %v", partial, code, codes.Internal)
	}
}

type partialFanoutError struct {
	causes []error
}

func (e *partialFanoutError) Error() string { return "partial topic fan-out" }

func (e *partialFanoutError) Unwrap() []error { return e.causes }

func TestIsFailedPreconditionPreservesPolicyState(t *testing.T) {
	err := fmt.Errorf("delete queue: %w", ErrFailedPrecondition)
	if !IsFailedPrecondition(err) {
		t.Fatalf("IsFailedPrecondition(%v) = false, want true", err)
	}
}
