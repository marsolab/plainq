package pqerr

import (
	"errors"
	"fmt"
	"testing"

	"github.com/marsolab/servekit/errkit"
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

func TestPartialFanoutAlwaysMapsToInternal(t *testing.T) {
	partial := &partialFanoutError{causes: []error{ErrPartialFanout, ErrUnavailable}}

	got := AsTransport(partial)
	if got != partial {
		t.Fatalf("AsTransport(%v) = %v, want original partial error", partial, got)
	}
	if !errors.Is(got, ErrPartialFanout) {
		t.Fatalf("AsTransport(%v) = %v, want partial fan-out marker preserved", partial, got)
	}
	if !errors.Is(got, ErrUnavailable) {
		t.Fatalf("AsTransport(%v) = %v, want nested %v preserved for diagnostics", partial, got, ErrUnavailable)
	}
	if errors.Is(got, errkit.ErrUnavailable) {
		t.Fatalf("AsTransport(%v) unexpectedly matched %v", partial, errkit.ErrUnavailable)
	}
}

type partialFanoutError struct {
	causes []error
}

func (e *partialFanoutError) Error() string { return "partial topic fan-out" }

func (e *partialFanoutError) Unwrap() []error { return e.causes }
