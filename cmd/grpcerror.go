package main

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A raw gRPC failure reads like this:
//
//	rpc error: code = Unavailable desc = connection error: desc = "transport:
//	Error while dialing: dial tcp 127.0.0.1:8080: connect: connection refused"
//
// Everything a caller needs is in there, buried under two layers of framing.
// grpcError digs it out and, where the failure has an obvious remedy, says what
// it is — because the most common thing to go wrong is that nobody started a
// server, and the fix should not require parsing nested descriptions to find.

// dialPrefix is the framing gRPC puts in front of a connection failure. It
// names the transport rather than the problem, so it is dropped.
const dialPrefix = "transport: Error while dialing: "

// grpcError renders a gRPC failure as an actionable message. operation names
// what was attempted; addr is the server that was called.
//
// Failures the server blames on the request come back as usage errors, so the
// exit code tells a caller whether to fix the command or retry it.
func grpcError(addr, operation string, err error) error {
	st, ok := grpcStatus(err)
	if !ok {
		// Not a gRPC status: a dial failure, a context cancellation, an
		// encoding error. Nothing to translate.
		return fmt.Errorf("%s: %w", operation, err)
	}

	message := cleanStatusMessage(st.Message())

	// Only the codes with advice worth giving are named; the rest are reported
	// as the server phrased them.
	//
	//nolint:exhaustive // The default arm deliberately covers every other code.
	switch st.Code() {
	case codes.Unavailable:
		return fmt.Errorf("cannot reach a PlainQ server at %q: %s"+
			` (start one with "plainq serve", or point -%s or $%s at a running server)`,
			addr, message, flagGRPCAddr, envGRPCAddr,
		)

	case codes.NotFound:
		return fmt.Errorf(`%s: %s (list the queues that do exist with "plainq list")`, operation, message)

	case codes.InvalidArgument:
		return usagef("%s: %s", operation, message)

	case codes.Unauthenticated, codes.PermissionDenied:
		return fmt.Errorf("%s: %s (the server requires credentials for this call)", operation, message)

	case codes.DeadlineExceeded:
		return fmt.Errorf("%s: %s (the server did not answer in time)", operation, message)

	default:
		return fmt.Errorf("%s: %s", operation, message)
	}
}

// grpcStatus extracts the status from err, however deeply it is wrapped.
//
// status.FromError would find it too, but on a wrapped error it overwrites the
// status message with the whole wrapped chain — which is exactly the framing
// this file exists to remove.
func grpcStatus(err error) (*status.Status, bool) {
	var carrier interface{ GRPCStatus() *status.Status }

	if !errors.As(err, &carrier) {
		return nil, false
	}

	st := carrier.GRPCStatus()
	if st == nil {
		return nil, false
	}

	return st, true
}

// cleanStatusMessage unwraps the nested `desc = "..."` framing gRPC adds around
// transport errors and returns the innermost description.
func cleanStatusMessage(message string) string {
	if _, inner, found := strings.Cut(message, `desc = "`); found {
		message = strings.TrimSuffix(inner, `"`)
	}

	return strings.TrimPrefix(message, dialPrefix)
}
