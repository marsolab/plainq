package pqerr

import (
	"errors"
	"fmt"

	"github.com/marsolab/servekit/errkit"
)

// AsTransport re-wraps a storage-layer error so the transport layer maps it to
// the status code it deserves.
//
// Storage speaks pqerr; httpkit and grpckit only recognise errkit sentinels and
// answer 500 for everything else. Without this translation a missing role reads
// as an internal failure, which is both wrong for the caller and misleading in
// logs. Errors that carry no pqerr sentinel are returned untouched — an
// unrecognised failure really is a 500.
func AsTransport(err error) error {
	if err == nil {
		return nil
	}

	sentinel := transportSentinel(err)
	if sentinel == nil {
		return err
	}

	return fmt.Errorf("%w: %w", sentinel, err)
}

func transportSentinel(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return errkit.ErrNotFound

	case errors.Is(err, ErrAlreadyExists):
		return errkit.ErrAlreadyExists

	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrInvalidID):
		return errkit.ErrInvalidArgument

	case errors.Is(err, ErrUnauthenticated):
		return errkit.ErrUnauthenticated

	case errors.Is(err, ErrUnauthorized):
		return errkit.ErrUnauthorized

	case errors.Is(err, ErrUnavailable):
		return errkit.ErrUnavailable

	default:
		return nil
	}
}
