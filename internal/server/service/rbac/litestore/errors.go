package litestore

import (
	"fmt"
	"strings"

	"github.com/marsolab/plainq/internal/shared/pqerr"
)

// classifyWrite maps a constraint failure onto a domain error so the transport
// can answer 400 or 409 instead of 500.
//
// A grant naming a queue that does not exist is the caller's mistake, and
// SQLite reports it as a foreign-key failure. The check is on the message
// because that is the stable surface every SQLite driver shares — the extended
// result code lives behind a driver-specific error type this package would
// otherwise have to import.
func classifyWrite(err error) error {
	if err == nil {
		return nil
	}

	message := err.Error()

	switch {
	case strings.Contains(message, "FOREIGN KEY constraint failed"):
		return fmt.Errorf("%w: %w", pqerr.ErrInvalidInput, err)

	case strings.Contains(message, "UNIQUE constraint failed"):
		return fmt.Errorf("%w: %w", pqerr.ErrAlreadyExists, err)

	default:
		return err
	}
}
