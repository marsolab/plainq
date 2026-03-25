package queue

import (
	"strings"

	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/idkit"
)

// validateQueueIDFromRequest performs validation of the queue identifier.
func validateQueueIDFromRequest(r interface{ GetQueueId() string }) error {
	if r == nil {
		return errkit.ErrInvalidID
	}

	return validateQueueID(r.GetQueueId())
}

// validateQueueID validates given queue identifier.
func validateQueueID(queueID string) error {
	if queueID == "" {
		return errkit.ErrInvalidID
	}

	if err := idkit.ValidateXID(strings.ToLower(queueID)); err != nil {
		return errkit.ErrInvalidID
	}

	return nil
}
