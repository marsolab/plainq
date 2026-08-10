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

// validateDescribeQueueRequest accepts either documented lookup key. Queue IDs
// take precedence when both are set, matching the protobuf contract.
func validateDescribeQueueRequest(r interface {
	GetQueueId() string
	GetQueueName() string
}) error {
	if r == nil {
		return errkit.ErrInvalidArgument
	}

	if r.GetQueueId() != "" {
		return validateQueueID(r.GetQueueId())
	}

	if r.GetQueueName() == "" {
		return errkit.ErrInvalidArgument
	}

	return nil
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
