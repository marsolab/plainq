package pgstore

import (
	"errors"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestListQueuesCursorIsOpaqueAndStable(t *testing.T) {
	rawCursor := "x' OR 1=1 --"

	_, _, err := queryListQueues(
		2,
		"",
		rawCursor,
		v1.ListQueuesRequest_ORDER_BY_NAME,
		v1.ListQueuesRequest_SORT_BY_ASC,
	)

	if !errors.Is(err, pqerr.ErrInvalidInput) {
		t.Fatalf("injected cursor error = %v, want invalid input", err)
	}
}
