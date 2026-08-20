package pgstore

import (
	"errors"
	"strings"
	"testing"
	"time"

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

func TestListQueuesQueryBindsCursorAndLiteralPrefix(t *testing.T) {
	createdAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name    string
		orderBy v1.ListQueuesRequest_OrderBy
		value   string
	}{
		{name: "name", orderBy: v1.ListQueuesRequest_ORDER_BY_NAME, value: "x' OR 1=1 --"},
		{name: "created at", orderBy: v1.ListQueuesRequest_ORDER_BY_CREATED_AT, value: createdAt.Format(time.RFC3339Nano)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cursor := encodeQueueCursor(queueCursor{Version: 1, Order: int32(tc.orderBy), Value: tc.value, ID: "queue-id"})
			query, args, err := queryListQueues(2, "literal%_", cursor, tc.orderBy, v1.ListQueuesRequest_SORT_BY_ASC)
			if err != nil {
				t.Fatalf("build query: %v", err)
			}

			if strings.Contains(query, tc.value) {
				t.Fatalf("cursor value was interpolated into query: %s", query)
			}
			if !strings.Contains(query, "LIKE $1 ESCAPE") {
				t.Fatalf("query does not escape literal prefix: %s", query)
			}
			if got := args[0]; got != `literal\%\_%` {
				t.Fatalf("prefix argument = %#v, want literal LIKE pattern", got)
			}
			if got := args[len(args)-1]; got != int32(2) {
				t.Fatalf("limit argument = %#v, want 2", got)
			}
		})
	}
}
