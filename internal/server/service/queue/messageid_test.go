package queue

import (
	"testing"
	"time"
)

// TestMessageIDRoundTrip is the guard that was missing: the id Send mints must
// be readable by the code that reports time-in-queue on delete.
func TestMessageIDRoundTrip(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC().Truncate(time.Millisecond)

	id := NewMessageID()

	createdAt, err := MessageCreatedAt(id)
	if err != nil {
		t.Fatalf("MessageCreatedAt(%q): %v", id, err)
	}

	after := time.Now().UTC()

	if createdAt.Before(before) || createdAt.After(after) {
		t.Errorf("created at %s, want between %s and %s", createdAt, before, after)
	}
}

func TestMessageCreatedAtRejectsUnreadableIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
	}{
		{name: "empty", id: ""},
		{name: "too short", id: "01ARZ3NDEK"},
		{name: "not an identifier", id: "hello world"},
		{name: "xid", id: "D9JLNDRE72TK20F60HQ0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := MessageCreatedAt(tt.id); err == nil {
				t.Errorf("MessageCreatedAt(%q): want error, got nil", tt.id)
			}
		})
	}
}
