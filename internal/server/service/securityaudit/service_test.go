package securityaudit

import (
	"strings"
	"testing"
)

func TestEventRejectsPayloadMetadata(t *testing.T) {
	event := Event{Metadata: map[string]string{"body": "secret"}}
	if err := event.Validate(); err == nil {
		t.Fatal("Event.Validate() error = nil, want unsupported metadata error")
	}
}

func TestEventAcceptsOnlyBoundedMetadata(t *testing.T) {
	event := Event{Metadata: map[string]string{"message_count": "1"}}
	if err := event.Validate(); err != nil {
		t.Fatalf("Event.Validate() error = %v", err)
	}

	event.Metadata["message_count"] = strings.Repeat("x", 257)
	if err := event.Validate(); err == nil {
		t.Fatal("Event.Validate() oversized value error = nil")
	}
}
