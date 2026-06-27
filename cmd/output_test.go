package main

import (
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

func TestValidateQueueID(t *testing.T) {
	cases := map[string]struct {
		id      string
		wantErr bool
	}{
		"upper-case xid": {id: "D8VEKIMGOO6F7O6LNLN0", wantErr: false},
		"lower-case xid": {id: "d8vekimgoo6f7o6lnln0", wantErr: false},
		"empty":          {id: "", wantErr: true},
		"too short":      {id: "abc", wantErr: true},
		"not base32":     {id: "!!!!!!!!!!!!!!!!!!!!", wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateQueueID(tc.id)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.id)
			}

			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.id, err)
			}
		})
	}
}

func TestCollectSendMessagesFromFlags(t *testing.T) {
	bodies, err := collectSendMessages([]string{"a", "b"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bodies) != 2 {
		t.Fatalf("expected 2 bodies, got %d", len(bodies))
	}

	if string(bodies[0].GetBody()) != "a" || string(bodies[1].GetBody()) != "b" {
		t.Fatalf("unexpected bodies: %q %q", bodies[0].GetBody(), bodies[1].GetBody())
	}
}

func TestCollectSendMessagesEmpty(t *testing.T) {
	if _, err := collectSendMessages(nil, ""); err == nil {
		t.Fatal("expected error when no messages are provided")
	}
}

func TestCollectSendMessagesFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bodies.txt")

	if err := os.WriteFile(path, []byte("one\n\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	bodies, err := collectSendMessages([]string{"flag"}, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// One flag body plus three non-empty file lines (the blank line is skipped).
	if len(bodies) != 4 {
		t.Fatalf("expected 4 bodies, got %d", len(bodies))
	}

	if string(bodies[0].GetBody()) != "flag" || string(bodies[1].GetBody()) != "one" {
		t.Fatalf("unexpected order: %q %q", bodies[0].GetBody(), bodies[1].GetBody())
	}
}

func TestEvictionPolicyString(t *testing.T) {
	cases := map[v1.EvictionPolicy]string{
		v1.EvictionPolicy_EVICTION_POLICY_DROP:        "drop",
		v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER: "dead-letter",
		v1.EvictionPolicy_EVICTION_POLICY_REORDER:     "reorder",
		v1.EvictionPolicy_EVICTION_POLICY_UNSPECIFIED: "unspecified",
	}

	for policy, want := range cases {
		if got := evictionPolicyString(policy); got != want {
			t.Errorf("policy %v: got %q want %q", policy, got, want)
		}
	}
}

func TestCollectSchemaListsService(t *testing.T) {
	services := collectSchema()
	if len(services) == 0 {
		t.Fatal("expected at least one service")
	}

	var found bool

	for _, svc := range services {
		if svc.Service == "v1.PlainQService" {
			found = true

			if len(svc.Methods) == 0 {
				t.Fatal("expected methods on PlainQService")
			}
		}
	}

	if !found {
		t.Fatal("PlainQService not found in schema")
	}
}
