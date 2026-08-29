package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestCollectMessageBodiesFromFlags(t *testing.T) {
	bodies, err := collectMessageBodies([]string{"a", "b"}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bodies) != 2 {
		t.Fatalf("expected 2 bodies, got %d", len(bodies))
	}

	if string(bodies[0]) != "a" || string(bodies[1]) != "b" {
		t.Fatalf("unexpected bodies: %q %q", bodies[0], bodies[1])
	}
}

func TestCollectMessageBodiesTreatsExplicitEmptyMessageAsBody(t *testing.T) {
	bodies, err := collectMessageBodies([]string{""}, "", nil)
	if err != nil {
		t.Fatalf("explicit empty message: %v", err)
	}
	if len(bodies) != 1 || len(bodies[0]) != 0 {
		t.Fatalf("bodies = %q, want one empty body", bodies)
	}
}

func TestCollectMessageBodiesEmpty(t *testing.T) {
	stdin := &failOnRead{err: errors.New("stdin must not be read")}

	if _, err := collectMessageBodies(nil, "", stdin); err == nil {
		t.Fatal("expected error when no messages are provided")
	}
	if stdin.reads != 0 {
		t.Fatalf("stdin reads = %d, want 0", stdin.reads)
	}
}

func TestCollectMessageBodiesFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bodies.txt")

	if err := os.WriteFile(path, []byte("one\n\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	bodies, err := collectMessageBodies([]string{"flag"}, path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// One flag body plus three non-empty file lines (the blank line is skipped).
	if len(bodies) != 4 {
		t.Fatalf("expected 4 bodies, got %d", len(bodies))
	}

	if string(bodies[0]) != "flag" || string(bodies[1]) != "one" {
		t.Fatalf("unexpected order: %q %q", bodies[0], bodies[1])
	}
}

func TestCollectMessageBodiesReadsStdinOnlyWhenExplicit(t *testing.T) {
	bodies, err := collectMessageBodies([]string{"flag"}, "-", strings.NewReader("stdin-one\n\nstdin-two\n"))
	if err != nil {
		t.Fatalf("collect mixed input: %v", err)
	}

	want := [][]byte{[]byte("flag"), []byte("stdin-one"), []byte("stdin-two")}
	if !equalBodies(bodies, want) {
		t.Fatalf("bodies = %q, want %q", bodies, want)
	}
}

func TestCollectMessageBodiesRejectsEmptyFileInput(t *testing.T) {
	_, err := collectMessageBodies(nil, "-", strings.NewReader("\n\n"))
	if err == nil {
		t.Fatal("expected an error for a file containing only empty lines")
	}

	var usage *usageError
	if !errors.As(err, &usage) {
		t.Fatalf("error type = %T, want *usageError", err)
	}
}

func TestReadMessageBodyLinesLimit(t *testing.T) {
	exact := bytes.Repeat([]byte{'x'}, maxMessageLineBytes)
	over := bytes.Repeat([]byte{'x'}, maxMessageLineBytes+1)

	tests := map[string]struct {
		input   []byte
		wantErr bool
	}{
		"exact limit at EOF": {
			input: exact,
		},
		"exact limit before newline": {
			input: append(bytes.Clone(exact), '\n'),
		},
		"over limit at EOF": {
			input:   over,
			wantErr: true,
		},
		"over limit before newline": {
			input:   append(bytes.Clone(over), '\n'),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			bodies, err := readMessageBodyLines("-", bytes.NewReader(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an over-limit error")
				}

				var usage *usageError
				if !errors.As(err, &usage) {
					t.Fatalf("error type = %T, want *usageError", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("read exact-limit line: %v", err)
			}
			if len(bodies) != 1 || len(bodies[0]) != maxMessageLineBytes {
				t.Fatalf("body lengths = %v, want [%d]", bodyLengths(bodies), maxMessageLineBytes)
			}
		})
	}
}

func TestReadMessageBodyLinesDropsCarriageReturn(t *testing.T) {
	bodies, err := readMessageBodyLines("-", strings.NewReader("one\r\ntwo\r"))
	if err != nil {
		t.Fatalf("read CRLF bodies: %v", err)
	}

	want := [][]byte{[]byte("one"), []byte("two")}
	if !equalBodies(bodies, want) {
		t.Fatalf("bodies = %q, want %q", bodies, want)
	}
}

func equalBodies(got, want [][]byte) bool {
	if len(got) != len(want) {
		return false
	}

	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			return false
		}
	}

	return true
}

func bodyLengths(bodies [][]byte) []int {
	lengths := make([]int, 0, len(bodies))
	for _, body := range bodies {
		lengths = append(lengths, len(body))
	}

	return lengths
}

type failOnRead struct {
	reads int
	err   error
}

func (r *failOnRead) Read(_ []byte) (int, error) {
	r.reads++

	return 0, r.err
}

var _ io.Reader = (*failOnRead)(nil)

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
	services := collectGRPCSchema()
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
