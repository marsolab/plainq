package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteContextFileReportsFailure checks that a failed write is reported
// rather than swallowed. The command prints "created" on a nil error, so an
// error dropped here would announce a context file that does not exist.
func TestWriteContextFileReportsFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.json")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	// Closing the handle first is the portable way to make both the encode and
	// the close fail; a real deployment gets here through a full disk or an
	// exceeded quota instead.
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	if err := writeContextFile(f, plainqContextConfig{}); err == nil {
		t.Fatal("expected an error writing to a closed file")
	}
}

// TestWriteContextFileClosesTheHandle checks the success path still closes.
func TestWriteContextFileClosesTheHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.json")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	cfg := plainqContextConfig{
		Current:  plainqContext{Name: "default", Endpoint: defaultGRPCAddr},
		Contexts: []plainqContext{{Name: "default", Endpoint: defaultGRPCAddr}},
	}

	if err := writeContextFile(f, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A second close only succeeds if the first one did not happen.
	if err := f.Close(); err == nil {
		t.Error("file handle was left open")
	}

	written, readErr := readContextConfig(path)
	if readErr != nil {
		t.Fatalf("read back: %v", readErr)
	}

	if written.Current.Endpoint != defaultGRPCAddr {
		t.Errorf("endpoint = %q, want %q", written.Current.Endpoint, defaultGRPCAddr)
	}
}

// TestContextInitLeavesNoPartialFile checks the recovery path: a context file
// is created with O_EXCL, so a half-written one would make every later
// "ctx init" report that a context already exists and refuse to fix it.
func TestContextInitLeavesNoPartialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "context.json")

	t.Setenv(envContextFile, path)

	init := contextInitCommand()

	if err := init.Run(nil, nil); err != nil {
		t.Fatalf("ctx init: %v", err)
	}

	cfg, err := readContextConfig(path)
	if err != nil {
		t.Fatalf("context file is not readable after init: %v", err)
	}

	if len(cfg.Contexts) != 1 {
		t.Fatalf("contexts = %d, want 1", len(cfg.Contexts))
	}

	// Running again must be a no-op rather than a truncation.
	if err := init.Run(nil, nil); err != nil {
		t.Fatalf("second ctx init: %v", err)
	}

	if _, err := readContextConfig(path); err != nil {
		t.Fatalf("context file damaged by a second init: %v", err)
	}
}
