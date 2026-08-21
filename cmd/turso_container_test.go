package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSqldContainerRunArgsRecordsContainerIDSeparately(t *testing.T) {
	t.Parallel()

	got := sqldContainerRunArgs("plainq-sqld-test", "/tmp/plainq-sqld.cid")
	want := []string{
		"run", "--rm", "-d", "--name", "plainq-sqld-test",
		"--cidfile", "/tmp/plainq-sqld.cid",
		"-p", "127.0.0.1::8080", "-e", "SQLD_NODE=primary", sqldImage,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sqld container args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestWaitForDockerPortRetriesTransientInspectFailures(t *testing.T) {
	t.Parallel()

	type result struct {
		output string
		err    error
	}
	results := []result{
		{output: "Error: No such object", err: errors.New("exit status 1")},
		{output: ""},
		{output: "not-a-port"},
		{output: "49152\n"},
	}
	calls := 0
	waits := 0

	got, err := waitForDockerPort(len(results), func() ([]byte, error) {
		result := results[calls]
		calls++
		return []byte(result.output), result.err
	}, func() {
		waits++
	})
	if err != nil {
		t.Fatalf("wait for mapped port: %v", err)
	}
	if got != "49152" {
		t.Fatalf("mapped port = %q, want %q", got, "49152")
	}
	if calls != 4 {
		t.Fatalf("inspect calls = %d, want 4", calls)
	}
	if waits != 3 {
		t.Fatalf("retry waits = %d, want 3", waits)
	}
}

func TestWaitForDockerPortReturnsLastDiagnostic(t *testing.T) {
	t.Parallel()

	calls := 0
	_, err := waitForDockerPort(2, func() ([]byte, error) {
		calls++
		return []byte("container is restarting"), errors.New("exit status 1")
	}, func() {})
	if err == nil {
		t.Fatal("wait for mapped port unexpectedly succeeded")
	}
	for _, want := range []string{"after 2 attempts", "exit status 1", "container is restarting"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if calls != 2 {
		t.Fatalf("inspect calls = %d, want 2", calls)
	}
}
