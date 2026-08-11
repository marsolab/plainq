package main

import (
	"path/filepath"
	"slices"
	"testing"
)

// testRoot builds the real command tree with the context file pointed at a path
// that does not exist, so that flag defaults do not depend on whatever the
// machine running the tests happens to have configured.
func testRoot(t *testing.T) *commandSpec {
	t.Helper()

	t.Setenv(envContextFile, filepath.Join(t.TempDir(), "absent.json"))
	t.Setenv(envGRPCAddr, "")

	root := rootCommand()
	root.command()

	return root
}

func TestNormalizeArgs(t *testing.T) {
	cases := map[string]struct {
		args []string
		want []string
	}{
		"empty": {
			args: nil,
			want: []string{},
		},
		"command only": {
			args: []string{"version"},
			want: []string{"version"},
		},
		"already ordered is left alone": {
			args: []string{"send", "-message=hi", "QID"},
			want: []string{"send", "-message=hi", "QID"},
		},
		"inline flag after positional moves in front": {
			args: []string{"send", "QID", "-message=hi"},
			want: []string{"send", "-message=hi", "QID"},
		},
		"separated flag value travels with its flag": {
			args: []string{"send", "QID", "-message", "hi"},
			want: []string{"send", "-message", "hi", "QID"},
		},
		"bool flag does not swallow the next argument": {
			args: []string{"delete-message", "QID", "-json", "MID"},
			want: []string{"delete-message", "-json", "QID", "MID"},
		},
		"trailing bool flag": {
			args: []string{"receive", "QID", "-ack"},
			want: []string{"receive", "-ack", "QID"},
		},
		"double dash flags are recognised": {
			args: []string{"delete", "QID", "--force"},
			want: []string{"delete", "--force", "QID"},
		},
		"variadic positionals keep their order": {
			args: []string{"delete-message", "QID", "one", "two", "-json"},
			want: []string{"delete-message", "-json", "QID", "one", "two"},
		},
		"nested subcommand": {
			args: []string{"cluster", "join", "-node-id", "n1", "-non-voter"},
			want: []string{"cluster", "join", "-node-id", "n1", "-non-voter"},
		},
		"lone dash is a value, not a flag": {
			args: []string{"send", "QID", "-file", "-"},
			want: []string{"send", "-file", "-", "QID"},
		},
		"unknown flag is left where it is and swallows nothing": {
			args: []string{"list", "-nope", "QID"},
			want: []string{"list", "-nope", "QID"},
		},
		"help flag survives reordering": {
			args: []string{"send", "QID", "-h"},
			want: []string{"send", "-h", "QID"},
		},
		"terminator keeps everything after it positional": {
			args: []string{"delete-message", "--", "-QID", "-MID"},
			want: []string{"delete-message", "--", "-QID", "-MID"},
		},
		"terminator is re-inserted when flags move in front of it": {
			args: []string{"delete-message", "--", "-QID"},
			want: []string{"delete-message", "--", "-QID"},
		},
		"unknown command is passed through untouched": {
			args: []string{"frobnicate", "-x", "y"},
			want: []string{"frobnicate", "-x", "y"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := testRoot(t)

			got := normalizeArgs(root, tc.args)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("normalizeArgs(%q)\n got: %q\nwant: %q", tc.args, got, tc.want)
			}
		})
	}
}

// TestNormalizeArgsLeavesServeUntouched is the highest-stakes case in this
// file. Rewriting os.Args happens before any command runs, so it applies to
// "serve" too — and serve is how the server is started in Docker, in Helm, and
// in the perf harness. A reordering bug that dropped or swapped a server flag
// would not fail a test or print a warning; it would silently start a server
// configured differently from the one that was asked for.
//
// The first case is the literal command line from perf/docker-compose.yml.
func TestNormalizeArgsLeavesServeUntouched(t *testing.T) {
	cases := map[string][]string{
		"perf harness command line": {
			"serve",
			"-grpc.addr=:8080",
			"-http.addr=:8081",
			"-storage.path=/data/plainq.db",
			"-auth.enable=false",
			"-auth.jwt.secret=perf-not-a-secret",
			"-telemetry.enable=false",
			"-log.access.enable=false",
			"-log.level=warn",
		},
		"space-separated values travel with their flags": {
			"serve", "-grpc.addr", ":8080", "-storage.path", "/data/plainq.db", "-log.level", "warn",
		},
		"bare bool flag does not swallow the next flag": {
			"serve", "-auth.enable", "-log.level=warn",
		},
		"quickstart form from the README": {
			"serve", "--auth.jwt.secret=abc123",
		},
		"durations and cluster flags": {
			"serve", "-cluster.enable", "-storage.gc.timeout=30s", "-auth.access.ttl", "1h",
		},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			root := testRoot(t)

			got := normalizeArgs(root, args)
			if !slices.Equal(got, args) {
				t.Fatalf("normalizeArgs rewrote a serve command line\n in: %q\nout: %q", args, got)
			}
		})
	}
}

// TestNormalizeArgsPreservesArguments guards the property that matters most:
// reordering may move arguments, but it must never lose or invent one.
func TestNormalizeArgsPreservesArguments(t *testing.T) {
	inputs := [][]string{
		{"send", "QID", "-message", "a", "-message", "b", "-json"},
		{"receive", "-batch", "10", "QID", "-ack"},
		{"cluster", "leave", "-node-id", "n1", "-json"},
		{"create", "orders", "-visibility-timeout", "300"},
	}

	for _, args := range inputs {
		root := testRoot(t)

		got := normalizeArgs(root, args)

		want := slices.Clone(args)
		slices.Sort(want)

		sorted := slices.Clone(got)
		slices.Sort(sorted)

		if !slices.Equal(sorted, want) {
			t.Fatalf("normalizeArgs(%q) changed the argument multiset: %q", args, got)
		}
	}
}
