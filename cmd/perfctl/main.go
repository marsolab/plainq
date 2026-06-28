// Command perfctl is the controller for the PlainQ performance / load-test
// harness under perf/. It wraps the Docker Compose stack (VictoriaMetrics,
// Grafana, k6) so load tests can be spun up with a single command.
//
//	perfctl ab                      # candidate (HEAD) vs baseline (origin/main)
//	perfctl ab -baseline v0.1.0 -vus 50 -duration 5m
//	perfctl load -target localhost:8080   # load any running server
//	perfctl up / down / clean / dashboard
//
// It must be run from within a PlainQ checkout (it locates the repo root via
// git) and requires Docker with the Compose plugin.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/heartwilltell/scotty"
)

// Build metadata, set via -ldflags at build time.
var (
	// Branch is the branch this binary was built from.
	Branch = "local"

	// Commit is the commit this binary was built from.
	Commit = "unknown"
)

// Default workload knobs, shared by the ab and load commands.
const (
	defaultBaseline = "origin/main"
	defaultVUS      = "20"
	defaultDuration = "2m"
	defaultBatch    = "1"
	defaultMsgBytes = "256"
	defaultTarget   = "host.docker.internal:8080"

	// k6 exits 99 when a threshold is crossed; for a load run that is a
	// reportable result, not a hard failure.
	k6ThresholdExitCode = 99
)

func main() {
	root := scotty.Command{
		Name:  "perfctl",
		Short: "Controller for the PlainQ performance / load-test harness",
	}

	root.AddSubcommands(
		abCommand(),
		loadCommand(),
		upCommand(),
		downCommand(),
		cleanCommand(),
		dashboardCommand(),
		versionCommand(),
	)

	if err := root.Exec(); err != nil {
		fmt.Fprintln(os.Stderr, "perfctl:", err)
		os.Exit(1)
	}
}

// abCommand builds two servers (candidate = current checkout, baseline = a git
// ref), runs an identical k6 gRPC workload against both, and reports the
// comparison. It delegates to perf/scripts/run.sh, the path also used by CI.
func abCommand() *scotty.Command {
	var (
		baseline string
		vus      string
		duration string
		batch    string
		msgBytes string
		runID    string
		keepUp   bool
	)

	cmd := scotty.Command{
		Name:  "ab",
		Short: "Run a candidate-vs-baseline AB load test and print the comparison",
		SetFlags: func(f *scotty.FlagSet) {
			f.StringVarE(&baseline, "baseline", "BASELINE_REF", defaultBaseline, "git ref to use as the baseline")
			f.StringVarE(&vus, "vus", "VUS", defaultVUS, "virtual users per variant")
			f.StringVarE(&duration, "duration", "DURATION", defaultDuration, "load duration (e.g. 45s, 2m)")
			f.StringVarE(&batch, "batch", "BATCH_SIZE", defaultBatch, "receive batch size (1-10)")
			f.StringVarE(&msgBytes, "msg-bytes", "MSG_BYTES", defaultMsgBytes, "message body size in bytes")
			f.StringVarE(&runID, "run-id", "RUN_ID", "", "run label (default: git short sha)")
			f.BoolVarE(&keepUp, "keep-up", "KEEP_UP", true, "keep the stack running after the test")
		},
		Run: func(_ *scotty.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}

			env := envWith(map[string]string{
				"BASELINE_REF": baseline,
				"VUS":          vus,
				"DURATION":     duration,
				"BATCH_SIZE":   batch,
				"MSG_BYTES":    msgBytes,
				"RUN_ID":       runID,
				"KEEP_UP":      boolEnv(keepUp),
			})

			script := filepath.Join(root, "perf", "scripts", "run.sh")

			return run(root, env, "bash", script, baseline)
		},
	}

	return &cmd
}

// loadCommand drives a single already-running server with the same workload
// (no baseline, no build). Metrics stream to VictoriaMetrics so the Grafana
// dashboard works; the series are tagged variant=<name> (default "load").
func loadCommand() *scotty.Command {
	var (
		target   string
		variant  string
		vus      string
		duration string
		batch    string
		msgBytes string
		runID    string
		stack    bool
	)

	cmd := scotty.Command{
		Name:  "load",
		Short: "Load-test a single running server (no AB comparison)",
		Long: "Load-test a single running gRPC server. Use host.docker.internal:PORT " +
			"to reach a server running on the host (e.g. `plainq serve`).",
		SetFlags: func(f *scotty.FlagSet) {
			f.StringVarE(&target, "target", "TARGET_ADDR", defaultTarget, "gRPC address to load (host:port)")
			f.StringVarE(&variant, "name", "VARIANT", "load", "series label for this run")
			f.StringVarE(&vus, "vus", "VUS", defaultVUS, "virtual users")
			f.StringVarE(&duration, "duration", "DURATION", defaultDuration, "load duration (e.g. 45s, 2m)")
			f.StringVarE(&batch, "batch", "BATCH_SIZE", defaultBatch, "receive batch size (1-10)")
			f.StringVarE(&msgBytes, "msg-bytes", "MSG_BYTES", defaultMsgBytes, "message body size in bytes")
			f.StringVarE(&runID, "run-id", "RUN_ID", "", "run label")
			f.BoolVarE(&stack, "stack", "", true, "bring up VictoriaMetrics + Grafana so the dashboard works")
		},
		Run: func(_ *scotty.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}

			compose := composeFile(root)
			env := envWith(map[string]string{
				"TARGET_ADDR": target,
				"VARIANT":     variant,
				"VUS":         vus,
				"DURATION":    duration,
				"BATCH_SIZE":  batch,
				"MSG_BYTES":   msgBytes,
				"RUN_ID":      runID,
			})

			// k6 writes its summary into the bind-mounted results dir as a
			// non-root user, so it must exist and be writable first.
			if err := ensureWorldWritableDir(filepath.Join(root, "perf", "results")); err != nil {
				return err
			}

			if stack {
				if err := run(root, env, "docker", "compose", "-f", compose, "up", "-d", "victoriametrics", "grafana"); err != nil {
					return fmt.Errorf("start stack: %w", err)
				}
			}

			fmt.Fprintf(os.Stderr, "Loading %s with %s VUs for %s...\n", target, vus, duration)

			err = run(root, env, "docker", "compose", "-f", compose, "run", "--rm", "k6-load")
			if code, ok := exitCode(err); ok && code == k6ThresholdExitCode {
				fmt.Fprintln(os.Stderr, "perfctl: k6 thresholds crossed (see summary above)")

				err = nil
			}

			if err != nil {
				return err
			}

			if stack {
				printEndpoints()
			}

			return nil
		},
	}

	return &cmd
}

// upCommand starts the observability stack (VictoriaMetrics + Grafana) without
// any servers, e.g. before a series of `perfctl load` runs.
func upCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "up",
		Short: "Start VictoriaMetrics + Grafana",
		Run: func(_ *scotty.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}

			if err := run(root, os.Environ(), "docker", "compose", "-f", composeFile(root),
				"up", "-d", "victoriametrics", "grafana"); err != nil {
				return err
			}

			printEndpoints()

			return nil
		},
	}

	return &cmd
}

// downCommand stops the stack, leaving volumes intact.
func downCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "down",
		Short: "Stop the stack (keep volumes)",
		Run: func(_ *scotty.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}

			return run(root, os.Environ(), "docker", "compose", "-f", composeFile(root), "down")
		},
	}

	return &cmd
}

// cleanCommand tears everything down: stack, volumes, built images, and the
// generated results directory.
func cleanCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "clean",
		Short: "Stop the stack and remove volumes, images, and results",
		Run: func(_ *scotty.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}

			// Best-effort: keep going even if some resources are absent.
			tryRun(root, os.Environ(), "docker", "compose", "-f", composeFile(root), "down", "-v")
			tryRun(root, os.Environ(), "docker", "image", "rm", "plainq-perf:candidate", "plainq-perf:baseline")

			if err := os.RemoveAll(filepath.Join(root, "perf", "results")); err != nil {
				return fmt.Errorf("remove results: %w", err)
			}

			return nil
		},
	}

	return &cmd
}

// dashboardCommand prints the URLs of the running stack.
func dashboardCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "dashboard",
		Short: "Print the Grafana and VictoriaMetrics URLs",
		Run: func(_ *scotty.Command, _ []string) error {
			printEndpoints()

			return nil
		},
	}

	return &cmd
}

func versionCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "version",
		Short: "Print the build version",
		Run: func(_ *scotty.Command, _ []string) error {
			fmt.Printf("perfctl %s [%s]\n", Branch, Commit)

			return nil
		},
	}

	return &cmd
}

// repoRoot returns the PlainQ repository root by asking git, falling back to
// the current working directory.
func repoRoot() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}

	wd, wdErr := os.Getwd()
	if wdErr != nil {
		return "", fmt.Errorf("locate repo root: %w", wdErr)
	}

	return wd, nil
}

// composeFile returns the path to the perf Docker Compose file.
func composeFile(root string) string {
	return filepath.Join(root, "perf", "docker-compose.yml")
}

// run executes a command in dir with env, streaming I/O to the terminal and
// canceling on SIGINT/SIGTERM.
func run(dir string, env []string, name string, args ...string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	return nil
}

// tryRun runs a command best-effort, logging (but not returning) any error.
func tryRun(dir string, env []string, name string, args ...string) {
	if err := run(dir, env, name, args...); err != nil {
		fmt.Fprintf(os.Stderr, "perfctl: %s (continuing)\n", err)
	}
}

// envWith returns the current environment with the given key/value pairs
// applied. Empty values are skipped so flag defaults do not clobber values
// that the underlying scripts resolve themselves.
func envWith(overrides map[string]string) []string {
	merged := make(map[string]string, len(overrides))

	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			merged[k] = v
		}
	}

	for k, v := range overrides {
		if v != "" {
			merged[k] = v
		}
	}

	env := make([]string, 0, len(merged))
	for k, v := range merged {
		env = append(env, k+"="+v)
	}

	return env
}

// ensureWorldWritableDir creates dir (if absent) and makes it world-writable,
// mirroring scripts/run.sh: the k6 image runs as a non-root user and must be
// able to write its run summary into the bind-mounted results directory.
func ensureWorldWritableDir(path string) error {
	if err := os.MkdirAll(path, 0o777); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	if err := os.Chmod(path, 0o777); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}

	return nil
}

// boolEnv renders a bool as the "1"/"0" the shell scripts expect.
func boolEnv(b bool) string {
	if b {
		return "1"
	}

	return "0"
}

// exitCode extracts the process exit code from an error returned by run.
func exitCode(err error) (int, bool) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), true
	}

	return 0, false
}

// printEndpoints prints where to view results.
func printEndpoints() {
	fmt.Fprintln(os.Stderr, "Grafana:        http://localhost:3000  (PlainQ AB Performance)")
	fmt.Fprintln(os.Stderr, "VictoriaMetrics http://localhost:8428")
}
