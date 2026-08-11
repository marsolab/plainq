package main

import (
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/heartwilltell/scotty"
)

// TestCommandSpecsAreSelfDescribing is the guard that keeps this CLI usable by
// a caller who only has the binary — no documentation, no source. Every command
// has to say what it does, what it takes, what it costs to run, and show at
// least one worked invocation, and every flag has to explain itself.
//
// A command added without that metadata fails here rather than silently
// shipping a help page that answers nothing.
func TestCommandSpecsAreSelfDescribing(t *testing.T) {
	root := testRoot(t)

	walkSpecs(root, func(spec *commandSpec) {
		t.Run(spec.path(), func(t *testing.T) {
			if spec.Short == "" {
				t.Error("Short is empty: every command needs a one-line summary")
			}

			if spec.Long == "" {
				t.Error("Long is empty: every command needs a description")
			}

			for _, arg := range spec.Args {
				if arg.Name == "" || arg.Description == "" {
					t.Errorf("positional argument %q is undocumented", arg.Name)
				}
			}

			spec.command().Flags().VisitAll(func(f *flag.Flag) {
				if strings.TrimSpace(f.Usage) == "" {
					t.Errorf("flag -%s has no usage text", f.Name)
				}
			})

			// Group commands only dispatch; the requirements below are about
			// commands a caller actually runs.
			if spec.Run == nil {
				return
			}

			if spec.Effect == "" {
				t.Error("Effect is empty: a caller cannot tell whether running this is safe")
			}

			if len(spec.Examples) == 0 {
				t.Error("no examples: agents copy examples before they read prose")
			}

			for _, example := range spec.Examples {
				if example.Command == "" {
					t.Error("example has no command")
				}
			}
		})
	})
}

// TestRequiredArgumentsAppearInUsage checks that the call signature a caller
// reads matches the arguments the command actually documents.
func TestRequiredArgumentsAppearInUsage(t *testing.T) {
	root := testRoot(t)

	walkSpecs(root, func(spec *commandSpec) {
		usage := spec.usageLine()

		for _, arg := range spec.Args {
			if !strings.Contains(usage, arg.Name) {
				t.Errorf("%s: usage %q omits argument %q", spec.path(), usage, arg.Name)
			}
		}

		if len(spec.flags()) > 0 && !strings.Contains(usage, "[flags]") {
			t.Errorf("%s: usage %q omits [flags]", spec.path(), usage)
		}
	})
}

// TestUsageIncludesTheContract checks that help answers the questions a caller
// has before running an unfamiliar command.
func TestUsageIncludesTheContract(t *testing.T) {
	root := testRoot(t)

	send := root.lookup("send")
	if send == nil {
		t.Fatal("send command not found")
	}

	var b strings.Builder

	send.printUsage(&b)

	help := b.String()

	for _, want := range []string{
		"plainq send - Send one or more messages to a queue",
		"Usage:",
		"plainq send [flags] <queue-id>",
		"Arguments:",
		"<queue-id>",
		"Flags:",
		"-message string",
		"(repeatable)",
		`(default "localhost:8080")`,
		"Examples:",
		"Effect: mutating",
		"Exit codes:",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help for send is missing %q\n---\n%s", want, help)
		}
	}
}

// TestRootUsageListsConventions checks that the root help teaches the calling
// convention, since that is the first thing a caller reads.
func TestRootUsageListsConventions(t *testing.T) {
	root := testRoot(t)

	var b strings.Builder

	root.printUsage(&b)

	help := b.String()

	for _, want := range []string{"Commands:", "Conventions:", "Exit codes:", "before or after positional"} {
		if !strings.Contains(help, want) {
			t.Errorf("root help is missing %q\n---\n%s", want, help)
		}
	}
}

func TestFlagValueType(t *testing.T) {
	var (
		set      = flag.NewFlagSet("test", flag.ContinueOnError)
		text     string
		enabled  bool
		count    int
		unsigned uint
		ratio    float64
		wait     time.Duration
		repeated stringSliceFlag
	)

	set.StringVar(&text, "text", "", "")
	set.BoolVar(&enabled, "enabled", false, "")
	set.IntVar(&count, "count", 0, "")
	set.UintVar(&unsigned, "unsigned", 0, "")
	set.Float64Var(&ratio, "ratio", 0, "")
	set.DurationVar(&wait, "wait", 0, "")
	set.Var(&repeated, "repeated", "")

	cases := map[string]struct {
		wantType       string
		wantRepeatable bool
	}{
		"text":     {wantType: "string"},
		"enabled":  {wantType: "bool"},
		"count":    {wantType: "int"},
		"unsigned": {wantType: "uint"},
		"ratio":    {wantType: "float"},
		"wait":     {wantType: "duration"},
		"repeated": {wantType: "string", wantRepeatable: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			found := set.Lookup(name)
			if found == nil {
				t.Fatalf("flag %q not registered", name)
			}

			gotType, gotRepeatable := flagValueType(found.Value)
			if gotType != tc.wantType || gotRepeatable != tc.wantRepeatable {
				t.Fatalf("flagValueType(%q) = (%q, %v), want (%q, %v)",
					name, gotType, gotRepeatable, tc.wantType, tc.wantRepeatable,
				)
			}
		})
	}
}

func TestReportError(t *testing.T) {
	cases := map[string]struct {
		err      error
		wantCode int
		wantText string
	}{
		"runtime failure": {
			err:      errors.New("list queues: server exploded"),
			wantCode: exitFailure,
			wantText: "plainq: list queues: server exploded\n",
		},
		"usage error": {
			err:      usagef("queue id is required"),
			wantCode: exitUsage,
			wantText: "plainq: queue id is required\n",
		},
		"wrapped usage error": {
			err:      errors.New("command failed: " + usagef("bad flag").Error()),
			wantCode: exitFailure,
			wantText: "plainq: bad flag\n",
		},
		"unknown command": {
			err:      errors.New("unknown command: frobnicate"),
			wantCode: exitUsage,
			wantText: "plainq: unknown command: frobnicate\n",
		},
		"scotty prefix is stripped": {
			err:      errors.New("command failed: send messages: nope"),
			wantCode: exitFailure,
			wantText: "plainq: send messages: nope\n",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var b strings.Builder

			if got := reportError(&b, tc.err); got != tc.wantCode {
				t.Errorf("exit code = %d, want %d", got, tc.wantCode)
			}

			if got := b.String(); got != tc.wantText {
				t.Errorf("message = %q, want %q", got, tc.wantText)
			}
		})
	}
}

// TestUsageErrorSurvivesScottyWrapping checks the path that actually happens at
// runtime: scotty wraps whatever Run returns, and the exit code still has to
// come out as a usage error.
func TestUsageErrorSurvivesScottyWrapping(t *testing.T) {
	spec := &commandSpec{
		Name:  "boom",
		Short: "always fails",
		Run: func(_ *scotty.Command, _ []string) error {
			return usagef("bad argument")
		},
	}

	err := spec.command().Run(nil, nil)

	var b strings.Builder

	if got := reportError(&b, err); got != exitUsage {
		t.Fatalf("exit code = %d, want %d", got, exitUsage)
	}
}

func TestWrapText(t *testing.T) {
	got := wrapText("one two three four five", 9, "..")

	want := "one two\n..three\n..four five"
	if got != want {
		t.Fatalf("wrapText = %q, want %q", got, want)
	}

	// A word wider than the wrap column is left whole rather than broken.
	if got := wrapText("supercalifragilistic", 5, ""); got != "supercalifragilistic" {
		t.Fatalf("long word was broken: %q", got)
	}
}

// TestSchemaCoversEveryCommand checks that the machine-readable surface and the
// command tree stay the same shape — an agent that reads the schema must not
// find commands missing from it.
func TestSchemaCoversEveryCommand(t *testing.T) {
	root := testRoot(t)

	out, err := buildSchema(root, schemaTargetAll)
	if err != nil {
		t.Fatalf("build schema: %v", err)
	}

	if out.CLI == nil {
		t.Fatal("cli surface missing")
	}

	if len(out.GRPC) == 0 {
		t.Fatal("grpc surface missing")
	}

	paths := make(map[string]bool)

	var collect func(commands []cliCommand)

	collect = func(commands []cliCommand) {
		for _, command := range commands {
			paths[command.Path] = true

			collect(command.Subcommands)
		}
	}

	collect(out.CLI.Commands)

	walkSpecs(root, func(spec *commandSpec) {
		if spec == root {
			return
		}

		if !paths[spec.path()] {
			t.Errorf("command %q is missing from the schema", spec.path())
		}
	})
}

func TestSchemaRejectsUnknownTarget(t *testing.T) {
	root := testRoot(t)

	_, err := buildSchema(root, "nonsense")
	if err == nil {
		t.Fatal("expected an error for an unknown target")
	}

	var usage *usageError
	if !errors.As(err, &usage) {
		t.Fatalf("expected a usage error, got %T", err)
	}
}

// walkSpecs visits spec and everything under it.
func walkSpecs(spec *commandSpec, visit func(*commandSpec)) {
	visit(spec)

	for _, sub := range spec.Subcommands {
		walkSpecs(sub, visit)
	}
}
