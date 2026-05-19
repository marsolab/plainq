---
name: go-cli
description: >-
  Building command-line tools in Go with the stdlib `flag` package.
  ALWAYS use this skill when writing or reviewing Go CLI code — top-level
  flags with `flag.Parse`, subcommands with `flag.NewFlagSet`, exit codes,
  writing errors to `os.Stderr`, signal handling, environment-variable
  fallbacks, `-h`/`-help` output, and `cmd/<tool>` project layout. Avoid
  reaching for cobra/urfave-cli unless the tool clearly needs it (~5+
  subcommands with rich help). Pair with go-style for naming and config
  patterns, go-errors for exit-code mapping, and go-logging for diagnostic
  output.
version: 1.0.0
tags:
  - go
  - golang
  - cli
  - flag
  - subcommands
---

# Go CLI

Build CLI tools with the stdlib `flag` package first. It handles 90% of
cases without a third-party dependency. Reach for cobra or urfave-cli
only when the help output or subcommand tree exceeds what `flag` can
present cleanly.

## Project layout

For a single binary:

```text
mycli/
├── main.go
├── go.mod
└── .golangci.yml
```

For multi-binary repos or tools that grow subcommand modules:

```text
mycli/
├── cmd/mycli/main.go
├── internal/command/
│   ├── add.go
│   ├── list.go
│   └── remove.go
├── go.mod
└── .golangci.yml
```

## Single-command CLI

```go
func main() {
    addr := flag.String("addr", ":8080", "listen address")
    verbose := flag.Bool("v", false, "verbose output")
    flag.Parse()

    if err := run(*addr, *verbose, flag.Args()); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func run(addr string, verbose bool, args []string) error {
    // ...
}
```

The `run` indirection makes the body testable — `main` becomes a thin
wrapper that turns errors into exit codes.

## Subcommands with flag.NewFlagSet

Each subcommand owns its own `FlagSet`. Dispatch on `os.Args[1]`:

```go
func main() {
    if len(os.Args) < 2 {
        usage()
        os.Exit(2)
    }

    cmd, args := os.Args[1], os.Args[2:]

    var err error
    switch cmd {
    case "add":
        err = runAdd(args)
    case "list":
        err = runList(args)
    case "remove":
        err = runRemove(args)
    case "-h", "--help", "help":
        usage()
        return
    default:
        fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
        usage()
        os.Exit(2)
    }

    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func runAdd(args []string) error {
    fs := flag.NewFlagSet("add", flag.ExitOnError)
    project := fs.String("project", "", "project to add to")
    fs.Parse(args)

    return command.Add(*project, fs.Args())
}
```

## Exit codes

Adopt the BSD/sysexits convention or a project-specific subset, but
**document them** in `--help`. Common pattern:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic failure |
| `2` | Usage error (bad flags, missing args) |
| `3+` | Tool-specific failure modes |

Use `os.Exit` only from `main` (or a top-level helper). Library code
returns errors.

## Stdout vs stderr

- **Stdout**: the data the tool produces. Pipe-friendly. Don't write
  status messages to stdout.
- **Stderr**: usage, errors, progress, diagnostic logs.

```go
fmt.Println("user-1234")                              // result → stdout
fmt.Fprintln(os.Stderr, "warning: deprecated flag")   // status → stderr
```

This lets `mycli list | jq .` work without filtering noise.

## Reading stdin

```go
if flag.NArg() == 0 {
    // no positional args — read from stdin
    if err := process(os.Stdin); err != nil {
        return err
    }
    return nil
}
for _, path := range flag.Args() {
    f, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open %s: %w", path, err)
    }
    if err := process(f); err != nil {
        f.Close()
        return fmt.Errorf("process %s: %w", path, err)
    }
    f.Close()
}
```

Conventional Unix tools accept paths as positional args and fall back
to stdin when none are given.

## Signal handling

```go
ctx, cancel := signal.NotifyContext(context.Background(),
    os.Interrupt, syscall.SIGTERM)
defer cancel()

if err := run(ctx); err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}
```

`signal.NotifyContext` (Go 1.16+) gives you a context that cancels on
the listed signals — ideal for "stop this long-running operation when
the user hits Ctrl-C."

## Configuration sources

Same precedence as services: flag → env → default. Don't pull in a
config-file framework for a CLI; if you need one, document the schema
and keep it minimal.

```go
addr := flag.String("addr", "", "server address")
flag.Parse()

if *addr == "" {
    *addr = os.Getenv("MYCLI_ADDR")
}
if *addr == "" {
    *addr = "localhost:8080"
}
```

## When third-party CLI libraries make sense

Reach for cobra or urfave-cli when:

- You have many subcommands (5+) with their own flags and help text.
- You need shell-completion generation.
- You need man-page generation.
- You're building a tool family with consistent UX (e.g. `kubectl`-style).

For everything smaller, the stdlib `flag` keeps dependencies tiny and
the binary slim.

## When to load a sibling skill

| Task | Skill |
|---|---|
| Reading SQL data inside the CLI | go-sql |
| Structured slog output (or `--json` flag) | go-logging |
| Error wrapping and exit-code mapping | go-errors |
| Table-driven tests for subcommand parsing | go-testing |
| General Go idioms and naming | go-style |
