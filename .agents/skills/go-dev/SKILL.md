---
name: go-dev
description: >-
  Writing, reviewing, refactoring, debugging, or designing Go code —
  backends, microservices, APIs, CLI tools, daemons, workers, data
  pipelines, libraries. Umbrella router that delegates to focused
  sibling Go skills.
when_to_use: >-
  TRIGGER WHEN the user mentions Go, Golang, .go files, go.mod,
  go.sum, go test, go build, go run, go vet, gofmt, goimports,
  golangci-lint, Chi router, sqlc, goose, slog, errgroup, goroutines,
  channels, context.Context, generics, iterators, table-driven tests,
  or any Go stdlib package (net/http, log/slog, encoding/json,
  database/sql, sync, errors, etc.).
  ALSO TRIGGER on indirect phrasings inside a Go repo: "build me a
  backend", "write a microservice", "create a CLI tool", "add an HTTP
  handler", "wire up a database", "add a migration", "write a worker",
  or any task in a directory containing go.mod.
  ALSO TRIGGER when reviewing a Go PR or diff.
  SKIP only when the task is purely about another language with no Go
  component.
  After loading, immediately invoke the sibling skill(s) named in the
  routing directives below for the task at hand.
version: 2.1.0
tags:
  - go
  - golang
  - umbrella
---

# Go Dev (umbrella)

This skill exists to make sure Claude has Go context loaded as soon as
the conversation involves Go. It is intentionally short. Its job is to
route: pick the focused sibling skill(s) that own the deep reference
material for the task at hand.

## Routing directives — invoke a sibling now

For each task signal below, invoke the named sibling skill via the
Skill tool before writing code. Do not answer Go questions from this
umbrella's fallback cheat sheet if a sibling owns the topic.

- Naming, packages, generics, interfaces, iterators → invoke `go-style:go-style`
- Wrapping errors, `errors.Is` / `errors.As` / `errors.Join`, log-or-return → invoke `go-errors:go-errors`
- Goroutines, channels, `context`, `errgroup`, `sync` → invoke `go-concurrency:go-concurrency`
- `log/slog`, structured logging, observability → invoke `go-logging:go-logging`
- Tests, `t.Helper`, `httptest`, table-driven, fixtures → invoke `go-testing:go-testing`
- HTTP services, Chi router, middleware, graceful shutdown → invoke `go-http:go-http`
- CLI tools, `flag.NewFlagSet`, subcommands, exit codes → invoke `go-cli:go-cli`
- sqlc, goose migrations, transactions, `database/sql` → invoke `go-sql:go-sql`
- `golangci-lint`, `.golangci.yml`, `gofmt`, `goimports` → invoke `go-lint:go-lint`

If the task spans multiple rows, invoke 2–3 siblings in parallel. If
none clearly applies, fall back to the cheat sheet below — but prefer
a sibling.

## Fallback cheat sheet (only if no sibling applies)

### NAMING

- Packages: lowercase, singular, no underscores
- Variables: short names for short scope, longer for wider scope
- Exported: PascalCase; unexported: camelCase
- Acronyms: consistent case (URL not Url, ID not Id)
- Getters: no Get prefix; setters: Set prefix

### STRUCTURE

- Check returned errors immediately after the call
- Return early with guard clauses; keep the success path left-aligned
- Group imports: stdlib, external, internal
- Define interfaces at the consumption site; keep them 1–3 methods
- Accept interfaces, return concrete types

### MODERN GO (1.18+)

- Generics: use for data structures and utilities, not behavior abstraction
- `log/slog`: pass as a dependency; `InfoContext` / `ErrorContext`; JSON in prod
- `errors.Join`: combine multiple errors; supports `errors.Is` / `errors.As`
- Iterators (`iter.Seq` / `iter.Seq2`): lazy, composable pipelines
- Range-over-int (`for i := range n`) since Go 1.22
- Prefer `slices` / `maps` / `cmp` over hand-rolled helpers

### CRITICAL PITFALLS

- Loop variable capture in closures (pre-1.22): pass to closure or shadow
- Nil interface check: interface with a nil concrete value is NOT nil
- Variable shadowing inside if/for: use `=` not `:=` when reassigning
- `defer` in a loop: wrap the body in a closure for per-iteration cleanup
- Writes to a nil map: always initialize with `make()`

## MCP

Use Context7 MCP to fetch up-to-date library docs when working with
third-party Go packages.
