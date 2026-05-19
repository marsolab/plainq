---
name: go-dev
description: >-
  Umbrella skill for Go development. ALWAYS use this skill when the
  user's task involves Go or Golang in any way — writing new Go code,
  reviewing existing Go code, building Go services, creating Go CLI
  tools, working with Go tests, setting up Go linting, using sqlc for
  database access, or anything else Go-related. This includes mentions
  of: Go, Golang, .go files, go.mod, go test, golangci-lint, Chi
  router, sqlc, goose migrations, generics, goroutines, channels,
  interfaces, error handling, concurrency, table-driven tests, slog,
  iterators, or any Go package/tool. This skill is a router — it loads
  fast and points to the focused sibling skill(s) that own the deep
  reference material for the task at hand.
version: 2.0.0
tags:
  - go
  - golang
  - umbrella
---

# Go Dev (umbrella)

This skill exists to make sure Claude has Go context loaded as soon as
the conversation mentions Go. It is intentionally short. Load the
specific sibling skill(s) below for the task at hand — each owns a
focused SKILL.md and reference material carved from a comprehensive
style guide.

## Pick the right sibling

| Task | Skill |
|---|---|
| Naming, package layout, generics, interfaces, iterators, common pitfalls | go-style |
| Wrapping errors, `errors.Is` / `errors.As`, `errors.Join`, "log or return" | go-errors |
| Goroutines, channels, context, `sync.WaitGroup`, `errgroup` | go-concurrency |
| `log/slog`, structured logging, observability | go-logging |
| Table-driven tests, `t.Helper`, `httptest`, integration gating | go-testing |
| HTTP services, Chi router, graceful shutdown | go-http |
| CLI tools, `flag.NewFlagSet`, subcommands, exit codes | go-cli |
| sqlc, goose migrations, transactions | go-sql |
| `golangci-lint`, `.golangci.yml`, formatting | go-lint |

If the task spans several of these, load the two or three that matter
most. Don't load everything by reflex — each sibling is self-contained.

## Quick reference for AI coding agents

When you do generate Go without loading a sibling, fall back to these
rules:

### NAMING

- Packages: lowercase, singular, no underscores
- Variables: short names for short scope, longer for wider scope
- Exported: PascalCase; unexported: camelCase
- Acronyms: consistent case (URL not Url, ID not Id)
- Getters: no Get prefix; setters: Set prefix

### STRUCTURE

- Error check immediately after call
- Return early with guard clauses
- Keep success path left-aligned
- Group imports: stdlib, external, internal

### ERRORS

- Always check returned errors
- Wrap with context: `fmt.Errorf("operation: %w", err)`
- Lowercase, no punctuation in messages
- Handle exactly once: log OR return, not both
- Never panic in libraries

### CONCURRENCY

- Context as first parameter
- Know when every goroutine stops
- Use sync.WaitGroup for coordination
- Don't force concurrency on callers

### INTERFACES

- Define at consumption site
- Keep small (1-3 methods)
- Accept interfaces, return concrete types

### TESTING

- Table-driven with named fields
- Use t.Run for subtests
- Call t.Helper() in helpers
- Message format: `got X, want Y`

### MODERN GO (1.18+)

- Generics: use for data structures and utilities, not behavior abstraction
- `log/slog`: pass as dependency, use `InfoContext`/`ErrorContext`, JSON in prod
- `errors.Join`: combine multiple errors, supports `errors.Is`/`errors.As`
- Iterators (`iter.Seq`/`iter.Seq2`): lazy evaluation, composable pipelines
- Range-over-int: `for i := range n` (Go 1.22+)
- `slices`/`maps`/`cmp` packages: prefer over hand-written utilities

### CRITICAL PITFALLS TO AVOID

- Loop variable capture: pass to closure or shadow
- Nil interface check: interface with nil value ≠ nil
- Variable shadowing: use = not := when reassigning
- Defer in loops: wrap in closure for per-iteration cleanup
- Map writes to nil: always initialize with make()

## MCP

Use Context7 MCP to fetch up-to-date library docs.
