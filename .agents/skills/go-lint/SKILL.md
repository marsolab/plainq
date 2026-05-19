---
name: go-lint
description: >-
  Linting and formatting Go code with `gofmt`, `goimports`,
  `golangci-lint`, and a curated `.golangci.yml`. ALWAYS use this skill
  when setting up or troubleshooting Go linting — installing
  golangci-lint, dropping the bundled `.golangci.yml` into a project,
  configuring pre-commit hooks, picking which linters to enable
  (errcheck, govet, staticcheck, unused, misspell, prealloc, gosec,
  revive, gocritic), suppressing findings with `//nolint` comments,
  reading lint output, or wiring lint into CI. Pair with go-style for
  the underlying idioms most lint rules enforce.
version: 1.0.0
tags:
  - go
  - golang
  - linting
  - golangci-lint
  - tooling
  - formatting
---

# Go Lint

Run `gofmt`, `goimports`, and `golangci-lint` on every commit. The
formatters fix style automatically; the linter catches the bugs the
compiler doesn't.

For the comprehensive reference, see `references/linting.md`. The
bundled config lives at `assets/golangci.yml` and the setup script at
`scripts/setup_golangci_lint.sh`.

## Setup script

Drop the bundled config into a project and (optionally) install a
pre-commit hook:

```bash
scripts/setup_golangci_lint.sh /path/to/project
```

The script copies `.golangci.yml` and prompts before installing the
hook so you can opt out.

## Day-to-day commands

```bash
# Run every enabled linter
golangci-lint run ./...

# Auto-fix what's fixable
golangci-lint run --fix ./...

# Lint a subset
golangci-lint run ./internal/...

# Show which linters are active
golangci-lint linters

# Format Go code (always before commit)
gofmt -w .
goimports -w .          # sorts and removes unused imports
```

## Required tools

- **gofmt** / **goimports**: non-negotiable. `goimports` is a strict
  superset of `gofmt`.
- **go vet**: built into the toolchain; catches misuse of stdlib types.
- **golangci-lint**: the meta-linter; runs many analyzers in parallel
  with shared parsing.

## Linters worth enabling

The bundled `.golangci.yml` turns these on:

| Linter | What it catches |
|---|---|
| `errcheck` | Unchecked errors |
| `govet` | Stdlib misuse, shadowing, struct tag typos |
| `staticcheck` | The biggest set of static-analysis rules |
| `unused` | Dead code |
| `misspell` | Typos in comments and strings |
| `prealloc` | Slices that should be preallocated |
| `gosec` | Common security issues |
| `revive` | Successor to golint; readable rules |
| `gocritic` | Many opinionated readability checks |
| `bodyclose` | Unclosed `http.Response.Body` |
| `nilerr` | Returning a non-nil err as nil |
| `errorlint` | `%w` and wrapping mistakes |

## Suppressing findings

Prefer fixing over suppressing. When you must suppress, do so narrowly
and explain why:

```go
//nolint:gosec // not user input — read from a generated config file
buf, err := os.ReadFile(path)
```

`//nolint` without a linter name disables every linter on that line —
avoid it. Always name the linter and add a comment.

## Pre-commit integration

The setup script writes a Git hook that runs `golangci-lint run` on
staged Go files. To skip in an emergency, use a regular `git commit`
after fixing — never `--no-verify`. If the hook is wrong, fix the rule.

## CI integration

```yaml
# .github/workflows/ci.yml fragment
- uses: golangci/golangci-lint-action@v6
  with:
    version: v1.61.0
    args: --timeout=5m
```

Pin the version. Floating `latest` will surprise you with new findings
when the linter releases.

## When to load a sibling skill

| Task | Skill |
|---|---|
| Why a rule fires (the underlying idiom) | go-style |
| Catching shadowed `ctx` from `:=` | go-style (pitfalls) |
| Tests that should run alongside lint | go-testing |
| HTTP handlers that frequently trigger `bodyclose` | go-http |
