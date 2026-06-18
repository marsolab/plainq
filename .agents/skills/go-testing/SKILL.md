---
name: go-testing
description: >-
  Idiomatic Go testing with the stdlib `testing` package and the
  go-testdeep assertion library. ALWAYS use this skill when writing or
  reviewing Go tests — table-driven tests with `map[string]testCase`,
  `t.Run` subtests, `t.Helper()` for assertion helpers, `t.Cleanup`,
  `t.Parallel`, integration test gating with environment variables,
  benchmarks (`testing.B`), fuzz tests, go-testdeep operators
  (`td.Cmp`, `td.CmpError`, `td.CmpNoError`, `td.Struct`, `td.Smuggle`,
  `td.Between`, `td.Re`, `td.Require`), and the third-party-frameworks
  debate (go-testdeep when deps are allowed, stdlib-only for
  dependency-free projects, never testify). Pair with go-sql for
  testing DB code with sqlc's `Querier` interface, go-http for `httptest`
  patterns, and go-concurrency for race-detector usage.
version: 1.0.0
tags:
  - go
  - golang
  - testing
  - table-driven-tests
  - benchmarks
---

# Go Testing

Pick the assertion stack by what your project allows:

- **Dependency-free project** — stdlib `testing` only. No third-party
  assertions.
- **Project that allows deps** — use
  [`go-testdeep`](https://github.com/maxatome/go-testdeep). Composable
  operators (`td.Cmp`, `td.Struct`, `td.Smuggle`, `td.Between`, …)
  produce precise diffs.
- **Never use testify.** Vague messages, the `assert`/`require` split,
  and `interface{}` comparisons are worse than either alternative.

References: `references/testing.md` for the carved style guide,
`references/perf-and-parallel.md` for parallel tests, benchmarks, and
the race detector.

## Table-driven with named cases

`map[string]testCase` makes the case name the subtest name
automatically:

```go
import (
    "testing"

    "github.com/maxatome/go-testdeep/td"
)

func TestProcess(t *testing.T) {
    type testCase struct {
        input   string
        want    string
        wantErr bool
    }

    tests := map[string]testCase{
        "valid input": {
            input: "hello",
            want:  "HELLO",
        },
        "empty input returns error": {
            input:   "",
            wantErr: true,
        },
    }

    for name, tc := range tests {
        t.Run(name, func(t *testing.T) {
            got, err := Process(tc.input)
            if tc.wantErr {
                td.CmpError(t, err)
                return
            }
            td.CmpNoError(t, err)
            td.Cmp(t, got, tc.want)
        })
    }
}
```

On a dependency-free project, swap the `td.*` calls for plain
`if got != tc.want { t.Errorf(...) }` checks — the table shape stays
the same.

## Helpers must call t.Helper()

```go
func mustOpen(t *testing.T, path string) *os.File {
    t.Helper()
    f, err := os.Open(path)
    td.Require(t).CmpNoError(err)
    t.Cleanup(func() { f.Close() })
    return f
}
```

`td.Require(t)` returns a `*td.T` whose failing assertions call
`t.Fatal`; `td.Cmp(t, ...)` is the `t.Error` equivalent. `t.Cleanup`
runs in LIFO order at the end of the test and replaces `defer` in
setup helpers.

## Failure messages

testdeep generates field-level diffs automatically — write the
comparison and let the library produce the message. Compose operators
for richer assertions:

```go
td.Cmp(t, user, td.Struct(User{}, td.StructFields{
    "ID":    int64(1),
    "Email": td.Re(`^.+@.+\..+$`),
    "Tags":  td.Bag("go", "testing"),  // unordered set match
}))
```

On stdlib-only projects, include inputs, expected, and actual yourself
— `got` first, `want` second:

```go
if got != want {
    t.Errorf("Square(%d) = %d, want %d", input, got, want)
}
```

Never write `t.Error("test failed")`. See `references/testing.md` for
the full discussion.

## t.Fatal vs t.Error (and td.Require vs td.Cmp)

- `t.Fatal` / `td.Require(t).Cmp(...)` — stop this test immediately.
  Use when later assertions can't run (setup failure, nil that would
  be dereferenced).
- `t.Error` / `td.Cmp(t, ...)` — record failure, keep running so
  remaining assertions still produce useful information.

## Integration tests: env vars, not build tags

```go
func TestDatabaseIntegration(t *testing.T) {
    dsn := os.Getenv("TEST_DATABASE_URL")
    if dsn == "" {
        t.Skip("set TEST_DATABASE_URL to run this test")
    }
    db, err := sql.Open("postgres", dsn)
    // ...
}
```

Build tags hide tests; the `t.Skip` line surfaces in normal `go test`
output and tells you exactly what to set.

## Parallel, benchmarks, race detector

The headlines:

- Mark independent tests with `t.Parallel()`. Re-bind the loop
  variables before passing to a subtest closure.
- Benchmarks live in `func BenchmarkXxx(b *testing.B)` and run with
  `go test -bench=. -benchmem`. Use `b.ResetTimer()` after setup.
- Run CI with `go test -race ./...`. The race detector finds the
  bugs you can't reproduce.

Full discussion: `references/perf-and-parallel.md`.

## When to load a sibling skill

| Task | Skill |
|---|---|
| Mocking a sqlc-generated `Querier` | go-sql |
| Testing HTTP handlers with `httptest` | go-http |
| Testing concurrent code, race detector | go-concurrency |
| Asserting on wrapped errors with `errors.Is`/`errors.As` | go-errors |
| General Go idioms and naming | go-style |
