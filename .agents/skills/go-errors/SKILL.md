---
name: go-errors
description: >-
  Idiomatic Go error handling. ALWAYS use this skill when writing or
  reviewing Go code that raises, returns, wraps, matches, or aggregates
  errors — questions about `fmt.Errorf` with `%w` vs `%v`, `errors.Is` and
  `errors.As`, sentinel errors, typed error structs, `errors.Join` for
  combining failures, the "handle exactly once" rule, panic vs error,
  guard clauses and early return, error message formatting, or any
  `if err != nil` pattern. Use alongside go-style for general idioms.
version: 1.0.0
tags:
  - go
  - golang
  - errors
  - error-handling
  - errors-join
---

# Go Errors

Errors are values. Treat them with the same care as any other return.

For the comprehensive reference, see `references/error-handling.md`.

## The four rules

1. **Check every returned error.** No exceptions for "this can't fail."
1. **Handle each error exactly once.** Either log it OR return it; never
   both. Log-and-return causes duplicate log lines further up the stack.
1. **Wrap with context as the error travels up.**
1. **Never panic in library code.** Return an error and let the caller
   decide.

## Decision tree

```
Got an error from a call.
├── Can I handle it completely here?            → Log (or recover) and continue.
├── Does the caller need programmatic match?    → fmt.Errorf("op: %w", err) — wraps.
├── Should I hide implementation details?       → fmt.Errorf("op: %v", err) — flattens.
└── Is this a library?                          → Return; never log.
```

## Wrapping

```go
// Add context as the error climbs the stack
if err != nil {
    return fmt.Errorf("connect to database: %w", err)
}
```

- Lowercase, no trailing punctuation, no `failed to` prefix. The strings
  get concatenated: `processing request: connect to database: connection refused`
  reads cleanly.
- `%w` wraps so `errors.Is` / `errors.As` work upstream.
- `%v` flattens — use when you don't want callers depending on the inner
  error's type.

## Sentinels and typed errors

```go
// Sentinel: comparable with errors.Is
var ErrNotFound = errors.New("user not found")

// Typed error: comparable with errors.As, carries data
type ValidationError struct {
    Field string
    Issue string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation: %s: %s", e.Field, e.Issue)
}

// Caller side
var verr *ValidationError
switch {
case errors.Is(err, ErrNotFound):
    // 404
case errors.As(err, &verr):
    // 400 with verr.Field
}
```

## errors.Join — combining failures

Use when several independent operations may each fail and you want to
report all of them:

```go
func ValidateConfig(cfg Config) error {
    var errs []error
    if cfg.Host == "" {
        errs = append(errs, errors.New("host is required"))
    }
    if cfg.Port < 1 || cfg.Port > 65535 {
        errs = append(errs, fmt.Errorf("invalid port: %d", cfg.Port))
    }
    return errors.Join(errs...) // nil if errs is empty
}
```

`errors.Join` returns `nil` for an empty slice and supports `errors.Is` /
`errors.As` against any constituent. Also handy for cleanup paths:

```go
func cleanup(db *sql.DB, file *os.File) error {
    return errors.Join(db.Close(), file.Close())
}
```

## Guard clauses keep the success path left

```go
// GOOD
func ProcessFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open %s: %w", path, err)
    }
    defer f.Close()

    data, err := io.ReadAll(f)
    if err != nil {
        return fmt.Errorf("read %s: %w", path, err)
    }
    return process(data)
}
```

Avoid `else` branches after a `return`. Avoid nested error checks — flat
is readable.

## Don't panic

Panics crash the program and cascade through any process running the
library. Return an error every time.

Acceptable panic uses:

- API misuse inside internal code (e.g. `reflect`-style developer error).
- `main()` initialization failures — prefer `log.Fatal` over `panic` so
  deferred functions don't deadlock.
- Marking unreachable code paths.

## When to load a sibling skill

| Task | Skill |
|---|---|
| `errgroup` patterns, goroutine error propagation | go-concurrency |
| Logging an error you've decided to handle | go-logging |
| Returning HTTP status codes from typed errors | go-http |
| Wrapping `sql.ErrNoRows` etc. at the data layer | go-sql |
| General Go idioms and naming | go-style |
