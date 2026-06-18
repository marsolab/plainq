---
name: go-style
description: >-
  Idiomatic Go style: naming, package and file organization, interfaces,
  documentation, generics, iterators, range-over-int, performance, dependency
  management, and common pitfalls. ALWAYS use this skill when writing or
  reviewing Go code for general style and idioms — questions about naming
  conventions, where to put a type, when to use generics vs `any`, how to
  size interfaces, godoc comments, the `internal/` package, struct literal
  initialization, slice/map gotchas, loop-variable capture, defer timing, or
  "is this idiomatic Go?". Pair with go-errors, go-concurrency, go-testing,
  go-logging, go-http, go-cli, go-sql, or go-lint when those concerns
  dominate the task.
version: 1.0.0
tags:
  - go
  - golang
  - style
  - idioms
  - generics
  - interfaces
  - pitfalls
---

# Go Style

Write Go code that is readable, maintainable, and predictable. Favour
clarity over cleverness; the language is small on purpose.

For the comprehensive idiomatic reference, see `references/idioms.md`. For
the catalogue of language gotchas, see `references/pitfalls.md`.

## Decision shortcuts

### Naming

- Packages: lowercase, singular, no underscores, no `util` / `common` /
  `helpers`. Name describes purpose.
- Variable length tracks scope: `i` in a tight loop, `customerOrderHistory`
  across a long function.
- Getters omit `Get`; setters use `Set`. `obj.Owner()`, `obj.SetOwner(u)`.
- Acronyms keep consistent case: `URL`, `ID`, `HTTP` — never `Url`, `Id`,
  `Http`.
- Constants are `mixedCaps`, not `SCREAMING_CASE`.
- Interfaces with one method end in `-er`: `Reader`, `Closer`, `Stringer`.

### Use generics when

- Building a data structure that works across types (cache, tree, pool).
- Writing slice/map/channel utilities (filter, map, reduce).
- Type constraints remove runtime assertions.

Skip generics when the body would need type assertions anyway, when a
concrete type works, or when the result is harder to read. Prefer
`slices`, `maps`, and `cmp` (Go 1.21+) over hand-rolled utilities.

### Interfaces

- Define interfaces at the **consumption site**, not next to the
  implementation. The consumer declares only the methods it needs.
- Aim for 1 method, accept 2–3 if cohesive, split at 4+. Larger interfaces
  are tolerable inside a SaaS product; keep them tiny in libraries.
- **Accept interfaces, return concrete types.**
- `any` says nothing. Use a real interface or document the expected type.

### Code organization

- Start as a few files in `package main`. Add structure only when growth
  demands it.
- `cmd/` for binaries, `internal/` for code only this module may import,
  `pkg/` (or top-level packages) for the public API.
- One package, one purpose. Orient packages around a domain
  (`package user`), not an implementation accident (`package models`).
- Imports group as: stdlib → external → internal, blank-line separated.

### Documentation

- Every exported symbol gets a comment that starts with the symbol's name
  and forms a complete sentence ending with a period.
- Document **why**, not what the code already says.
- Package docs go above the `package` clause in any one file (often
  `doc.go`).

## Modern Go quick reference

```go
// Range over int (Go 1.22+)
for i := range 10 { ... }

// Generic data structure (Go 1.18+)
type Cache[K comparable, V any] struct { ... }

// Iterator (Go 1.23+)
func Positive(nums []int) iter.Seq[int] {
    return func(yield func(int) bool) {
        for _, n := range nums {
            if n > 0 && !yield(n) {
                return
            }
        }
    }
}

// Prefer stdlib utilities
slices.Sort(items)
slices.SortFunc(items, func(a, b Item) int {
    return cmp.Compare(a.Priority, b.Priority)
})
```

## Configuration patterns

- Only `main()` defines flags. Libraries take their config through a
  constructor, never `flag.String` at package scope.
- Precedence: flags → environment → config file → default.
- Initialize structs with literals in one shot — never leave a struct
  partially populated across multiple statements.

```go
server := &http.Server{
    Addr:         addr,
    ReadTimeout:  30 * time.Second,
    WriteTimeout: 30 * time.Second,
    Handler:      mux,
}
```

## Common pitfalls (read `references/pitfalls.md` for the full set)

- **Loop variable capture in closures** — pass as parameter, or shadow
  with `item := item` before the closure.
- **Nil interface vs nil value** — an interface holding a typed nil is
  not nil. Return explicit `nil` when the underlying value is nil.
- **Variable shadowing with `:=`** inside `if` blocks silently drops the
  inner result. Use `=` to reassign.
- **Defer in loops** — defers fire at function exit, not loop iteration.
  Wrap the body in a closure when you need per-iteration cleanup.
- **Nil map writes panic.** Always `make(map[K]V)` before writing.
- **Range copies values.** Mutate via index: `for i := range items { items[i].x++ }`.
- **Slice reslicing shares the backing array.** Use the three-index form
  `s[:n:n]` to force a fresh allocation when needed.

## When to load a sibling skill

| Task | Skill |
|---|---|
| Wrapping or matching errors, `errors.Join` | go-errors |
| Goroutines, channels, context, errgroup | go-concurrency |
| `log/slog`, structured logging, observability | go-logging |
| Table-driven tests, `t.Helper`, integration gating | go-testing |
| HTTP services, Chi router, graceful shutdown | go-http |
| CLI tools, subcommands, `flag.NewFlagSet` | go-cli |
| sqlc, goose migrations, transactions | go-sql |
| `golangci-lint`, `.golangci.yml`, formatting | go-lint |

## Performance — measure first

Don't optimize without benchmarks. Once you have data:

- Preallocate when size is known: `make([]T, 0, n)`, `make(map[K]V, n)`.
- Use `strings.Builder` for iterative concatenation.
- On hot paths, `strconv.Itoa` beats `fmt.Sprint`.
- Convert string→[]byte once outside the loop.

```go
func BenchmarkProcess(b *testing.B) {
    data := generateTestData()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        Process(data)
    }
}
```

## Dependencies

- Libraries never vendor. Vendoring is for binaries.
- `internal/` is enforced by the compiler — only packages rooted at the
  parent directory may import it. Use it to keep an API surface small.
