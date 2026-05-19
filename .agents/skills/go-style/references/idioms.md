# Idiomatic Go reference

Carved from the comprehensive Go style guide. Covers foundational
principles, naming, code organization, interface design, documentation,
performance, configuration, dependency management, points of disagreement,
and modern Go patterns (generics, iterators, range-over-int).

For error handling see go-errors. For concurrency see go-concurrency. For
testing see go-testing. For logging see go-logging. For pitfalls see
`pitfalls.md` in this directory.

---

## Foundational principles that shape every guideline

Go's design philosophy flows from a single insight: **"Software engineering is
what happens to programming when you add time and other programmers."** Code
will be read far more than written, maintained by people who didn't write it,
and debugged under pressure at 3 AM. Every guideline here serves readability and
maintainability.

The Zen of Go, articulated by Dave Cheney, captures ten engineering values that
should guide decisions:

1. **Each package fulfills a single purpose**—name it with an elevator pitch
  using one word
1. **Handle errors explicitly**—the verbosity of `if err != nil` outweighs the
  value of deliberately handling each failure
1. **Return early rather than nesting deeply**—keep the success path to the left
1. **Leave concurrency to the caller**—don't force async on consumers
1. **Before launching a goroutine, know when it will stop**—goroutines own
  resources
1. **Avoid package-level state**—reduce coupling and spooky action at a distance
1. **Simplicity matters**—simple doesn't mean crude; it means readable and
  maintainable
1. **Write tests to lock in API behavior**—tests are contracts written in code
1. **Prove slowness with benchmarks before optimizing**—crimes against
  maintainability are committed in the name of performance
1. **Moderation is a virtue**—use goroutines, channels, interfaces in moderation

---

## Naming conventions establish code clarity

**Poor naming is symptomatic of poor design.** Good names are concise,
descriptive, and predictable—readers should know how to use something without
consulting documentation.

### Package names should be lowercase, singular, and unique

Packages must be lowercase single words without underscores or mixedCaps. The
package name becomes a prefix for all exported identifiers, so avoid redundancy:

```go
// BAD: redundant package prefix
package chubby
type ChubbyFile struct{}  // caller writes chubby.ChubbyFile

// GOOD: package name provides context
package chubby
type File struct{}  // caller writes chubby.File
```

Avoid meaningless names like `util`, `common`, `misc`, `api`, `types`, or
`helpers`. If two packages seem to need the same name, either they overlap in
responsibility or the name is too generic. Production codebases enforce unique
package names across the entire project to prevent `goimports`
confusion—CockroachDB uses parent-prefixed names like `server/serverpb`,
`kv/kvserver`, and `util/contextutil`.

### Variable length should correlate with scope distance

The distance between declaration and final use determines appropriate name
length. Short names work when context is clear and scope is small:

```go
// Short scope: short name
for i, v := range items {
    process(v)
}

// Longer scope: longer name
customerOrderHistory := fetchOrdersForCustomer(customerID)
// ... many lines later ...
processOrderHistory(customerOrderHistory)
```

**Use `var` for zero-value declarations, `:=` for initializations.** The `var`
keyword signals deliberate use of the zero value:

```go
var players int              // deliberately zero
things := make([]Thing, 0)   // initialized to specific state
```

### Exported names follow strict conventions

Getters omit `Get` prefix; setters use `Set` prefix:

```go
// GOOD
owner := obj.Owner()
obj.SetOwner(user)

// BAD
owner := obj.GetOwner()
```

Acronyms maintain consistent casing—`URL` appears as `URL` or `url`, never
`Url`. Write `ServeHTTP` not `ServeHttp`, `xmlHTTPRequest` not `XmlHttpRequest`,
and `appID` not `appId`.

### Interfaces name the behavior with an -er suffix

One-method interfaces derive names from the method plus `-er`: `Reader`,
`Writer`, `Formatter`, `CloseNotifier`. When implementing well-known interfaces,
match the established signature exactly—name your string converter `String()`
not `ToString()`.

### Constants avoid SCREAMING_CASE

Go uses mixedCaps for constants, matching other identifiers:

```go
// GOOD
const maxConnections = 100
const DefaultTimeout = 30 * time.Second

// BAD (not idiomatic Go)
const MAX_CONNECTIONS = 100
```

Use `iota` for enumerated constants, typically skipping zero if it could mask
missing initialization:

```go
type Status int
const (
    _             Status = iota  // skip zero
    StatusPending                // 1
    StatusActive                 // 2
    StatusClosed                 // 3
)
```

---

## Code organization emerges from simplicity

### Start small and add structure only when needed

Peter Bourgon advises: **"Most projects start as a few files in package main at
the root, staying that way until they become a couple thousand lines."** Go's
lightweight feel should be preserved. Rigid a priori project structure typically
harms more than helps—requirements diverge, grow, and mutate.

When structure becomes necessary, the `cmd/pkg` layout works well for
applications with multiple binaries:

```text
github.com/yourorg/project/
    cmd/
        server/
            main.go
        cli/
            main.go
    pkg/
        storage/
            storage.go
            storage_test.go
        api/
            api.go
```

### Packages should fulfill a single purpose

Create packages when you have self-contained functionality, need protobuf
definitions, find a package grown too large (slow tests, insufficient
encapsulation), or have reusable code another team needs. Orient packages around
**business domains rather than implementation accidents**—prefer `package user`
over `package models`.

Google's guidance on file organization: **"There is no 'one type, one file'
convention."** Files should be focused enough that maintainers know where to
find things, and small enough to navigate easily. The standard library's
`net/http` package demonstrates this: `client.go`, `server.go`, `cookie.go`,
`transport.go`.

### Import grouping follows a standard order

Separate imports into groups: standard library, external dependencies, internal
packages:

```go
import (
    "context"
    "fmt"
    "time"

    "github.com/pkg/errors"
    "go.uber.org/zap"

    "github.com/yourorg/project/pkg/storage"
)
```

Always use fully-qualified import paths, never relative imports. GitLab enforces
this with `goimports -local gitlab.com/gitlab-org`.

---

## Interface design emphasizes small, consumer-defined contracts

### Define interfaces at the consumption site, not the implementation

Go's structural typing means interfaces should be defined where they're used,
not where implementations live:

```go
// GOOD: interface defined by consumer
package storage

type Reader interface {
    Read(ctx context.Context, key string) ([]byte, error)
}

func NewCache(r Reader) *Cache {
    return &Cache{backend: r}
}

// BAD: interface defined by implementor
package database

type Database interface {  // don't do this
    Read(ctx context.Context, key string) ([]byte, error)
    Write(ctx context.Context, key string, value []byte) error
    Delete(ctx context.Context, key string) error
}

func New() Database { return &db{} }
```

The consuming package declares only the methods it actually needs, enabling easy
mocking and loose coupling.

### Prefer one-method interfaces

Small interfaces compose better and describe precise behavioral contracts. The
standard library exemplifies this: `io.Reader`, `io.Writer`, `io.Closer`,
`fmt.Stringer`. Thanos explicitly recommends **1-3 methods maximum**:

```go
// GOOD: narrow interfaces
type Compactor interface {
    Compact(ctx context.Context) error
}

type MetaFetcher interface {
    Fetch(ctx context.Context) ([]Meta, error)
}

// BAD: kitchen-sink interface
type Service interface {
    Compact(ctx context.Context) error
    Fetch(ctx context.Context) ([]Meta, error)
    Store(ctx context.Context, data []byte) error
    Delete(ctx context.Context, id string) error
    List(ctx context.Context) ([]string, error)
    // ... more methods
}
```

### Accept interfaces, return concrete types

Functions should accept interface parameters for flexibility but return concrete
types so implementations can add methods without breaking callers:

```go
// GOOD
func NewServer(logger Logger) *Server {
    return &Server{logger: logger}
}

// The hash library exception: when multiple implementations exist
// for a common interface, returning the interface makes sense
func NewSHA256() hash.Hash { return &sha256{} }
```

### The empty interface says nothing

`interface{}` (or `any`) communicates zero information about expected behavior.
Use specific interfaces when possible, and when using empty interface, document
what types are actually expected.

---

## Documentation follows godoc conventions

### Comment every exported symbol with the symbol's name

Comments become godoc output. Start with the identifier name:

```go
// Server handles incoming HTTP requests for the API.
// It maintains connection pools and manages request routing.
type Server struct {
    // ...
}

// ListenAndServe starts the server on the given address.
// It blocks until the server is shut down or an error occurs.
func (s *Server) ListenAndServe(addr string) error {
    // ...
}
```

### Comments must be complete sentences

Start with uppercase, end with a period. This is enforced by linters in Thanos
and other production codebases.

### Document the why, not the obvious what

Good comments explain **why** something is done, not **what** the code literally
does:

```go
// BAD: restates the code
// Increment counter by one.
counter++

// GOOD: explains rationale
// Track total requests for rate limiting decisions.
// This counter resets hourly via the cleanup goroutine.
counter++
```

### Package documentation goes in doc.go or any file

Place a package comment immediately before the `package` declaration:

```go
// Package storage provides a unified interface for persisting
// application data across multiple backend implementations.
//
// The primary types are Store for read-write access and
// ReadOnlyStore for cached, read-only views.
package storage
```

For commands, use `// Command myapp ...` or simply `// Myapp ...`.

---

## Performance optimization requires measurement first

### Prove slowness with benchmarks before optimizing

Dave Cheney warns: **"So many crimes against maintainability are committed in
the name of performance."** Optimization couples code tightly, tears down
abstractions, and exposes internals. Only pay that cost when benchmarks prove
necessity.

```go
func BenchmarkProcess(b *testing.B) {
    data := generateTestData()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        Process(data)
    }
}
```

### Preallocate slices and maps with known sizes

When size is known or estimable, preallocate:

```go
// GOOD: preallocate
results := make([]Result, 0, len(inputs))
for _, input := range inputs {
    results = append(results, process(input))
}

// Map with size hint
cache := make(map[string]Value, expectedSize)
```

But don't over-allocate—wasted memory harms performance too.

### Use strings.Builder for iterative string construction

```go
// GOOD: efficient for multiple appends
var b strings.Builder
for _, part := range parts {
    b.WriteString(part)
}
result := b.String()

// GOOD: simple concatenation
key := "prefix:" + id

// GOOD: formatting
msg := fmt.Sprintf("%s [%s:%d]", name, host, port)
```

### Hot-path optimizations (CockroachDB guidance)

On critical paths, `strconv` outperforms `fmt`:

```go
// Hot path: 64 ns/op, 1 alloc
s := strconv.Itoa(n)

// Cold path okay: 143 ns/op, 2 allocs
s := fmt.Sprint(n)
```

Convert strings to bytes once when writing repeatedly:

```go
// GOOD: convert once
data := []byte("fixed string")
for i := 0; i < n; i++ {
    w.Write(data)
}
```

---

## Configuration follows explicit patterns

### Only main() decides command-line flags

Library code never defines flags directly. Parameters come through constructors:

```go
// main.go
func main() {
    addr := flag.String("addr", ":8080", "listen address")
    timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
    flag.Parse()

    server := service.New(service.Config{
        Addr:    *addr,
        Timeout: *timeout,
    })
}

// service/service.go
type Config struct {
    Addr    string
    Timeout time.Duration
}

func New(cfg Config) *Service {
    // ...
}
```

This makes the configuration surface explicit and self-documenting via `-h`.

### Flags take priority over environment variables

Support multiple configuration sources, but establish clear precedence:

1. Command-line flags (highest priority)
1. Environment variables
1. Configuration files
1. Default values

```go
addr := flag.String("addr", "", "listen address")
flag.Parse()

if *addr == "" {
    *addr = os.Getenv("SERVER_ADDR")
}
if *addr == "" {
    *addr = ":8080"  // default
}
```

### Use struct literal initialization

Avoid multiple assignment statements that can leave objects in invalid states:

```go
// GOOD: single initialization
server := &Server{
    Addr:         addr,
    ReadTimeout:  30 * time.Second,
    WriteTimeout: 30 * time.Second,
    Handler:      mux,
}

// BAD: multiple statements
server := &Server{}
server.Addr = addr
server.ReadTimeout = 30 * time.Second
// Oops, forgot WriteTimeout - partially initialized
```

---

## Dependency management with Go modules

### Libraries must never vendor dependencies

Vendoring is for binaries only. Libraries with vendored dependencies are
impossible to use because consumers face dependency conflicts. From the binary
author's perspective, vendoring ensures reproducible builds.

### Use the internal package for private code

Code in `internal/` is only importable by packages rooted at the parent of
`internal/`. This enforces API boundaries:

```text
project/
    cmd/server/main.go     # can import internal/
    internal/
        auth/auth.go       # private to this module
    pkg/
        api/api.go         # public API
```

---

## Points of disagreement and alternative approaches

### Error wrapping libraries

Sources disagree on error library choice:

- **Standard library**: Google recommends `fmt.Errorf` with `%w`
- **pkg/errors**: Thanos prefers explicit `errors.Wrap`
- **cockroachdb/errors**: CockroachDB uses their own superset with redaction
  support

The consensus: use *some* form of wrapping; the specific library matters less
than consistent application.

### Project structure

- **Peter Bourgon (2016)**: Recommended cmd/pkg structure
- **Peter Bourgon (2018)**: Softened stance—start simple, add structure only
  when needed
- **Google**: No prescribed structure; organize by maintainability

The consensus: avoid premature structure, but cmd/pkg works when complexity
warrants it.

### Test assertions

- **Google**: Forbids assertion libraries; use standard testing package
- **GitLab**: Permits testify for assertions
- **Peter Bourgon**: Testing DSLs increase cognitive burden

The consensus: the standard library suffices; third-party frameworks are
optional convenience.

### Receiver type consistency

- **Google Code Review Comments**: Don't mix receiver types on one type
- **Effective Go**: Choose based on method needs

Practical guidance: if any method needs a pointer receiver (mutation, large
struct, sync primitives), use pointer receivers for all methods on that type.

---

## Modern Go patterns (1.18+)

### Generics: when and how to use type parameters

Go 1.18 introduced type parameters. The key principle: **generics reduce
duplication without sacrificing readability**. If a generic version is harder
to understand than two concrete versions, skip generics.

**When to use generics:**

- Data structures that work across element types (caches, trees, pools)
- Utility functions on slices, maps, or channels (filter, map, reduce)
- When type constraints eliminate runtime type assertions

**When NOT to use generics:**

- The function body would need type assertions anyway
- A concrete type or `any` works fine
- The generic version is harder to read for marginal DRY benefit
- You're abstracting over behavior, not data shape — use interfaces instead

```go
// GOOD: generic data structure
type Cache[K comparable, V any] struct {
    mu    sync.RWMutex
    items map[K]cacheItem[V]
}

type cacheItem[V any] struct {
    value     V
    expiresAt time.Time
}

func NewCache[K comparable, V any]() *Cache[K, V] {
    return &Cache[K, V]{items: make(map[K]cacheItem[V])}
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    item, ok := c.items[key]
    if !ok || time.Now().After(item.expiresAt) {
        var zero V
        return zero, false
    }
    return item.value, true
}
```

```go
// GOOD: constrained utility
type Ordered interface {
    ~int | ~int8 | ~int16 | ~int32 | ~int64 |
    ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
    ~float32 | ~float64 | ~string
}

func Min[T Ordered](a, b T) T {
    if a < b {
        return a
    }
    return b
}
```

```go
// BAD: unnecessary generic — just use the concrete type
func ProcessUser[T User](u T) error { ... }

// BAD: generic with type assertions — defeats the purpose
func Handle[T any](v T) {
    switch v := any(v).(type) { ... }
}
```

**Use `cmp.Ordered` and `slices`/`maps` packages** (Go 1.21+) instead of
writing your own constraints and utilities:

```go
import (
    "cmp"
    "slices"
)

slices.Sort(items)
slices.SortFunc(items, func(a, b Item) int {
    return cmp.Compare(a.Priority, b.Priority)
})
idx, found := slices.BinarySearch(sorted, target)
```

### Iterators and range-over-func (Go 1.23+)

Go 1.23 introduced iterator functions via the `iter` package. An iterator is
a function that calls a yield function for each element. This enables lazy
evaluation without channels or goroutines.

**Basic patterns:**

```go
import "iter"

// Single-value iterator
func Positive(nums []int) iter.Seq[int] {
    return func(yield func(int) bool) {
        for _, n := range nums {
            if n > 0 {
                if !yield(n) {
                    return
                }
            }
        }
    }
}

// Key-value iterator
func Enumerate[T any](s []T) iter.Seq2[int, T] {
    return func(yield func(int, T) bool) {
        for i, v := range s {
            if !yield(i, v) {
                return
            }
        }
    }
}

// Consuming iterators — they work with range
for v := range Positive(data) {
    fmt.Println(v)
}
for i, v := range Enumerate(items) {
    fmt.Printf("%d: %v\n", i, v)
}
```

**When to use iterators vs slices:**

- Use iterators when the full collection is expensive to compute or unbounded
- Use iterators for composable pipelines (filter → map → take)
- Use plain slices when the data is already materialized and small
- Don't use iterators just because you can — concrete slices are simpler

**Chaining iterators:**

```go
func Filter[T any](seq iter.Seq[T], pred func(T) bool) iter.Seq[T] {
    return func(yield func(T) bool) {
        for v := range seq {
            if pred(v) {
                if !yield(v) {
                    return
                }
            }
        }
    }
}

func Take[T any](seq iter.Seq[T], n int) iter.Seq[T] {
    return func(yield func(T) bool) {
        i := 0
        for v := range seq {
            if i >= n {
                return
            }
            if !yield(v) {
                return
            }
            i++
        }
    }
}
```

### Range-over-int (Go 1.22+)

A small but welcome simplification:

```go
// Go 1.22+
for i := range 10 {
    fmt.Println(i) // 0, 1, 2, ..., 9
}

// Before Go 1.22
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
```

Use this in new code — it's cleaner and less error-prone.
