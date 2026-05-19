---
name: go-concurrency
description: >-
  Disciplined Go concurrency. ALWAYS use this skill when writing or
  reviewing Go code that touches goroutines, channels, `context.Context`,
  `sync.WaitGroup`, `sync.Mutex` / `sync.RWMutex`, `sync.Once`,
  `errgroup.Group`, worker pools, fan-out/fan-in pipelines, request
  cancellation, timeouts, deadlines, or any "run this in the background"
  pattern. Also use when debugging deadlocks, goroutine leaks, race
  conditions, or channel-related bugs. Pair with go-errors for error
  propagation across goroutines.
version: 1.0.0
tags:
  - go
  - golang
  - concurrency
  - goroutines
  - channels
  - context
  - errgroup
---

# Go Concurrency

Goroutines are cheap; goroutine *lifecycle* is the hard part. Every
goroutine you start owns resources (memory, locks, file descriptors) until
it exits.

For the comprehensive reference, see `references/concurrency.md`.

## The single most important rule

**Never start a goroutine without knowing when it will stop.**

```go
// BAD: leaks if workChan is abandoned
go func() {
    for {
        process(<-workChan)
    }
}()

// GOOD: terminates on context cancellation
go func() {
    for {
        select {
        case <-ctx.Done():
            return
        case work := <-workChan:
            process(work)
        }
    }
}()
```

If you can't answer "when does this goroutine exit?", don't write it.

## Context

- `context.Context` is the **first** parameter on every function that may
  block, do I/O, or call something that does.
- Never store a context in a struct.
- Cancel contexts you create: `defer cancel()`.
- Pass `ctx` through; don't replace it with `context.Background()`
  partway down the call stack.

```go
ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
defer cancel()

if err := db.QueryRowContext(ctx, q, id).Scan(&u); err != nil {
    return fmt.Errorf("load user: %w", err)
}
```

## Leave concurrency to the caller

Library functions should be synchronous. Let the caller decide whether
to launch a goroutine.

```go
// BAD: forces async, hides errors, requires draining
func ListFiles(dir string) <-chan string { ... }

// GOOD: synchronous walk; caller can wrap in `go` if they want
func ListFiles(dir string, fn func(string) error) error {
    return filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        return fn(p)
    })
}
```

## WaitGroup for fan-out

```go
var wg sync.WaitGroup
for _, item := range items {
    wg.Add(1)
    go func(item Item) {       // pass item to avoid capture bug
        defer wg.Done()
        process(item)
    }(item)
}
wg.Wait()
```

## errgroup for fan-out with errors

When goroutines can fail, `golang.org/x/sync/errgroup` handles
cancellation and the first-error collection:

```go
g, ctx := errgroup.WithContext(ctx)
for _, item := range items {
    item := item
    g.Go(func() error {
        return process(ctx, item)
    })
}
if err := g.Wait(); err != nil {
    return fmt.Errorf("processing batch: %w", err)
}
```

The shared `ctx` cancels as soon as one goroutine returns an error, so
the others can short-circuit.

## Channels

- Buffer size **0 or 1**, anything larger needs justification — large
  buffers mask synchronization bugs.
- The sender closes the channel; never the receiver.
- Closing a closed channel panics. So does sending on a closed channel.
- Receiving from a closed channel returns the zero value immediately.

```go
ch := make(chan Result)
go func() {
    defer close(ch)              // owner closes
    for _, x := range inputs {
        select {
        case ch <- compute(x):
        case <-ctx.Done():
            return
        }
    }
}()
for r := range ch { ... }
```

## Mutex patterns

- Keep critical sections small. Compute outside the lock, write inside.
- `sync.RWMutex` only when reads dominate (10:1 or more); otherwise the
  write-lock fairness penalty negates the benefit.
- Don't copy a struct that contains a `sync.Mutex` (the linter `copylocks`
  catches this).

```go
type Cache struct {
    mu    sync.RWMutex
    items map[string]Item
}

func (c *Cache) Get(k string) (Item, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    i, ok := c.items[k]
    return i, ok
}
```

## Common bugs

- **Loop variable capture** — pass to the goroutine as an argument or
  shadow with `item := item` before `go func()`.
- **Forgetting `defer cancel()`** — leaks the context's resources.
- **Map writes from multiple goroutines** — Go's runtime detects and
  panics. Use a mutex or `sync.Map`.
- **`time.After` in a loop** — leaks a timer per iteration; use
  `time.NewTimer` and `Reset`.

## When to load a sibling skill

| Task | Skill |
|---|---|
| Returning errors out of goroutines, wrapping with context | go-errors |
| Logging from concurrent code with request-scoped attrs | go-logging |
| Per-request cancellation in HTTP handlers | go-http |
| General Go idioms and naming | go-style |
