# Concurrency reference

Carved from the comprehensive Go style guide. Covers goroutine lifecycle,
"leave concurrency to the caller", WaitGroup coordination, context as
first parameter, and channel buffer sizing.

---

## Never start a goroutine without knowing when it will stop

This is the single most important concurrency guideline, repeated across all
sources. Goroutines own resources—locks, memory, connections—that only get freed
when the goroutine exits:

```go
// BAD: goroutine may never terminate
func startWorker() {
    go func() {
        for {
            process(<-workChan)  // blocked forever if workChan abandoned
        }
    }()
}

// GOOD: explicit termination
func startWorker(ctx context.Context) {
    go func() {
        for {
            select {
            case work := <-workChan:
                process(work)
            case <-ctx.Done():
                return
            }
        }
    }()
}
```

## Leave concurrency to the caller

Don't force async execution on consumers. Let them choose whether to run your
code in a goroutine:

```go
// BAD: forces concurrency
func ListFiles(dir string) <-chan string {
    ch := make(chan string)
    go func() {
        filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
            ch <- path
            return nil
        })
        close(ch)
    }()
    return ch
}

// GOOD: caller decides
func ListFiles(dir string, fn func(string) error) error {
    return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        return fn(path)
    })
}
```

The bad pattern can't distinguish errors from empty directories and forces
callers to drain the channel even when they've found their answer.

## Use sync.WaitGroup for goroutine coordination

```go
var wg sync.WaitGroup
for _, item := range items {
    wg.Add(1)
    go func(item Item) {
        defer wg.Done()
        process(item)
    }(item)  // pass by value to avoid closure capture bug
}
wg.Wait()
```

## Context must be the first parameter

```go
func ProcessRequest(ctx context.Context, req *Request) (*Response, error) {
    // ...
}
```

Never store context in structs—pass it explicitly through each call. The
cancellation of a context argument implies interruption of the function
receiving it.

## Channel buffer sizes should be zero or one

CockroachDB's rule: **any buffer size other than 0 or 1 requires scrutiny**.
Larger buffers often mask synchronization bugs. When you need buffering,
document why that specific size was chosen.
