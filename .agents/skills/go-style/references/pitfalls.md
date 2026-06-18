# Common pitfalls every Go developer encounters

Carved from the comprehensive Go style guide. The traps below catch
people repeatedly; assume any unfamiliar Go reviewer will catch them too.

---

## Loop variable capture in closures

The most common Go bug: closures capture loop variables by reference, seeing the
final value:

```go
// BAD: all goroutines see same value
for _, item := range items {
    go func() {
        process(item)  // captures reference, sees final item
    }()
}

// GOOD: pass as parameter
for _, item := range items {
    go func(item Item) {
        process(item)
    }(item)
}

// GOOD: shadow with local copy
for _, item := range items {
    item := item  // shadow
    go func() {
        process(item)
    }()
}
```

## Nil interface vs nil value in interface

An interface is only nil when **both** type and value are nil. A nil pointer
stored in an interface is not a nil interface:

```go
func returnsInterface() error {
    var err *MyError = nil
    return err  // NOT nil! Type is *MyError, value is nil
}

if err := returnsInterface(); err != nil {
    fmt.Println("error:", err)  // prints "error: <nil>"
}

// CORRECT: return explicit nil
func returnsInterface() error {
    var err *MyError = nil
    if err == nil {
        return nil  // explicit nil interface
    }
    return err
}
```

## Variable shadowing silently breaks logic

The `:=` operator creates new variables, potentially shadowing outer scope:

```go
// BAD: ctx gets shadowed
func handle(ctx context.Context) {
    if needsTimeout {
        ctx, cancel := context.WithTimeout(ctx, time.Second)  // shadows!
        defer cancel()
    }
    // ctx here is the ORIGINAL, not the timeout version
    doWork(ctx)
}

// GOOD: declare cancel separately
func handle(ctx context.Context) {
    if needsTimeout {
        var cancel func()
        ctx, cancel = context.WithTimeout(ctx, time.Second)  // assigns
        defer cancel()
    }
    doWork(ctx)
}
```

Use `go vet -shadow` to detect shadowing.

## Defer timing and argument evaluation

Defer arguments evaluate immediately; the deferred function executes at function
end:

```go
// Arguments evaluated NOW, function runs LATER
func example() {
    i := 1
    defer fmt.Println(i)  // captures 1
    i = 2
    // prints: 1
}

// Defers run at function end, not block end
for _, f := range files {
    file, _ := os.Open(f)
    defer file.Close()  // ALL close at function end, not loop iteration
}

// CORRECT: use closure for per-iteration cleanup
for _, f := range files {
    func() {
        file, _ := os.Open(f)
        defer file.Close()  // closes after this iteration
        process(file)
    }()
}
```

## Map operations require initialization and aren't thread-safe

```go
// PANIC: nil map write
var m map[string]int
m["key"] = 1  // panic!

// CORRECT
m := make(map[string]int)
m["key"] = 1

// Check existence with comma-ok
if val, ok := m["key"]; ok {
    use(val)
}

// Concurrent access requires sync.Mutex or sync.Map
```

## Range returns copies, not references

```go
// BAD: modifies copy
for _, item := range items {
    item.count++  // doesn't affect original
}

// GOOD: use index
for i := range items {
    items[i].count++
}
```

## Slice reslicing shares backing array

```go
// DANGER: modifying one affects the other
original := []byte("AAAA/BBBBB")
first := original[:4]
first = append(first, "XXX"...)  // overwrites original[4:]!

// SAFE: full slice expression limits capacity
first := original[:4:4]  // [low:high:max]
first = append(first, "XXX"...)  // allocates new array
```

## HTTP response bodies must be closed

```go
// WRONG position for defer
resp, err := http.Get(url)
defer resp.Body.Close()  // resp may be nil!
if err != nil {
    return err
}

// CORRECT
resp, err := http.Get(url)
if err != nil {
    return err
}
defer resp.Body.Close()

// BEST: handle redirect failures (both resp and err non-nil)
resp, err := http.Get(url)
if resp != nil {
    defer resp.Body.Close()
}
if err != nil {
    return err
}
```

Modern Go (CL 737720, [golang/go#77370](https://github.com/golang/go/issues/77370))
drains any remaining body inside `Close()` — up to 256 KB or 50 ms — so
connection reuse no longer requires a manual
`io.Copy(io.Discard, resp.Body)`. On older Go versions (before this CL
landed) add the manual drain when the body is small and you care about
keep-alive reuse.
