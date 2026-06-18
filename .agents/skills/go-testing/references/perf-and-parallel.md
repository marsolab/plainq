# Parallel tests, benchmarks, and the race detector

Reference material for `t.Parallel()`, `testing.B` benchmarks, and the
race detector. The SKILL.md keeps only the headline; details live here.

---

## Parallel tests

Mark independent tests with `t.Parallel()` so the runner uses multiple
cores. Inside a table-driven loop, capture the case variable explicitly
— Go 1.22+ fixed the loop-variable scoping in `for`, but the explicit
capture makes parallelism intent obvious to readers:

```go
for name, tc := range tests {
    name, tc := name, tc
    t.Run(name, func(t *testing.T) {
        t.Parallel()
        got, err := Process(tc.input)
        if tc.wantErr {
            td.CmpError(t, err)
            return
        }
        td.CmpNoError(t, err)
        td.Cmp(t, got, tc.want)
    })
}
```

`t.Parallel()` blocks the current subtest until all serial subtests in
the same parent finish, then runs alongside other parallel ones. Don't
mark tests parallel when they share mutable global state (env vars,
working directory, a process-wide singleton) — use a serial group
inside a subtest or refactor the dependency.

`t.Setenv` automatically prevents `t.Parallel`, which is intentional —
the env var would leak across parallel goroutines.

## Benchmarks

```go
func BenchmarkProcess(b *testing.B) {
    data := generateTestData()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        Process(data)
    }
}
```

Run with `go test -bench=. -benchmem`. Patterns:

- **`b.ResetTimer()`** after expensive setup so it's not counted.
- **`b.StopTimer()` / `b.StartTimer()`** around per-iteration setup if
  it can't be hoisted.
- **`b.ReportAllocs()`** at the top of the benchmark to always show
  allocations.
- **Run benchmarks multiple times** (`-count=10`) and compare with
  `benchstat` — single-run numbers are noisy.

Sub-benchmarks work like subtests:

```go
func BenchmarkProcessSizes(b *testing.B) {
    for _, n := range []int{10, 100, 1000} {
        b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
            data := generate(n)
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                Process(data)
            }
        })
    }
}
```

## Race detector

Run `go test -race ./...` regularly. It instruments memory accesses and
flags two-thread reads/writes that aren't separated by a happens-before
relation. It catches:

- Concurrent map reads + writes (Go's runtime panics on these, but only
  when the race actually happens; `-race` finds them earlier).
- Unsynchronised struct-field access from goroutines.
- Mis-paired `sync.Mutex` locking.
- Channel-related data races where you assumed a `select` provided
  synchronisation but it didn't.

CI must run the race detector. Production builds don't need it — the
instrumentation costs about 5–10x slowdown and 2x memory.
