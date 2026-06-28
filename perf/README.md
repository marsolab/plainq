# PlainQ performance & AB-testing harness

Measure PlainQ's gRPC performance on **every change** and compare it against a
**stable reference** (e.g. `main`). The harness builds two servers — your
current checkout (**candidate**) and a stable git ref (**baseline**) — drives
an identical [k6](https://k6.io) gRPC workload at both simultaneously, stores
everything in [VictoriaMetrics](https://victoriametrics.com), and reports the
result two ways:

- a **Grafana dashboard** (`PlainQ AB Performance`) for live, side-by-side
  comparison, and
- a **markdown report** with a pass/fail regression verdict, suitable for CI.

```
                         ┌──────────────────┐
              scrape /metrics (variant label)│
        ┌───────────────►│ VictoriaMetrics  │◄── remote-write (k6, variant tag)
        │                └────────┬─────────┘
┌───────┴────────┐               │ query
│ plainq-baseline│◄──┐           ▼
│ plainq-candidate│◄─┤      ┌──────────┐     ┌──────────────┐
└────────────────┘   │      │ Grafana  │     │ report.py    │
                     k6 gRPC │ dashboard│     │ markdown +   │
                  (Send/Recv/└──────────┘     │ verdict      │
                   Delete)                    └──────────────┘
```

## Requirements

- Docker + Docker Compose v2
- `git`, `bash`, `curl`, `python3` (stdlib only — no pip installs)
- Internet access on first run to pull the `victoriametrics`, `grafana`, and
  `grafana/k6` images. Building the PlainQ images themselves only needs the Go
  module cache (Houston/Bun are skipped — see `Dockerfile.plainq`).

k6's **native** gRPC support (`k6/net/grpc`) is used — no xk6 plugin build is
required. The pinned `grafana/k6:0.55.0` image bundles the protobuf
well-known types, so `schema/v1/schema.proto` loads as-is.

## Quick start

```shell
# From the repo root or perf/ — runs the whole pipeline:
#   build candidate + baseline → start stack → load test → report
make -C perf ab

# Tune the workload:
make -C perf ab DURATION=5m VUS=50 MSG_BYTES=1024

# Compare against a specific stable ref instead of origin/main:
make -C perf ab BASELINE_REF=v0.1.0
```

When it finishes you get:

- **Grafana**: <http://localhost:3000> → *PlainQ AB Performance* (anonymous
  admin access is enabled).
- **Report**: `perf/results/report-<run-id>.md` (also printed to the console).
- **k6 summary**: `perf/results/summary-<run-id>.json`.

The stack is left running so you can explore Grafana. Stop it with
`make -C perf down`, or fully clean up (volumes, images, worktree) with
`make -C perf clean`.

## The `perfctl` CLI

`perfctl` ([`cmd/perfctl`](../cmd/perfctl)) is the single-entry CLI for the
harness — `make ab` / `make load` are thin wrappers over it. Build it once,
then drive everything from one binary:

```shell
make -C perf cli          # builds ./perf/perfctl
./perf/perfctl -h         # list commands

# AB comparison (candidate = current checkout, baseline = a git ref):
./perf/perfctl ab
./perf/perfctl ab -baseline v0.1.0 -vus 50 -duration 5m

# Single-target load: just hammer one already-running server, no baseline,
# no build. Spins up VictoriaMetrics + Grafana so the dashboard works.
./perf/perfctl load -target localhost:8080 -vus 30 -duration 2m

# Stack management:
./perf/perfctl up         # VictoriaMetrics + Grafana only
./perf/perfctl dashboard  # print URLs
./perf/perfctl down       # stop
./perf/perfctl clean      # stop + remove volumes, images, results
```

Every flag also reads an env var fallback (`-vus`/`VUS`, `-baseline`/
`BASELINE_REF`, `-target`/`TARGET_ADDR`, …), and `-h` works on each
subcommand. To load a server running on the **host** from inside Docker, use
`-target host.docker.internal:PORT` (the default). `perfctl load` reuses the
same metric names as the AB test, so the *PlainQ AB Performance* dashboard
shows the run under the `load` variant.

## How it works

1. **Build both variants.** `scripts/run.sh` builds `plainq-perf:candidate`
   from the current checkout and `plainq-perf:baseline` from `BASELINE_REF`
   (materialized via a throwaway `git worktree`). Both use the same
   `Dockerfile.plainq`, so the only difference is the source revision.
2. **Run both servers** with auth and telemetry disabled, SQLite on `tmpfs`
   (so disk noise doesn't skew results), and the Prometheus `/metrics`
   endpoint enabled.
3. **Load test.** k6 runs two `constant-vus` scenarios in parallel — one per
   variant — performing a full message lifecycle each iteration:
   `Send → Receive → Delete`. Every sample is tagged `variant=baseline|candidate`
   (scenario tag) and `op=send|receive|delete|total` (per call).
4. **Store.** k6 streams metrics to VictoriaMetrics via Prometheus
   remote-write; VictoriaMetrics also scrapes both servers' `/metrics`.
5. **Report.** `scripts/report.py` queries VictoriaMetrics over the test
   window and emits the comparison table + verdict.

## Configuration

All knobs are environment variables (forwarded by `make`/`run.sh`):

| Variable       | Default      | Meaning                                  |
| -------------- | ------------ | ---------------------------------------- |
| `BASELINE_REF` | `origin/main`| Git ref to build the baseline from.      |
| `VUS`          | `20`         | Virtual users **per variant**.           |
| `DURATION`     | `2m`         | Load duration.                           |
| `BATCH_SIZE`   | `1`          | `Receive` batch size (1–10).             |
| `MSG_BYTES`    | `256`        | Message body size.                       |
| `RUN_ID`       | git short sha| Label applied to metrics & result files. |
| `KEEP_UP`      | `1`          | Keep the stack up after the run.         |

## Metrics

Custom k6 metrics (in VictoriaMetrics, prefixed `k6_`):

| Series                              | Type    | Labels          |
| ----------------------------------- | ------- | --------------- |
| `k6_plainq_reqs_total`              | counter | `variant`, `op` |
| `k6_plainq_errs_total`              | counter | `variant`, `op` |
| `k6_plainq_latency_{p50,p95,p99,…}` | gauge   | `variant`, `op` |

Server-side series scraped from each PlainQ `/metrics` (label `variant`,
`job="plainq"`): `process_resident_memory_bytes`, `process_cpu_seconds_total`,
`go_goroutines`, and the per-RPC `grpc_requests_total` /
`grpc_request_duration` when available.

> Server-resource panels depend on the server exposing process/Go metrics. If
> they read `n/a`, the AB comparison still works — k6's client-side metrics are
> the source of truth for latency and throughput.

> **High error rates under load are expected** with the SQLite backend: it is
> single-writer, so many concurrent VUs doing `Send`/`Delete` raise
> `SQLITE_BUSY`. That contention hits **both** variants equally, so the
> *relative* candidate-vs-baseline verdict stays meaningful even when absolute
> error rates are high. Lower `VUS`, raise `BATCH_SIZE`, or point at PostgreSQL
> for a cleaner absolute picture. k6's absolute thresholds are intentionally
> loose for this reason — `report.py`'s relative comparison is the real gate.

## Regression gating in CI

`report.py` exits non-zero when the candidate's end-to-end p95 is more than
10% above baseline (or its error rate is materially worse), so it can gate a
pipeline:

```shell
make -C perf ab DURATION=3m   # exits non-zero on regression
```

Thresholds live at the top of `scripts/report.py`
(`REGRESSION_THRESHOLD`, `IMPROVEMENT_THRESHOLD`). k6 also enforces absolute
guard-rail thresholds (see `options.thresholds` in `k6/ab_test.js`).

## Layout

```
perf/
├── Makefile                  # entry points (make ab / up / down / clean)
├── Dockerfile.plainq         # fast, UI-less server build (candidate & baseline)
├── docker-compose.yml        # VM + Grafana + both servers + k6
├── scripts/
│   ├── run.sh                # orchestrator
│   └── report.py             # VictoriaMetrics → markdown comparison + verdict
├── k6/
│   └── ab_test.js            # native-gRPC AB load test
├── victoriametrics/
│   └── scrape.yml            # scrape both servers, label by variant
├── grafana/
│   ├── provisioning/         # datasource + dashboard providers
│   └── dashboards/
│       └── plainq-ab.json    # PlainQ AB Performance dashboard
└── results/                  # generated reports & k6 summaries (gitignored)
```

## Manual workflow

```shell
make -C perf ab            # build + run once (leaves stack up)
make -C perf k6            # re-run only the load test against the live stack
make -C perf dashboard     # print Grafana/VM URLs
make -C perf logs          # tail stack logs
make -C perf down          # stop
make -C perf clean         # stop + remove volumes, images, worktree, results
```
