---
name: perf-ab-testing
description: >-
  Use when measuring or comparing PlainQ's gRPC performance — running the
  perf/ AB harness, comparing a branch or PR against a stable ref, reasoning
  about a latency/throughput regression, reading the "PlainQ AB Performance"
  Grafana dashboard or the markdown report, editing the k6 gRPC load script,
  the VictoriaMetrics scrape config, the Performance AB GitHub workflow, or
  the perf Dockerfile. Covers the candidate-vs-baseline AB model, the report
  verdict, and the per-PR CI integration.
version: 1.0.0
tags:
  - performance
  - benchmarking
  - k6
  - grpc
  - victoriametrics
  - grafana
  - ci
  - plainq
---

# PlainQ performance AB testing

## Overview

PlainQ ships a self-contained AB harness under [`perf/`](../../../perf). It
builds **two** servers — `candidate` (current checkout) and `baseline` (a
stable git ref) — runs an identical k6 gRPC workload (`Send → Receive →
Delete`) at both at once, stores everything in VictoriaMetrics, and reports
the comparison via a Grafana dashboard **and** a markdown report with a
pass/fail verdict. Every metric is tagged `variant=baseline|candidate` and
`op=send|receive|delete|total`.

**Core idea:** never read a single absolute number — always compare candidate
against the baseline ref under the same load.

## When to use

- "Did this change make PlainQ slower/faster?" / suspected perf regression.
- Comparing a branch or PR against `main` (or a tag) for latency/throughput.
- Reading the AB Grafana dashboard or `perf/results/report-*.md`.
- Editing the harness: `k6/ab_test.js`, `victoriametrics/scrape.yml`,
  `grafana/`, `Dockerfile.plainq`, `scripts/`, or `.github/workflows/perf.yml`.

## Quick reference

| Action | Command |
| --- | --- |
| Full AB run vs `origin/main` (leaves stack up) | `make -C perf ab` |
| Compare against a specific ref | `make -C perf ab BASELINE_REF=v0.1.0` |
| Heavier / longer run | `make -C perf ab DURATION=5m VUS=50 MSG_BYTES=1024` |
| Re-run only k6 against the live stack | `make -C perf k6` |
| Stop stack / full cleanup | `make -C perf down` / `make -C perf clean` |

Knobs (env): `BASELINE_REF`, `VUS`, `DURATION`, `BATCH_SIZE`, `MSG_BYTES`,
`RUN_ID`, `KEEP_UP`. See `perf/README.md` for the full table.

## Reading results

- **Markdown report** — `perf/results/report-<run-id>.md` (also printed by
  `run.sh`). Verdict: `✅ NO REGRESSION`, `🚀 IMPROVEMENT`, or
  `⚠️ REGRESSION` (candidate end-to-end p95 >10% above baseline, or worse
  error rate). `report.py` **exits non-zero on regression** so `run.sh` /
  CI can gate.
- **Grafana** — <http://localhost:3000> → *PlainQ AB Performance*: latency
  (p50/p95/p99), throughput, errors, per-op latency, server resources, all
  baseline-vs-candidate.
- **Metrics in VictoriaMetrics** (`:8428`, prefix `k6_`):
  `k6_plainq_latency_p95{variant,op}`, `k6_plainq_reqs_total{variant,op}`,
  `k6_plainq_errs_total{variant,op}`.

## On every PR (CI)

`.github/workflows/perf.yml` runs the harness automatically:

- **Pull requests** → candidate = the PR, baseline = the target branch;
  a **light** run (10 VUs, 45s). The report is posted as a sticky PR comment.
- **Push to `main`** → candidate = new `main`, baseline = previous commit;
  a **thorough** run (30 VUs, 2m) for the baseline trend.

It is **informational** — the verdict never fails the check. Full data is in
the run's `perf-results` artifact. To make it a hard gate, remove
`continue-on-error` from the `Run AB test` step.

## Common mistakes

- **Comparing absolute numbers across machines.** Only candidate-vs-baseline
  on the same run is meaningful; CI runners are noisy.
- **Forgetting `KEEP_UP=0`** in automation — `run.sh` leaves the stack up by
  default for interactive use.
- **Expecting an xk6 plugin build.** k6's gRPC support is native
  (`k6/net/grpc`); no plugin compile is needed.
- **Server-resource panels show `n/a`.** They depend on the server exposing
  process/Go metrics; the k6 client-side latency/throughput is the source of
  truth regardless.
- **Editing the dashboard JSON by hand and breaking it.** Validate with
  `jq empty perf/grafana/dashboards/plainq-ab.json`.

## Agent/platform notes

This skill uses Claude Code tool names. On Codex/others, map them per
`.agents/skills/using-superpowers/references/codex-tools.md` (e.g. `Bash` →
your shell). The harness itself is plain `make`/`docker`/`git` — identical on
every platform.
