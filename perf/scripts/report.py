#!/usr/bin/env python3
"""Render a baseline-vs-candidate comparison report from VictoriaMetrics.

Queries the metrics produced by the k6 AB run (and the scraped PlainQ
/metrics endpoints) over the test window, builds a markdown table comparing
the two variants per operation, and emits an overall regression verdict.

Uses only the Python standard library (no external dependencies).
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request

# A candidate p95 more than this fraction above baseline is a regression.
REGRESSION_THRESHOLD = 0.10
# A candidate p95 more than this fraction below baseline is an improvement.
IMPROVEMENT_THRESHOLD = 0.05

OPS = ["total", "send", "receive", "delete"]


def vm_query(vm_url, promql, at):
    """Run an instant query against VictoriaMetrics; return first sample float or None."""
    params = urllib.parse.urlencode({"query": promql, "time": str(at)})
    url = f"{vm_url}/api/v1/query?{params}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            payload = json.load(resp)
    except Exception as exc:  # noqa: BLE001 - report tool, never hard-fail
        print(f"warn: query failed ({promql}): {exc}", file=sys.stderr)
        return None

    result = payload.get("data", {}).get("result", [])
    if not result:
        return None
    try:
        return float(result[0]["value"][1])
    except (KeyError, IndexError, ValueError):
        return None


def counter(vm_url, name, selector, window, at):
    """increase() of a k6 counter over the window, tolerating the _total suffix."""
    base = f'sum(increase({name}{{{selector}}}[{window}s]))'
    val = vm_query(vm_url, base, at)
    if val is None and not name.endswith("_total"):
        val = vm_query(vm_url, f'sum(increase({name}_total{{{selector}}}[{window}s]))', at)
    return val


def avg_gauge(vm_url, name, selector, window, at):
    """avg_over_time() of a gauge series over the window."""
    return vm_query(vm_url, f'avg(avg_over_time({name}{{{selector}}}[{window}s]))', at)


def collect(vm_url, variant, window, at):
    sel = f'variant="{variant}"'
    data = {}

    for op in OPS:
        opsel = f'{sel},op="{op}"'
        # k6's Prometheus remote-write exports time metrics in seconds; convert
        # to milliseconds for display.
        data[op] = {
            "p50": _ms(avg_gauge(vm_url, "k6_plainq_latency_p50", opsel, window, at)),
            "p95": _ms(avg_gauge(vm_url, "k6_plainq_latency_p95", opsel, window, at)),
            "p99": _ms(avg_gauge(vm_url, "k6_plainq_latency_p99", opsel, window, at)),
            "reqs": counter(vm_url, "k6_plainq_reqs", opsel, window, at),
            "errs": counter(vm_url, "k6_plainq_errs", opsel, window, at),
        }

    # Server-side resource usage scraped from PlainQ /metrics.
    data["server"] = {
        "rss_mb": _div(avg_gauge(vm_url, "process_resident_memory_bytes", sel, window, at), 1024 * 1024),
        "cpu": vm_query(vm_url, f'avg(rate(process_cpu_seconds_total{{{sel}}}[1m]))', at),
        "goroutines": avg_gauge(vm_url, "go_goroutines", sel, window, at),
    }
    return data


def _div(value, denom):
    return None if value is None else value / denom


def _ms(value):
    """Convert a seconds value (k6 prom-rw unit) to milliseconds for display."""
    return None if value is None else value * 1000.0


def fmt(value, suffix="", nd=2):
    if value is None:
        return "n/a"
    return f"{value:.{nd}f}{suffix}"


def delta_pct(candidate, baseline):
    if candidate is None or baseline is None or baseline == 0:
        return None
    return (candidate - baseline) / baseline * 100.0


def fmt_delta(candidate, baseline, lower_is_better=True):
    pct = delta_pct(candidate, baseline)
    if pct is None:
        return "n/a"
    arrow = ""
    if lower_is_better:
        arrow = " ✅" if pct < -IMPROVEMENT_THRESHOLD * 100 else (" ⚠️" if pct > REGRESSION_THRESHOLD * 100 else "")
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}%{arrow}"


def verdict(cand, base):
    c95 = cand["total"]["p95"]
    b95 = base["total"]["p95"]
    c_reqs = cand["total"]["reqs"] or 0
    b_reqs = base["total"]["reqs"] or 0
    c_err = (cand["total"]["errs"] or 0) / c_reqs if c_reqs else 0
    b_err = (base["total"]["errs"] or 0) / b_reqs if b_reqs else 0

    notes = []
    status = "✅ NO REGRESSION"

    if c95 is not None and b95 is not None and b95 > 0:
        pct = (c95 - b95) / b95
        if pct > REGRESSION_THRESHOLD:
            status = "⚠️ REGRESSION"
            notes.append(f"candidate p95 is {pct * 100:.1f}% slower than baseline (> {REGRESSION_THRESHOLD * 100:.0f}% threshold)")
        elif pct < -IMPROVEMENT_THRESHOLD:
            status = "🚀 IMPROVEMENT"
            notes.append(f"candidate p95 is {-pct * 100:.1f}% faster than baseline")
    else:
        notes.append("insufficient latency data to compare p95")

    if c_err > b_err + 0.01:
        status = "⚠️ REGRESSION"
        notes.append(f"candidate error rate {c_err * 100:.2f}% > baseline {b_err * 100:.2f}%")

    return status, notes


def render(args, cand, base):
    window = max(1, args.end - args.start)
    lines = []
    lines.append(f"# PlainQ AB Performance Report — `{args.run_id}`")
    lines.append("")
    lines.append(f"- **Candidate**: `{args.candidate_sha}`")
    lines.append(f"- **Baseline**: `{args.baseline_sha}`")
    lines.append(f"- **Window**: {window}s")
    lines.append("")

    status, notes = verdict(cand, base)
    lines.append(f"## Verdict: {status}")
    lines.append("")
    for note in notes:
        lines.append(f"- {note}")
    lines.append("")

    # Throughput & errors.
    lines.append("## Throughput & errors (end-to-end, op=total)")
    lines.append("")
    lines.append("| Metric | Baseline | Candidate | Δ |")
    lines.append("| --- | --- | --- | --- |")
    b_rps = _div(base["total"]["reqs"], window)
    c_rps = _div(cand["total"]["reqs"], window)
    lines.append(f"| Iterations/s | {fmt(b_rps)} | {fmt(c_rps)} | {fmt_delta(c_rps, b_rps, lower_is_better=False)} |")
    lines.append(f"| Iterations | {fmt(base['total']['reqs'], nd=0)} | {fmt(cand['total']['reqs'], nd=0)} | — |")
    lines.append(f"| Errors | {fmt(base['total']['errs'], nd=0)} | {fmt(cand['total']['errs'], nd=0)} | — |")
    lines.append("")

    # Latency per operation.
    lines.append("## Latency by operation (ms)")
    lines.append("")
    lines.append("| Op | Stat | Baseline | Candidate | Δ |")
    lines.append("| --- | --- | --- | --- | --- |")
    for op in OPS:
        for stat in ("p50", "p95", "p99"):
            b = base[op][stat]
            c = cand[op][stat]
            lines.append(f"| {op} | {stat} | {fmt(b)} | {fmt(c)} | {fmt_delta(c, b)} |")
    lines.append("")

    # Server resources.
    lines.append("## Server resources (scraped from /metrics)")
    lines.append("")
    lines.append("| Metric | Baseline | Candidate | Δ |")
    lines.append("| --- | --- | --- | --- |")
    bs, cs = base["server"], cand["server"]
    lines.append(f"| RSS (MB) | {fmt(bs['rss_mb'])} | {fmt(cs['rss_mb'])} | {fmt_delta(cs['rss_mb'], bs['rss_mb'])} |")
    lines.append(f"| CPU (cores) | {fmt(bs['cpu'])} | {fmt(cs['cpu'])} | {fmt_delta(cs['cpu'], bs['cpu'])} |")
    lines.append(f"| Goroutines | {fmt(bs['goroutines'], nd=0)} | {fmt(cs['goroutines'], nd=0)} | {fmt_delta(cs['goroutines'], bs['goroutines'])} |")
    lines.append("")
    lines.append("_Legend: Δ lower is better for latency/resources (✅ improvement, ⚠️ regression); higher is better for throughput._")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="PlainQ AB comparison report")
    parser.add_argument("--vm", default="http://localhost:8428")
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--run-id", default="local")
    parser.add_argument("--candidate-sha", default="candidate")
    parser.add_argument("--baseline-sha", default="baseline")
    parser.add_argument("--out", default="-")
    args = parser.parse_args()

    window = max(1, args.end - args.start)
    cand = collect(args.vm, "candidate", window, args.end)
    base = collect(args.vm, "baseline", window, args.end)

    report = render(args, cand, base)

    if args.out == "-":
        print(report)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(report)

    status, _ = verdict(cand, base)
    # Exit non-zero on regression so CI can gate on it.
    sys.exit(1 if status.startswith("⚠️") else 0)


if __name__ == "__main__":
    main()
