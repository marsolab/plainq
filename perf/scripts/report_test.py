#!/usr/bin/env python3

import argparse
import unittest

import report


def sample(total_reqs=1000, total_errs=0, total_p95=10.0, statuses=None):
    data = {}
    for op in report.OPS:
        data[op] = {
            "p50": 5.0,
            "p95": total_p95 if op == "total" else 8.0,
            "p99": 15.0,
            "reqs": total_reqs,
            "errs": total_errs,
            "statuses": statuses or [],
        }
    data["server"] = {"rss_mb": 10.0, "cpu": 0.2, "goroutines": 8.0}
    return data


class VerdictTest(unittest.TestCase):
    def test_low_success_rate_is_inconclusive_and_suppresses_latency_verdict(self):
        baseline = sample(total_reqs=1000, total_errs=923, total_p95=10.0)
        candidate = sample(total_reqs=1000, total_errs=989, total_p95=20.0)

        status, notes = report.verdict(candidate, baseline)

        self.assertEqual(status, "⏸️ INCONCLUSIVE")
        joined = " ".join(notes)
        self.assertIn("baseline success rate 7.70%", joined)
        self.assertIn("candidate success rate 1.10%", joined)
        self.assertIn("latency verdict suppressed", joined)
        self.assertNotIn("slower than baseline", joined)

    def test_missing_requests_is_inconclusive(self):
        status, notes = report.verdict(sample(total_reqs=0), sample(total_reqs=0))

        self.assertEqual(status, "⏸️ INCONCLUSIVE")
        self.assertTrue(any("no completed iterations" in note for note in notes))

    def test_valid_workload_can_report_latency_regression(self):
        baseline = sample(total_errs=5, total_p95=10.0)
        candidate = sample(total_errs=5, total_p95=12.0)

        status, notes = report.verdict(candidate, baseline)

        self.assertEqual(status, "⚠️ REGRESSION")
        self.assertTrue(any("20.0% slower" in note for note in notes))


class RenderTest(unittest.TestCase):
    def test_renders_bounded_rpc_status_breakdown(self):
        statuses = [
            {"code": "8", "status": "RESOURCE_EXHAUSTED", "reason": "rate_limited", "count": 17},
            {"code": "13", "status": "INTERNAL", "reason": "sqlite_busy", "count": 3},
        ]
        args = argparse.Namespace(
            start=100,
            end=145,
            run_id="test",
            candidate_sha="candidate",
            baseline_sha="baseline",
        )

        rendered = report.render(args, sample(statuses=statuses), sample(statuses=statuses))

        self.assertIn("RPC status breakdown", rendered)
        self.assertIn("| candidate | total | 8 | RESOURCE_EXHAUSTED | rate_limited | 17 |", rendered)


if __name__ == "__main__":
    unittest.main()
