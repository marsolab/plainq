#!/usr/bin/env python3

import pathlib
import re
import unittest


PERF_DIR = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = PERF_DIR.parent


class BuilderVersionTest(unittest.TestCase):
    def test_perf_builder_matches_go_mod_patch_version(self):
        go_mod = (REPO_ROOT / "go.mod").read_text(encoding="utf-8")
        dockerfile = (PERF_DIR / "Dockerfile.plainq").read_text(encoding="utf-8")

        go_version = re.search(r"^go (\S+)$", go_mod, re.MULTILINE)
        builder_version = re.search(
            r"^FROM golang:([^-\s]+)-alpine AS build$",
            dockerfile,
            re.MULTILINE,
        )

        self.assertIsNotNone(go_version, "go.mod has no Go version directive")
        self.assertIsNotNone(builder_version, "perf builder image is not a pinned Alpine Go image")
        self.assertEqual(
            builder_version.group(1),
            go_version.group(1),
            "perf builder must not lag the Go patch version required by go.mod",
        )


if __name__ == "__main__":
    unittest.main()
