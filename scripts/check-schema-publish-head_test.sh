#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guard="$repo_root/scripts/check-schema-publish-head.sh"
workflow="$repo_root/.github/workflows/schema-release.yaml"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

remote="$tmp_dir/remote.git"
writer="$tmp_dir/writer"
git init --quiet --bare --initial-branch=main "$remote"
git init --quiet --initial-branch=main "$writer"
git -C "$writer" config user.name "Schema Guard Test"
git -C "$writer" config user.email "schema-guard@example.invalid"
git -C "$writer" remote add origin "$remote"

git -C "$writer" commit --quiet --allow-empty -m initial
initial_sha="$(git -C "$writer" rev-parse HEAD)"
git -C "$writer" push --quiet --set-upstream origin main
"$guard" "$initial_sha" "$remote" >/dev/null

git -C "$writer" commit --quiet --allow-empty -m newer
current_sha="$(git -C "$writer" rev-parse HEAD)"
git -C "$writer" push --quiet origin main

if "$guard" "$initial_sha" "$remote" >/dev/null 2>&1; then
  echo "stale main SHA unexpectedly passed the publication guard" >&2
  exit 1
fi
"$guard" "$current_sha" "$remote" >/dev/null

rg -U -q 'concurrency:\n      group: plainq-schema-bsr-main-publish\n      cancel-in-progress: false' "$workflow"
rg -U -q '\./scripts/check-schema-publish-head\.sh "\$server_git_sha" origin >/dev/null\n          buf push schema' "$workflow"
echo "schema publication guard accepted current main, rejected stale main, and is immediately before buf push"
