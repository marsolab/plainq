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

run_guard() {
  (cd "$writer" && "$guard" "$1" "$remote")
}

expect_rejected() {
  if rejection_output="$(run_guard "$1" 2>&1)"; then
    echo "$2 unexpectedly passed the publication guard" >&2
    exit 1
  fi
  if ! rg -q "$3" <<< "$rejection_output"; then
    echo "$2 failed for an unexpected reason: $rejection_output" >&2
    exit 1
  fi
}

git -C "$writer" commit --quiet --allow-empty -m initial
initial_sha="$(git -C "$writer" rev-parse HEAD)"
git -C "$writer" push --quiet --set-upstream origin main
run_guard "$initial_sha" >/dev/null

printf '%s\n' unrelated > "$writer/README.md"
git -C "$writer" add README.md
git -C "$writer" commit --quiet -m unrelated
unrelated_sha="$(git -C "$writer" rev-parse HEAD)"
git -C "$writer" push --quiet origin main
run_guard "$initial_sha" >/dev/null

mkdir -p "$writer/schema/v1"
printf '%s\n' relevant > "$writer/schema/v1/schema.proto"
git -C "$writer" add schema/v1/schema.proto
git -C "$writer" commit --quiet -m relevant
relevant_sha="$(git -C "$writer" rev-parse HEAD)"
git -C "$writer" push --quiet origin main
expect_rejected "$unrelated_sha" "stale SHA followed by a relevant schema change" 'publication-relevant'
run_guard "$relevant_sha" >/dev/null

git -C "$writer" switch --quiet -c docs-branch "$unrelated_sha"
printf '%s\n' side-branch-unrelated > "$writer/README.md"
git -C "$writer" add README.md
git -C "$writer" commit --quiet -m side-branch-unrelated
git -C "$writer" switch --quiet main
git -C "$writer" merge --quiet --no-ff --no-edit docs-branch
git -C "$writer" push --quiet origin main
run_guard "$relevant_sha" >/dev/null
merged_unrelated_sha="$(git -C "$writer" rev-parse HEAD)"

printf '%s\n' newer-relevant > "$writer/schema/v1/schema.proto"
git -C "$writer" add schema/v1/schema.proto
git -C "$writer" commit --quiet -m newer-relevant
git -C "$writer" revert --quiet --no-edit HEAD >/dev/null
reverted_sha="$(git -C "$writer" rev-parse HEAD)"
git -C "$writer" push --quiet origin main
expect_rejected "$merged_unrelated_sha" "stale SHA followed by a reverted schema change" 'publication-relevant'
run_guard "$reverted_sha" >/dev/null

git -C "$writer" switch --quiet -c divergent "$initial_sha"
printf '%s\n' divergent > "$writer/divergent.txt"
git -C "$writer" add divergent.txt
git -C "$writer" commit --quiet -m divergent
git -C "$writer" push --quiet --force origin divergent:main
expect_rejected "$reverted_sha" "non-ancestor SHA" 'not an ancestor'
expect_rejected invalid-sha "invalid SHA" 'invalid expected git SHA'

rg -U -q 'concurrency:\n      group: plainq-schema-bsr-main-publish\n      cancel-in-progress: false' "$workflow"
rg -U -q "paths:\n      - 'schema/\\*\\*'\n      - 'internal/server/schema/\\*\\*'\n      - 'scripts/check-schema-\\*\\.sh'\n      - 'Makefile'\n      - '\\.github/workflows/schema-release\\.yaml'" "$workflow"
rg -F -q 'schema/*|internal/server/schema/*|scripts/check-schema-*.sh|Makefile|.github/workflows/schema-release.yaml)' "$guard"
rg -F -q -- 'git log --first-parent --diff-merges=first-parent' "$guard"
rg -U -q -- '- uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n      - uses: bufbuild/buf-setup-action@v1' "$workflow"
rg -U -q '\./scripts/check-schema-publish-head\.sh "\$server_git_sha" origin >/dev/null\n          buf push schema' "$workflow"
echo "schema publication guard accepted exact, linear-unrelated, and merged-unrelated descendants; rejected relevant/reverted/divergent/invalid heads; and is immediately before buf push"
