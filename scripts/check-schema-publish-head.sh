#!/usr/bin/env bash
set -euo pipefail

expected_sha="${1:?usage: check-schema-publish-head.sh EXPECTED_SHA [REMOTE]}"
remote="${2:-origin}"

case "$expected_sha" in
  (*[!0-9a-f]*|'') echo "invalid expected git SHA" >&2; exit 1 ;;
esac
test "${#expected_sha}" -eq 40

git fetch --no-tags --quiet "$remote" refs/heads/main
remote_main_sha="$(git rev-parse --verify 'FETCH_HEAD^{commit}')"
case "$remote_main_sha" in
  (*[!0-9a-f]*|'') echo "invalid remote main git SHA" >&2; exit 1 ;;
esac
test "${#remote_main_sha}" -eq 40

if test "$expected_sha" = "$remote_main_sha"; then
  printf '%s\n' "$remote_main_sha"
  exit 0
fi

if ! git cat-file -e "$expected_sha^{commit}" ||
  ! git merge-base --is-ancestor "$expected_sha" "$remote_main_sha"; then
  echo "stale schema publication: workflow SHA $expected_sha is not an ancestor of main head $remote_main_sha" >&2
  exit 1
fi

if ! git log --first-parent --diff-merges=first-parent --no-renames --format= --name-only -z \
  "$expected_sha..$remote_main_sha" -- |
  while IFS= read -r -d '' changed_path; do
    case "$changed_path" in
      # The release workflow publishes only when schema sources change.
      # Generator and workflow inputs still trigger validation, but must not
      # stale an older source-changing run because they schedule no replacement
      # publication of their own.
      (schema/*)
        echo "newer publication-relevant path: $changed_path" >&2
        exit 1
        ;;
    esac
  done; then
  echo "stale schema publication: main advanced through publication-relevant changes" >&2
  exit 1
fi

printf '%s\n' "$remote_main_sha"
