#!/usr/bin/env bash
set -euo pipefail

expected_sha="${1:?usage: check-schema-publish-head.sh EXPECTED_SHA [REMOTE]}"
remote="${2:-origin}"

case "$expected_sha" in
  (*[!0-9a-f]*|'') echo "invalid expected git SHA" >&2; exit 1 ;;
esac
test "${#expected_sha}" -eq 40

remote_main_ref="$(git ls-remote --exit-code "$remote" refs/heads/main)"
if [[ "$remote_main_ref" == *$'\n'* ]]; then
  echo "remote returned multiple main refs" >&2
  exit 1
fi
IFS=$'\t' read -r remote_main_sha remote_ref <<< "$remote_main_ref"
test "$remote_ref" = "refs/heads/main"
case "$remote_main_sha" in
  (*[!0-9a-f]*|'') echo "invalid remote main git SHA" >&2; exit 1 ;;
esac
test "${#remote_main_sha}" -eq 40

if test "$expected_sha" != "$remote_main_sha"; then
  echo "stale schema publication: workflow SHA $expected_sha is not main head $remote_main_sha" >&2
  exit 1
fi
printf '%s\n' "$remote_main_sha"
