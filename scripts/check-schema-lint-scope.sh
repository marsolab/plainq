#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

buf lint "$repo_root/schema"
cp -R "$repo_root/schema" "$tmp_dir/schema"
mkdir -p "$tmp_dir/schema/lintguard/v1"
printf '%s\n' \
  'syntax = "proto3";' \
  '' \
  'package lintguard.v1;' \
  '' \
  'option go_package = "example.com/lintguard/v1;lintguardv1";' \
  '' \
  'enum GuardedEnum {' \
  '  INVALID_UNSPECIFIED = 0;' \
  '}' > "$tmp_dir/schema/lintguard/v1/invalid.proto"

if lint_output="$(buf lint "$tmp_dir/schema" --error-format=json 2>&1)"; then
  echo "non-exempt invalid enum prefix unexpectedly passed Buf lint" >&2
  exit 1
fi
case "$lint_output" in
  *ENUM_VALUE_PREFIX*) ;;
  *)
    echo "Buf lint failed for an unexpected reason:" >&2
    echo "$lint_output" >&2
    exit 1
    ;;
esac
echo "Buf lint accepted the scoped agent.v1 exception and rejected a non-exempt enum prefix"
