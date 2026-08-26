#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/plainq"

fail() {
  echo "helm health render check failed: $*" >&2
  exit 1
}

assert_contains() {
  local rendered="$1"
  local expected="$2"
  grep -Fq -- "$expected" <<<"$rendered" || fail "missing ${expected}"
}

assert_not_contains() {
  local rendered="$1"
  local unexpected="$2"
  if grep -Fq -- "$unexpected" <<<"$rendered"; then
    fail "unexpected ${unexpected}"
  fi
}

rendered="$({
  helm template plainq "$chart_dir" \
    --set auth.enabled=false \
    --set config.healthRoute=/ready-custom \
    --set config.healthLivenessRoute=/live-custom
})"
assert_contains "$rendered" "-health=true"
assert_contains "$rendered" "-health.route=/ready-custom"
assert_contains "$rendered" "-health.liveness.route=/live-custom"
assert_contains "$rendered" "livenessProbe:"
assert_contains "$rendered" "path: /live-custom"
assert_contains "$rendered" "readinessProbe:"
assert_contains "$rendered" "path: /ready-custom"

rendered="$({
  helm template plainq "$chart_dir" \
    --set auth.enabled=false \
    --set config.healthEnabled=false
})"
assert_contains "$rendered" "-health=false"
assert_not_contains "$rendered" "livenessProbe:"
assert_not_contains "$rendered" "readinessProbe:"

rendered="$({
  helm template plainq "$chart_dir" \
    --set auth.enabled=false \
    --set-json livenessProbe=null \
    --set-json readinessProbe=null
})"
assert_not_contains "$rendered" "livenessProbe:"
assert_not_contains "$rendered" "readinessProbe:"

rendered="$({
  helm template plainq "$chart_dir" \
    --set auth.enabled=false \
    --set config.healthEnabled=false \
    --set-json 'livenessProbe={"exec":{"command":["/bin/true"]}}' \
    --set-json 'readinessProbe={"tcpSocket":{"port":"http"}}'
})"
assert_contains "$rendered" "livenessProbe:"
assert_contains "$rendered" "command:"
assert_contains "$rendered" "/bin/true"
assert_contains "$rendered" "readinessProbe:"
assert_contains "$rendered" "tcpSocket:"

echo "helm health render checks passed"
