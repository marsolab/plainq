#!/bin/sh

set -eu

chart_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT INT TERM

render_and_assert() {
  mode=$1
  output=$2
  shift 2

  helm template task7 "$chart_dir" "$@" \
    --set auth.existingSecret=plainq-auth \
    --set auth.secretKey=jwt-signing \
    --set auth.bootstrap.existingSecret=plainq-auth \
    --set auth.bootstrap.secretKey=remote-bootstrap \
    --set auth.bootstrap.secret=bootstrap-cleartext-sentinel-32-bytes >"$output"

  grep -F -- '- -auth.bootstrap.secret=$(PLAINQ_BOOTSTRAP_SECRET)' "$output" >/dev/null
  grep -F -- '- name: PLAINQ_BOOTSTRAP_SECRET' "$output" >/dev/null
  grep -F -- 'name: plainq-auth' "$output" >/dev/null
  grep -F -- 'key: remote-bootstrap' "$output" >/dev/null

  if grep -F -- 'bootstrap-cleartext-sentinel' "$output" >/dev/null; then
    echo "$mode render disclosed the bootstrap secret" >&2
    exit 1
  fi
}

render_and_assert install "$test_dir/install.yaml"
render_and_assert upgrade "$test_dir/upgrade.yaml" --is-upgrade

if helm template task7 "$chart_dir" \
  --set auth.existingSecret=plainq-auth \
  --set auth.secretKey=jwt-signing >"$test_dir/missing-bootstrap.yaml" 2>"$test_dir/missing-bootstrap.err"; then
  echo "auth-enabled render succeeded without a bootstrap Secret" >&2
  exit 1
fi

grep -F -- 'no bootstrap secret was provided' "$test_dir/missing-bootstrap.err" >/dev/null
