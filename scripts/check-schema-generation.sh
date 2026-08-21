#!/usr/bin/env bash
set -euo pipefail
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
buf generate schema --template schema/buf.gen.yaml --output "$tmp_dir"
generated_root="$tmp_dir/go"
for pkg in v1 agent/v1; do
  package_root="$generated_root/$pkg"
  test -n "$(find "$package_root" -maxdepth 1 -name '*.pb.go' ! -name '*_grpc.pb.go' ! -name '*_vtproto.pb.go' -print -quit)"
  grpc_file="$(find "$package_root" -maxdepth 1 -name '*_grpc.pb.go' -print -quit)"
  vt_file="$(find "$package_root" -maxdepth 1 -name '*_vtproto.pb.go' -print -quit)"
  test -n "$grpc_file"
  test -n "$vt_file"
  client_file_count="$(find "$package_root" -maxdepth 1 -name '*.go' -type f \
    -exec grep -l -E 'type .*ServiceClient interface' {} + | wc -l | tr -d '[:space:]')"
  test "$client_file_count" -eq 1
  grep -q -E 'type .*ServiceClient interface' "$grpc_file"
  if grep -q -E 'type .*ServiceClient interface' "$vt_file"; then exit 1; fi
done
