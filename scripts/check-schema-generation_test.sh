#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guard="$repo_root/scripts/check-schema-generation.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/bin"
cat > "$tmp_dir/bin/buf" <<'EOF'
#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    break
  fi
  shift
done
test -n "$output"
for package in v1 agent/v1; do
  root="$output/go/$package"
  mkdir -p "$root"
  printf '%s\n' 'package generated' > "$root/schema.pb.go"
  printf '%s\n' 'package generated' 'type PlainQServiceClient interface {' '}' > "$root/schema_grpc.pb.go"
  printf '%s\n' 'package generated' > "$root/schema_vtproto.pb.go"
done
EOF
chmod +x "$tmp_dir/bin/buf"

# Match a stock GitHub runner: standard POSIX tools are present, ripgrep is not.
test_path="$tmp_dir/bin:/usr/bin:/bin"
if PATH="$test_path" command -v rg >/dev/null 2>&1; then
  echo "test PATH unexpectedly contains rg" >&2
  exit 1
fi

PATH="$test_path" "$guard"
echo "schema generation guard works without ripgrep"
