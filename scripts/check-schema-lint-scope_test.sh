#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guard="$repo_root/scripts/check-schema-lint-scope.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/bin"
cat > "$tmp_dir/bin/buf" <<'EOF'
#!/bin/sh
case " $* " in
  *" --error-format=json "*)
    printf '%s\n' '{"type":"ENUM_VALUE_PREFIX","message":"enum value prefix"}' >&2
    exit 1
    ;;
  *)
    exit 0
    ;;
esac
EOF
chmod +x "$tmp_dir/bin/buf"

# Deliberately omit Homebrew and other locations that may contain ripgrep.
# The guard only needs a POSIX literal search and must work on a stock runner.
test_path="$tmp_dir/bin:/usr/bin:/bin"
if PATH="$test_path" command -v rg >/dev/null 2>&1; then
  echo "test PATH unexpectedly contains rg" >&2
  exit 1
fi

output="$(PATH="$test_path" "$guard")"
printf '%s\n' "$output" | grep -F -q \
  'Buf lint accepted the scoped agent.v1 exception and rejected a non-exempt enum prefix'

echo "schema lint scope guard works without ripgrep"
