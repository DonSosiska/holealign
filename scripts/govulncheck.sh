#!/usr/bin/env bash
# Vulnerability check for the shipped binaries.
#
# Source-mode govulncheck (./...) walks the call graph of every package in the
# module graph and does not finish in CI. Binary mode checks the module versions
# compiled into each binary, which takes seconds. This script builds the agent
# and server, runs govulncheck in binary mode on each, and fails if a finding is
# not listed in .govulncheck-allow.
set -euo pipefail
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

allow_file="$repo_root/.govulncheck-allow"
if [[ ! -f "$allow_file" ]]; then
  echo "error: $allow_file not found" >&2
  exit 1
fi
for tool in go govulncheck jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found (govulncheck: go install golang.org/x/vuln/cmd/govulncheck@v1.9.0)" >&2
    exit 1
  fi
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CGO_ENABLED=0 go build -trimpath -o "$tmp/" ./cmd/...

findings="$tmp/findings.txt"
: > "$findings"
for bin in "$tmp"/*; do
  [[ -f "$bin" && -x "$bin" ]] || continue
  name="$(basename "$bin")"
  out="$tmp/$name.json"
  rc=0
  govulncheck -mode=binary -format json "$bin" > "$out" || rc=$?
  # govulncheck exits 3 when it reports findings; anything else is a real failure.
  if (( rc != 0 && rc != 3 )); then
    echo "error: govulncheck failed on $name (exit $rc)" >&2
    exit 1
  fi
  # The JSON output is a stream of objects; keep the OSV IDs of findings only.
  jq -r 'select(.finding) | .finding.osv' "$out" >> "$findings"
done

ids="$tmp/ids.txt"
allow="$tmp/allow.txt"
sort -u "$findings" | grep -v '^$' > "$ids" || true
awk '{ sub(/#.*/, ""); if (NF) print $1 }' "$allow_file" | sort -u > "$allow"

seen="$(grep -xF -f "$allow" "$ids" || true)"
unexpected="$(grep -vxF -f "$allow" "$ids" || true)"
stale="$(grep -vxF -f "$ids" "$allow" || true)"

echo "govulncheck (binary mode): $(grep -c . "$ids" || true) distinct finding(s)"
if [[ -n "$seen" ]]; then
  echo "allowlisted (see .govulncheck-allow):"
  while IFS= read -r id; do echo "  $id"; done <<< "$seen"
fi

if [[ -n "$stale" ]]; then
  echo "warning: allowlist entries no longer reported, remove them from .govulncheck-allow:" >&2
  while IFS= read -r id; do echo "  $id" >&2; done <<< "$stale"
fi

if [[ -n "$unexpected" ]]; then
  echo "error: vulnerabilities not listed in .govulncheck-allow:" >&2
  while IFS= read -r id; do echo "  $id" >&2; done <<< "$unexpected"
  echo "hint: upgrade the affected module, or if no fix exists and the risk is reviewed," >&2
  echo "      add 'ID  # reason, reviewed YYYY-MM-DD' to .govulncheck-allow (see docs/development.md)." >&2
  echo "      details: govulncheck -mode=binary <binary>" >&2
  exit 1
fi

echo "ok: no unreviewed vulnerabilities"
