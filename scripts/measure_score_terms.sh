#!/usr/bin/env bash
# Measure the scoring terms across real projects, to check the presented
# scale against the signal that is actually implemented.
#
# This is a measurement script, not a test: it prints a table. It exists so
# that claims about which score terms carry signal are observed rather than
# assumed.
set -uo pipefail
export PATH="$HOME/.local/go/bin:$PATH"
SCRAM="${1:-/tmp/wk/scram}"
FX="${2:-$HOME/scram/testdata/fixtures}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf '%-8s %7s %6s %-8s %s\n' project comps score bucket 'terms'
printf '%s\n' '----------------------------------------------------------------'

measure() {
  local eco="$1" file="$2"
  local hit
  hit=$(find "$FX/$eco/real" -name "$file" -type f 2>/dev/null | head -1)
  if [ -z "$hit" ]; then
    printf '%-8s %s\n' "$eco" "(no $file in the corpus)"
    return
  fi
  local d="$WORK/$eco"
  mkdir -p "$d"
  cp "$hit" "$d/"
  local out
  out=$(cd "$d" && "$SCRAM" scan . --format json --no-gate 2>/dev/null)
  if [ -z "$out" ]; then
    printf '%-8s %s\n' "$eco" "(scan produced nothing)"
    return
  fi
  local comps score bucket purl terms
  comps=$(printf '%s' "$out" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["scan"]["components"]))' 2>/dev/null)
  score=$(printf '%s' "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["scan"]["summary"]["repo_score"])' 2>/dev/null)
  bucket=$(printf '%s' "$out" | python3 -c 'import json,sys;print(json.load(sys.stdin)["scan"]["summary"]["repo_bucket"])' 2>/dev/null)
  # A component carrying findings shows non-zero terms; a clean one shows
  # all zeros, which measures nothing about availability.
  purl=$(cd "$d" && "$SCRAM" scan . --format json --no-gate 2>/dev/null \
    | python3 -c '
import json,sys
cs=json.load(sys.stdin)["scan"]["components"]
tgt=None
for c in cs:
    if c.get("vulnerabilities") or c.get("findings"):
        tgt=c; break
print((tgt or cs[0])["purl"] if cs else "")')
  if [ -z "$purl" ]; then
    printf '%-8s %7s %6s %-8s %s\n' "$eco" "${comps:-?}" "${score:-?}" "${bucket:-?}" "(no component)"
    return
  fi
  terms=$(cd "$d" && "$SCRAM" scan . --no-gate --explain "$purl" 2>/dev/null \
    | grep -E '^  (severity|exploitability|maintenance|freshness)' \
    | sed 's/^ *//; s/  */ /g' | paste -sd' | ' -)
  printf '%-8s %7s %6s %-8s %s\n' "$eco" "${comps:-?}" "${score:-?}" "${bucket:-?}" "${terms:-(none)}"
}

measure npm   package-lock.json
measure yarn  yarn.lock
measure pnpm  pnpm-lock.yaml
measure cargo Cargo.lock
measure gomod go.sum
measure pypi  requirements.txt
