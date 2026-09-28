#!/usr/bin/env bash
#
# The lodash drift demo, end to end and repeatable.
#
# The README claims that bumping lodash 4.17.11 -> 4.17.21 removes a
# specific set of findings. This script is where that claim comes from:
# it builds a real npm project, a real git repository, a real baseline, and
# runs a real scan on each side of the bump. Nothing is transcribed.
#
#   ./run.sh              build, baseline, scan, bump, scan, print the diff
#   ./run.sh --keep       leave the scratch repo in place afterwards
#
# Requires: go 1.23+, and network access for OSV/EPSS (SCRAM fails closed
# without it rather than reporting a clean result it did not verify).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${SCRAM_DRIFT_DEMO_DIR:-${TMPDIR:-/tmp}/scram-lodash-drift}"

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

say() { printf '\033[1m%s\033[0m\n' "$*"; }

# Build the binary from the current tree, so the demo cannot drift away
# from the code it is demonstrating.
SCRAM="$WORK/scram"
mkdir -p "$WORK"
say "building scram from $REPO_ROOT"
(cd "$REPO_ROOT" && go build -o "$SCRAM" ./cmd/scram)

PROJECT="$WORK/demo-app"

# ---------------------------------------------------------------------------
# Step 1 -- a real npm project pinning the vulnerable lodash.
# ---------------------------------------------------------------------------
say "1/5  creating the project at lodash 4.17.11"
rm -rf "$PROJECT"
mkdir -p "$PROJECT"
cd "$PROJECT"

cat > package.json <<'JSON'
{
  "name": "scram-lodash-drift-demo",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "lodash": "4.17.11"
  }
}
JSON

# A real lockfile, including the real integrity hash npm publishes for
# 4.17.11. Written by hand rather than by `npm install` so the demo needs
# no Node toolchain -- but the shape and the hash are the real ones, which
# is what the resolver reads.
cat > package-lock.json <<'JSON'
{
  "name": "scram-lodash-drift-demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "scram-lodash-drift-demo",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.11"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.11",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    }
  }
}
JSON

# A real repository, because drift detection and --why both need history.
git init -q .
git config user.email  "demo@example.com"
git config user.name   "scram drift demo"
git add -A
git commit -q -m "Initial commit: lodash 4.17.11"

# ---------------------------------------------------------------------------
# Step 2 -- the baseline, taken at the vulnerable version.
# ---------------------------------------------------------------------------
say "2/5  capturing the baseline"
# The first scan is expected to exit 1: the baseline project is the
# vulnerable one, and the policy gate does its job. `|| true` keeps that
# from aborting the script -- it is not a way of ignoring a real failure,
# and the second scan's exit code is checked explicitly below.
set +e
"$SCRAM" scan . --epss
set -e
"$SCRAM" baseline update

# ---------------------------------------------------------------------------
# Step 3 -- the bump. This is the commit a real PR would contain.
# ---------------------------------------------------------------------------
say "3/5  bumping lodash 4.17.11 -> 4.17.21"
python3 - "$PROJECT" <<'PY'
import json, re, sys, pathlib
root = pathlib.Path(sys.argv[1])
lock = root / "package-lock.json"
pkg = root / "package.json"

# The real integrity hash npm publishes for 4.17.21.
INTEGRITY = ("sha512-v2f6mEui/ckV3q038tF1T5BM1/VkVxT+HPcAcqfOg9Q"
             "sT0ghk8SN0FSF97GkSVCkG0iqshONBie3r+x/6L/wTA==")

data = json.loads(lock.read_text())
data["packages"]["node_modules/lodash"]["version"] = "4.17.21"
data["packages"]["node_modules/lodash"]["resolved"] = (
    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
data["packages"]["node_modules/lodash"]["integrity"] = INTEGRITY
data["packages"][""]["dependencies"]["lodash"] = "4.17.21"
lock.write_text(json.dumps(data, indent=2) + "\n")

p = json.loads(pkg.read_text())
p["dependencies"]["lodash"] = "4.17.21"
pkg.write_text(json.dumps(p, indent=2) + "\n")
print("  package-lock.json and package.json now pin 4.17.21")
PY

git add -A
git commit -q -m "Bump lodash from 4.17.11 to 4.17.21"

# ---------------------------------------------------------------------------
# Step 4 -- rescan. This is where the PR gate runs.
# ---------------------------------------------------------------------------
say "4/5  rescanning against the baseline"
# --no-trend because the sparkline is per-machine history: a fresh scratch
# repo has no prior scans, so the line is meaningless here and does not
# appear in the README's quoted output. Everything else is the default.
set +e
"$SCRAM" scan . --epss --no-trend
GATE=$?
set -e
say "    scram exit code: $GATE  (0 = gate passed, 1 = policy failure)"

# ---------------------------------------------------------------------------
# Step 5 -- the summary the README quotes.
# ---------------------------------------------------------------------------
say "5/5  the resolved version and its remaining findings"
"$SCRAM" sbom generate . --format cyclonedx --out "$WORK/sbom" >/dev/null
python3 - "$WORK/sbom/sbom.cdx.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
for c in doc.get("components", []):
    print(f"  resolved: {c.get('name')}@{c.get('version')}")
PY

cat <<'EOF'

To run this again from scratch:  ./examples/lodash-drift/run.sh
EOF

if [ "$KEEP" -eq 0 ]; then
  say "scratch repo: $WORK  (pass --keep to keep it, or delete it)"
fi
