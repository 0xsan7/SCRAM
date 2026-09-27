#!/usr/bin/env bash
# Builds a throwaway git repo with a real, multi-commit dependency history so
# `scram blame` is exercised end to end against actual commits rather than a
# mock. Used for manual verification; the Go tests build their own repos.
set -euo pipefail
DIR="${1:-/tmp/scram-blame-demo}"
rm -rf "$DIR" && mkdir -p "$DIR" && cd "$DIR"

git init -q -b main
git config user.name "Priya Raman"
git config user.email "priya@example.com"
git config commit.gpgsign false

# The date vars must sit directly on `git commit`; putting them on the `git add`
# that precedes it scopes them to the wrong process and the commit records the
# current time instead, which makes the demo print "0m ago" for a 22-month-old
# commit.
commit() {  # commit <ISO-8601 date> <message>
  git add -A
  GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" git commit -q -m "$2"
}

# 22 months ago: a reasonable choice, safe at the time.
cat > package-lock.json <<'JSON'
{"lockfileVersion":3,"packages":{
  "":{"name":"acme-api","dependencies":{"express":"^4.18.0"}},
  "node_modules/express":{"version":"4.18.2"},
  "node_modules/lodash":{"version":"4.17.11"}}}
JSON
commit "2024-01-15T09:00:00Z" "feat: scaffold API service"

# 14 months ago: an unrelated lockfile churn (left-pad arrives). lodash is NOT
# changed, so it must not show up in lodash's history.
cat > package-lock.json <<'JSON'
{"lockfileVersion":3,"packages":{
  "":{"name":"acme-api","dependencies":{"express":"^4.18.0"}},
  "node_modules/express":{"version":"4.18.2"},
  "node_modules/lodash":{"version":"4.17.11"},
  "node_modules/left-pad":{"version":"1.3.0"}}}
JSON
commit "2024-09-02T14:30:00Z" "chore: add left-pad"

# 6 months ago: a real bump, motivated by an advisory.
cat > package-lock.json <<'JSON'
{"lockfileVersion":3,"packages":{
  "":{"name":"acme-api","dependencies":{"express":"^4.18.0"}},
  "node_modules/express":{"version":"4.18.2"},
  "node_modules/lodash":{"version":"4.17.21"},
  "node_modules/left-pad":{"version":"1.3.0"}}}
JSON
commit "2025-03-18T11:15:00Z" "fix: bump lodash to 4.17.21 for prototype pollution advisory"

echo "Demo repo ready at $DIR"
git log --oneline
