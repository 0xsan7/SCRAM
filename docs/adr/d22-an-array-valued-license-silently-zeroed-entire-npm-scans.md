# D22 — An array-valued `license` silently zeroed entire npm scans

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D22

**Title:** An array-valued `license` silently zeroed entire npm scans

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Found by:** running the resolver against real lockfiles fetched from six
upstream projects, not against fixtures written by hand.

`nestjs/nest` is a 1676-package project. It failed to parse at all:

    json: cannot unmarshal array into Go struct field lockPkg.packages.license of type string

Real-world evidence from that lockfile:

    "node_modules/pause-stream": { "license": ["MIT", "Apache2"] }

npm accepts either a string or an array of license identifiers. Declaring the
field as `string` made `json.Unmarshal` fail on the ENTIRE document, so all
1676 packages resolved to zero — and a scan of zero components prints
`CLEAN` on the terminal. One dual-licensed dependency cost a whole repository
its entire scan, silently.

**Rule:** a parser must not let one unexpected field invalidate a document it
has otherwise understood. Fields that vary in shape get a tolerant type
(`flexString` in `internal/resolve/npm.go`), and a lockfile that yields zero
components from a non-empty file is a test failure, not a passing scan.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
