# SCRAM — status

Written 2026-09-28. Every row cites a commit hash, a test name, or a
measured number. Rows marked **PARTIAL** or **NOT STARTED** say what is
missing rather than implying otherwise.

`origin/main` is at `6f837aa`, 19 commits, 2026-09-27 → 2026-09-28.

---

## Phase 0 — state audit

**DONE.** This file. The audit was performed against the code, not against
earlier summaries: `go list -m all`, `grep -rhoE '^func Test…'`, the
registry in `internal/resolve/resolve.go`, and the CLI's own `--help`
output were all read directly.

The audit found that five Part-1 features (`blame`, `why`, `trend`,
`badge`, `sparkline`) already existed as real packages with real commands,
which the earlier summaries had understated.

## Phase 1 — validation sections

| Item | Status | Evidence |
|---|---|---|
| 1a. Mutation audit | **DONE** | `146cf66`; `scripts/mutation_audit.py`; 16/16 mutants killed, 0 survived |
| 1a. Vacuous test found and fixed | **DONE** | `TestEscalationByCount`; `146cf66` |
| 1b. Differential vs syft/grype | **DONE** | `160f3e6`; `scripts/differential.py`, `scripts/diff_vulns.py` |
| 1b. REPRODUCIBILITY.md | **DONE** | `REPRODUCIBILITY.md`; 15 repos, list read from `differential.json` |
| 1c. Benchmarks (NFR-1) | **DONE** | `cacb9c4`; `BENCHMARKS.md`; 9 benchmarks |
| 1c. ~500-dependency repo, cold+warm | **DONE** | `BENCHMARKS.md`; `yargs/yargs` 492 components: 6,022 ms cold, 2,256 ms warm, 30 ms SBOM-only; NFR-1 (<30s) met |
| 1d. Nightly fuzz workflow | **NOT STARTED** | `.github/workflows/` contains only `ci.yml` |
| 1d. Corpus/invariant job on every PR | **PARTIAL** | `internal/resolve/invariant_test.go` runs in `ci.yml` via `go test ./...`, but as part of the test job, not a named gate |
| 1d. TESTING.md / CONTRIBUTING.md rules | **PARTIAL** | `CONTRIBUTING.md` has resolver/fixture rules; **`TESTING.md` does not exist** |

## Phase 2 — unreviewed features

| Feature | Status | Evidence |
|---|---|---|
| `blame` — review | **DONE** | `a33c1ba`; 2 real bugs found and fixed |
| `blame` — re-add bug | **DONE** | `a33c1ba`; `TestBlameReportsAReaddAfterRemoval` |
| `blame` — shallow clone | **DONE** | `a33c1ba`; `TestBlameReportsShallowClone` |
| `blame` — mutation audit of new tests | **DONE** | both fixes revert-to-red, recorded in `a33c1ba` message |
| `blame` — real-repo verification | **DONE** | checked by hand against `git log --oneline -- requirements.txt`; SHAs match |
| `why` — review | **PARTIAL** | runs, output inspected on a real corpus repo; no git-history input, so no edge cases apply; not mutation-audited |
| `trend` / sparkline | **PARTIAL** | renders in `scram scan`; not audited for edge cases |
| `badge` — review | **DONE** | verified on real scan JSON, `6f837aa`; correct output `36/100 low` |
| Self-score in CI | **PARTIAL** | `internal/badge` works; **not wired into `ci.yml`** |
| Abandonment prediction | **NOT STARTED** | correctly out of scope; nothing built |

### Bugs found in Phase 2

Both in `blame`, both found by building real git histories rather than by
reading tests:

1. A dependency removed and re-added at the same version was reported once,
   with `introduced` pointing at its **first** appearance. Cause: the
   removed-commit branch did `continue` without clearing the
   "version at the previous commit" variable.
2. A shallow clone reported `introduced 6.7y ago` from its single commit.
   Now detected with `git rev-parse --is-shallow-repository`; the label
   becomes `first seen` and a warning is printed **above** the answer.

## Phase 3 — professionalization A–G

| Item | Status | Evidence |
|---|---|---|
| A. goreleaser | **NOT STARTED** | no `.goreleaser.yml` |
| A. cosign signing | **NOT STARTED** | — |
| A. SLSA provenance | **NOT STARTED** | — |
| A. SBOM attached to releases | **NOT STARTED** | `scram sbom generate` works; not wired |
| B. Go/OS CI matrix | **NOT STARTED** | `ci.yml` is single-version, single-OS |
| B. golangci-lint | **NOT STARTED** | no `.golangci.yml` |
| B. govulncheck | **NOT STARTED** | — |
| B. Coverage reporting | **NOT STARTED** | no badge, no service configured |
| C. CODE_OF_CONDUCT.md | **NOT STARTED** | — |
| C. GOVERNANCE.md | **NOT STARTED** | — |
| C. ROADMAP.md | **NOT STARTED** | — |
| C. CODEOWNERS | **NOT STARTED** | — |
| C. SUPPORT.md | **NOT STARTED** | — |
| D. ADRs in `docs/adr/` | **NOT STARTED** | `docs/` exists but holds no ADRs; `DECISIONS.md` has D01–D40 |
| E. mkdocs site | **NOT STARTED** | — |
| F. Renovate/Dependabot | **NOT STARTED** | — |
| G. LICENSE | **DONE** | Apache-2.0 present; **year/holder not verified against the real owner** |

## Phase 5 — final verification

| Item | Status | Evidence |
|---|---|---|
| Cold-clone build | **DONE** | re-verified 2026-09-28 from a fresh `git clone`: build, vet, gofmt, 14 packages green, corpus 86 files / 30,885 components |
| Cold-clone full test suite | **DONE** | 210 test functions, all packages green |
| README link + anchor check | **DONE** | `e08859c`; 0 broken links, 0 broken anchors |
| Resolver walkthrough executed | **DONE** | `6f837aa`; 4 steps applied, verified, reverted |
| Self-scan | **DONE** | resolves 6 components, no findings |
| Secret scan | **DONE** | clean at every push |
| GitHub Actions runs | **UNVERIFIED** | `gh` is not installed and the repo is private; see "Blockers" |
| Signing / provenance | **UNVERIFIED** | requires a real tag, which is forbidden here |
| Pages deploy / Homebrew | **UNVERIFIED** | same |

---

## Blockers

1. **`gh` is not installed**, so the Actions run on `origin/main` cannot be
   inspected. CI status is **unverified**, not "passing".
2. **The repository is private.** `https://api.github.com/repos/0xsan7/SCRAM`
   returns 404 unauthenticated and `raw.githubusercontent.com` returns 404,
   while `git push` succeeds using a stored credential for user `232798030`.
   This is why commits do not appear on the `0xsan7` contribution graph —
   see `OVERNIGHT_REPORT.md` for the full explanation.
3. **No release automation can be verified end to end** without a tag, and
   cutting one is out of scope by instruction. Everything in Phase 3A is
   therefore config-only until a human cuts the first tag.

## Gaps carried forward

- **`why` and `trend` have not been mutation-audited.** `blame` has; the
  other two have only been run.
- **The test suite is green but CI is unobserved.** A CI-only failure (a
  missing tool, a workflow syntax error) would not show up locally.
