# SCRAM — status

Written 2026-09-28. Every row cites a commit hash, a test name, or a
measured number. Rows marked **PARTIAL** or **NOT STARTED** say what is
missing rather than implying otherwise.

`origin/main` is at `6f837aa`, 19 commits, 2026-09-27 → 2026-09-28.

---


### JSON consumers: `schema_version` is now 2.0.0

`summary.repo_score` changed meaning and kept its name. It is now a presented
score out of **65**; it used to be a raw total out of **100**. A consumer
written against `1.0.0` keeps parsing it successfully and keeps rendering
`25/100`, which is wrong by 35%, with nothing in the document to contradict
it — so this is a **major** version bump, not a minor one.

Two things changed in the JSON:

- `summary.repo_score_max` was **added**. It carries the denominator, so the
  scale is a fact in the data instead of something a reader has to know. Read
  `repo_score_max` rather than assuming any maximum.
- `repo_bucket` boundaries moved with the scale: critical 58–65, high 45–57,
  medium 26–44, low 1–25, clean 0. Previously 90/70/40/1 on the old scale.

`repo_score` is still the same underlying severity ordering, so a consumer
that only *sorts* by it is unaffected. One that renders a fraction is not.
`scram badge` reads a scan document, so it picked this up automatically and
now emits `25/65`.

## BREAKING: scores are now out of 65, not 100

**Any score printed by SCRAM after this commit is not comparable to one
printed by v0.1.0 or earlier.** This is a presentation change, not a
detection change — the same vulnerabilities are found, the same terms are
computed, and the ranking of projects relative to each other is unchanged.
But the number a user sees has a different denominator, and CI jobs,
dashboards or policy files that hard-code a score threshold need checking.

| | before | after |
|---|---|---|
| denominator | 100 | 65 |
| the lodash demo project | 37/100 | 37/65 |
| a clean-looking tree | 39/100 | 25/65 |
| bucket boundaries | 90 / 70 / 40 / 1 | 58 / 45 / 26 / 1 |
| scores changing bucket | — | 69 and 89 only, both upward |

**Why.** `scripts/measure_score_terms.sh` runs all six ecosystems and
reports which score terms actually carry data. Severity is the only term
that scores without an opt-in flag; exploitability is the only other that
can, and it returns nothing when FIRST.org is unreachable. Freshness needs
latest-version data this project does not collect, so it is structurally 0
everywhere. Presenting a total out of 100 therefore claimed 35 points of
signal that the tool usually cannot produce, and made a project with real
findings look like it had lost most of a scale it was never competing on.

**Bucket boundaries, and two exceptions.** Boundaries moved
proportionally (90/70/40/1 → 58/45/26/1) and were rounded down. Dividing by
0.65 is monotonic but not bucket-preserving: checked over all 101 inputs,
**two scores change bucket, both upward** — 69 (medium → high) and 89
(high → critical) — and none are demoted. A score just under an old
threshold can land just over the new one, and those are the two that do.
`TestRescalePromotesOnlyTheTwoBoundaryScores` pins the list.

**What did not change.** The formula. Severity, exploitability, maintenance
and freshness are still computed in their own units with the same weights
(40/25/20/15), and `--explain` prints all four plus the 0–100 subtotal they
sum to. Only the denominator the total is reported against changed.

**One bug this surfaced.** `BucketFor` was used in two places to band raw
CVSS v3 scores (`CVSSv3 * 10`, i.e. 0–100) — in drift and in policy, the
two paths that decide whether a pull request fails. That worked only
because the presented scale and the CVSS scale happened to be the same
number. Rescaling would have reported a 9.8 critical as "high". The CVSS
path now has its own function with the specification's boundaries, and
`TestBucketForCVSSKeepsTheSpecificationBoundaries` pins it.

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
| 1b. REPRODUCIBILITY.md | **DONE** | [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md); 15 repos, list read from `docs/differential.json` |
| 1c. Benchmarks (NFR-1) | **DONE** | `cacb9c4`; `BENCHMARKS.md`; 9 benchmarks |
| 1c. ~500-dependency repo, cold+warm | **DONE** | `BENCHMARKS.md`; `yargs/yargs` 492 components: 6,022 ms cold, 2,256 ms warm, 30 ms SBOM-only; NFR-1 (<30s) met |
| 1d. Nightly fuzz + mutation audit | **DONE** | `.github/workflows/fuzz.yml`; targets derived from source (16), nightly 02:17 UTC, runs `scripts/mutation_audit.py`; **verified green**: dispatched at `ca15f8f`, 16 targets enumerated and fuzzed, no crashes; mutation audit `killed 16 survived 0` |
| 1d. Corpus/invariant job on every PR | **PARTIAL** | `internal/resolve/invariant_test.go` runs in `ci.yml` via `go test ./...`, but as part of the test job, not a named gate |
| 1d. TESTING.md / CONTRIBUTING.md rules | **PARTIAL** | `CONTRIBUTING.md` has resolver/fixture rules; **`TESTING.md` does not exist** |
| Score terms measured, not assumed | **DONE** | `scripts/measure_score_terms.sh` runs all six ecosystems and prints the per-term breakdown. Result: severity is the only term that scores without an opt-in flag; exploitability returns nothing when FIRST.org is unreachable; freshness needs latest-version data the project does not collect. This is the evidence behind the 0-65 presented scale |

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
| `badge` — review | **DONE** | verified on real scan JSON, `6f837aa`; correct output `36/65 low` (denominator rescaled; see the BREAKING note at the top) |
| Self-score in CI | **DONE** | `ci.yml` job `dogfood`: builds, scans, renders the badge, uploads it as an artifact |
| Abandonment prediction | **NOT STARTED** | correctly out of scope; nothing built |
| B. Testability workflow | **DONE** | `testability.yml`; coverage + race on main, never gating a PR diff |

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
| A. goreleaser | **DONE** | `.goreleaser.yml`; `goreleaser check` valid, `release --snapshot` builds 5 cross-compiled binaries + checksums + self-generated SBOM; no tag cut |
| A. cosign signing | **PARTIAL** | keyless step in `ci.yml`; the signing loop was verified against real snapshot artifacts (signs 5). Job is `skipped` on non-tag pushes and has never executed |
| A. SLSA provenance | **NOT STARTED** | — |
| A. SBOM attached to releases | **DONE** | generated in a `.goreleaser.yml` before-hook and attached via `extra_files`; both formats verified in the snapshot output |
| B. Go/OS CI matrix | **DONE** | `ci.yml` job `build`: 3 OSes x Go 1.23/1.24, `fail-fast: false`; **verified green** at `ca15f8f` |
| B. golangci-lint | **DONE** | `.golangci.yml`; clean on pinned v1.64.5. Found 5 real defects, incl. D41 (a rename that disabled the fail-closed path) |
| B. govulncheck | **DONE** | `ci.yml` job `govulncheck`, scheduled (queries the Go vuln DB, so not on every PR); **not yet fired** — the schedule is nightly and has not come round |
| B. Coverage reporting | **DONE** | `.github/workflows/testability.yml`; **green on CI**, measured 67.0% overall, median 83.3%, weakest `cli` 24.5%. No badge, because no service is configured |
| C. CODE_OF_CONDUCT.md | **NOT STARTED** | — |
| C. GOVERNANCE.md | **NOT STARTED** | — |
| C. ROADMAP.md | **NOT STARTED** | — |
| C. CODEOWNERS | **NOT STARTED** | — |
| C. SUPPORT.md | **NOT STARTED** | — |
| D. ADRs | **PARTIAL** | `DECISIONS.md` carries the decisions; a generated index (25 entries, anchors verified) is checked in CI. D06-D21 never existed and the gap is documented, not back-filled |
| E. mkdocs site | **decided against** 2026-09-29 | `ROADMAP.md`, with the argument both ways and the conditions that would reverse it. (A previous report claimed this was already recorded there; it was not. Corrected.) |
| F. Renovate/Dependabot | **NOT STARTED** | — |
| G. LICENSE | **DONE** | Apache-2.0 with the appendix placeholder `Copyright [yyyy] [name of copyright owner]` replaced |

## Phase 5 — final verification

| Item | Status | Evidence |
|---|---|---|
| Cold-clone build | **DONE** | re-verified 2026-09-28 from a fresh `git clone`: build, vet, gofmt, 14 packages green, corpus 86 files / 30,885 components |
| Cold-clone full test suite | **DONE** | 210 test functions, all packages green |
| README link + anchor check | **DONE** | `e08859c`; 0 broken links, 0 broken anchors |
| Resolver walkthrough executed | **DONE** | `6f837aa`; 4 steps applied, verified, reverted |
| Self-scan | **DONE** | resolves 6 components, no findings |
| Secret scan | **DONE** | clean at every push |
| GitHub Actions runs | **VERIFIED** | read from the Actions REST API on every commit; on the tagged commit 11 jobs green and `govulncheck (self)` correctly skipped (it is schedule-only) |
| Signing / provenance | **VERIFIED** | 5/5 `cosign verify-blob` → `Verified OK` on v0.1.0, downloaded and re-verified locally; a wrong identity is rejected |
| Pages deploy / Homebrew | **NOT BUILT** | no site, no formula; see ROADMAP.md |

---

## Release status — v0.1.0

<https://github.com/0xsan7/SCRAM/releases/tag/v0.1.0>

`prerelease: false`. `releases/latest` resolves to it, which is the first
time either has been true.

18 assets: 5 binaries (darwin/linux × amd64/arm64, windows-amd64.exe),
5 `.sig` + 5 `.pem` signature files, `scram_0.1.0_checksums.txt`, and
CycloneDX + SPDX SBOMs.

Verified by downloading the release assets and running the published
instructions against them:

| Check | Result |
|---|---|
| `shasum -a 256 -c scram_0.1.0-rc3_checksums.txt` | 5/5 `OK` |
| `cosign verify-blob` on each binary | 5/5 `Verified OK` |
| Signature with a wrong identity regexp | correctly **rejected** |
| Release job on the tagged commit | `success` |
| CI / Testability / secret-scan on the tagged commit | `success` ×3 |

### The Action took three release candidates

`v0.1.0-rc1`, `-rc2`, and `-rc3` all remain on the repository and none
should be used. Seven defects in `action.yml`, all of the same kind: a
question about what happens when the file *runs*, which no linter,
schema validator, or unit test in this repository can answer.

| # | Defect | Effect | Found by |
|---|---|---|---|
| 1 | `secrets.GITHUB_TOKEN` in a composite step | runner refuses to load the manifest; the action is unusable | pointing it at a scratch repo |
| 2 | URL `scram-linux-amd64`; GoReleaser publishes `scram-<version>-<os>-<arch>` | both URLs 404 | reading the release asset list |
| 3 | `$OUT_DIR` never created | redirect fails, scanner never runs, reported as "policy check failed" | first end-to-end run |
| 4 | binary name hardcoded to `scram` | Windows gets `scram.exe` | reading the install step |
| 5 | base commit absent from the default depth-1 checkout | `fatal: invalid reference`; **the action cannot run on a PR at all** | running it on a real pull request |
| 6 | `case "$version" in [0-9]*)` | accepts any commit SHA starting with a hex digit (~62%), builds a nonsense asset name | pinning the action to a SHA to test #5 |
| 7 | baseline written as a scan report, not a baseline | `ReadBaseline` finds no top-level `components`, so the gate reports **every pre-existing finding as new** | comparing two baseline files on the same tree |

Defect 7 deserves emphasis: it is the failure that looks like a working
security tool. The gate fires, the comment renders, the numbers are
plausible, and every one of them is wrong in the direction that makes
the tool look useful. It was only visible by running the gate against a
tree with unchanged dependencies and asking why it failed.

### The Action, verified on a GitHub-hosted runner

Push, using the documented minimum and no `with:` block at all:

    - uses: 0xsan7/SCRAM@v0.1.0
    Installing scram-0.1.0-linux-amd64 (action ref: v0.1.0)
    scram-0.1.0-linux-amd64: OK
    scram version 0.1.0
    commit:     de903ac4c09af34b0d1f6d50fecf49884eabcbfb
    PASS  (fail-on: high, new findings only: true)
    repo-score: 36   repo-bucket: low

Pull request, against a `lodash@4.17.11` fixture:

- **unchanged tree** → `PASS`, and the comment reports
  `New vulnerabilities | 0` with all 5 real advisories still present
- **added `minimist@0.0.8`** → `FAIL`, naming exactly one finding —
  `GHSA-xvch-5gv4-984h affects pkg:npm/minimist@0.0.8 (severity
  critical)` — and nothing else, with the pre-existing lodash findings
  correctly suppressed

That pair is the product working. Both halves, on the same repository,
for the first time.

### Checks added so these cannot recur silently

`scripts/check_action_metadata.py` now rejects `secrets.` in any
composite step, and cross-checks the install step's asset name against
`.goreleaser.yml`'s `archives[].name_template`. Mutation-tested,
including the rc1 URL verbatim. It cannot catch defects 3, 5 or 7 --
those need a runner, and the honest conclusion is that this file needs
an end-to-end test, not another static check.

## Gaps carried forward

- **`why` and `trend` have not been mutation-audited.** `blame` has; the
  other two have only been run.
