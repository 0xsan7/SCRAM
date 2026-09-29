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
| 1b. REPRODUCIBILITY.md | **DONE** | [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md); 15 repos, list read from `docs/differential.json` |
| 1c. Benchmarks (NFR-1) | **DONE** | `cacb9c4`; `BENCHMARKS.md`; 9 benchmarks |
| 1c. ~500-dependency repo, cold+warm | **DONE** | `BENCHMARKS.md`; `yargs/yargs` 492 components: 6,022 ms cold, 2,256 ms warm, 30 ms SBOM-only; NFR-1 (<30s) met |
| 1d. Nightly fuzz + mutation audit | **DONE** | `.github/workflows/fuzz.yml`; targets derived from source (16), nightly 02:17 UTC, runs `scripts/mutation_audit.py`; **verified green**: dispatched at `ca15f8f`, 16 targets enumerated and fuzzed, no crashes; mutation audit `killed 16 survived 0` |
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
| Signing / provenance | **VERIFIED** | 5/5 `cosign verify-blob` → `Verified OK` against the published release |
| Pages deploy / Homebrew | **NOT BUILT** | no site, no formula; see ROADMAP.md |

---

## Release status — v0.1.0-rc1

Published and verified. <https://github.com/0xsan7/SCRAM/releases/tag/v0.1.0-rc1>

18 assets: 5 binaries (darwin/linux × amd64/arm64, windows-amd64.exe),
5 `.sig` + 5 `.pem` signature files, `scram_0.1.0-rc1_checksums.txt`,
and CycloneDX + SPDX SBOMs.

Verified by downloading the release assets and running the published
instructions against them, not by reading the CI badge:

| Check | Result |
|---|---|
| `shasum -a 256 -c scram_0.1.0-rc1_checksums.txt` | 5/5 `OK` |
| `cosign verify-blob` on each of the 5 binaries | 5/5 `Verified OK` |
| Signature with a wrong `--certificate-identity-regexp` | correctly **rejected** |
| Certificate subject | `https://github.com/0xsan7/SCRAM/.github/workflows/ci.yml@refs/tags/v0.1.0-rc1` |
| `scram --version` with the release ldflags | `v0.1.0-rc1`, commit, and date all populated |
| Release job on the tagged commit | `success` |
| CI / Testability / secret-scan on the tagged commit | `success` / `success` / `success` |

### What the first tag exposed

The release path had never been executed. Five real defects surfaced,
each of which had passed every local check because the local checks
skipped the broken part:

1. **No `tags:` trigger** — the workflow only fired on `push` to `main`,
   so the release job's `if: startsWith(github.ref, 'refs/tags/v')` was
   a gate on a job that was never scheduled. The tag did nothing.
2. **`-X main.commit` / `-X main.date`** — neither symbol exists. The
   linker accepts a `-X` for an unknown path and discards it, so release
   binaries reported a version and nothing else. Now stamped into
   `internal/cli` and printed by `--version`, with a test that builds
   the binary and fails if a stamp does not appear.
3. **cosign not installed, then installed too late** — the first run
   failed with `executable file not found`; adding the install step in
   the position the old signing step had left produced the *same*
   error, because that position is after GoReleaser. The step now runs
   first and ends with `cosign version`, so a broken install names
   itself.
4. **A signature upload glob matching zero files** — `dist/*.pem` is one
   level deep; GoReleaser writes signatures to `dist/scram_<target>/`.
   `fail_on_unmatched_files: false` meant the step exited 0 having
   uploaded nothing. GoReleaser was already publishing all ten signature
   files itself, so the step was removed entirely.
5. **A release footer using artifact-only template keys** — `{{ .Os }}`
   and `{{ .Arch }}` are not in scope for a release footer. GoReleaser
   builds, signs, and generates the changelog, then fails while
   publishing the notes: everything works and the release still does not
   happen.

The tag was moved four times during this, each move recorded in the tag
message itself. No published artifact was retracted, because none
existed until the final move. Commit `a0cb565` records the reasoning.

## Gaps carried forward

- **`why` and `trend` have not been mutation-audited.** `blame` has; the
  other two have only been run.
