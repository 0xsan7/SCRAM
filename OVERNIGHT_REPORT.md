# Overnight report

Written 2026-09-28, covering the session that began with the README
rewrite (`e08859c`) and ended at `29ac2db`.

**Four commits, all pushed. `origin/main` is at `29ac2db`, 0 ahead, 0
behind.** No tag was cut, no release published, no repository setting
changed.

---

## The contribution graph is empty, and here is why

`0xsan7/SCRAM` is a **private repository**. `https://api.github.com/repos/0xsan7/SCRAM`
returns 404 unauthenticated, which is what GitHub does for a private repo.

Private-repository commits only appear on your profile's contribution graph
if **Settings → Public profile → Private contributions** is set to
**"Make private contributions 'Private' and 'Include private contributions
on my profile"**. Until that is on, the squares stay grey no matter how
many commits land.

A second thing worth knowing: `git config credential.helper` is
`osxkeychain`, and the stored credentials for `github.com` belong to
account **`232798030`**, not `0xsan7`. The push works because that account
has write access to the repository, but the commits you make in this
working tree are attributed to whichever identity is in `git config
user.email`. Both are `santiagojerald734@gmail.com` right now, so the
author line is consistent with `0xsan7` — but if the two accounts have
different emails on file, commits made under the wrong one will not
attribute at all.

This is the one item here that needs a click in the GitHub UI rather than a
change in the repository.

---

## What I fixed

### 1. The README rewrite had never been pushed

Not lost — local `HEAD` was correct at `e08859c` while `origin/main` was
still 17 commits behind at the MVP commit `842d9bc`. You were reading
GitHub. Pushed.

### 2. The GitHub Action never produced a SARIF file

`upload-sarif` was declared as an input with **no step consuming it**.
Setting it to `true` did nothing at all.

Root cause worth knowing: **`--format sarif` writes to stdout, not to
`--out`.** `--out` is the SBOM directory, and the machine-readable formats
keep stdout a single valid document on purpose. So the file the upload step
needed did not exist and never had.

Two steps added. The producing step validates its own output before
handing it over, because GitHub drops an invalid SARIF upload silently and
that is indistinguishable from "no vulnerabilities found" — a security
tool reporting clean because its output was malformed is the same failure
class as everything else in this project. Verified locally: valid 2.1.0,
one run, 5 results.

The README's `sarif_file` pointed at `scan.json`, which is JSON, not
SARIF. Now `scan.sarif`, verified to be real SARIF.

### 3. The "Adding a resolver" walkthrough did not work

I followed it literally as a dummy resolver. It failed twice before
working, and the README was missing three things:

- **Declaring the ecosystem is not sufficient.** `osvEcosystem` returns
  `false` for unknown ecosystems, so without that third step your
  components are detected, scored, and shipped — and silently never
  vulnerability-matched, with a *warning* rather than a failure. Verified
  both directions.
- **`detect.go` uses string literals.** The documented `model.EcoDummy`
  line does not compile; the package does not import `model`.
- **`TestResolverRegistry` asserts `len(Supported()) == 3`** and that
  cargo is unregistered, so the fourth ecosystem fails a test that is
  correct today.

All four steps are now applied, verified end to end (SBOM both formats,
SARIF, drift, scoring), and reverted.

### 4. Enabling golangci-lint found five real defects

The one that matters is **D41**. `govet` flagged a shadowed `err` in
`internal/scan/scan.go`. I renamed it with a scripted regex; the regex
covered `err != nil` and `return nil, err` but not
`errors.Is(err, resolve.ErrSilentZero)`, so the sentinel check kept
reading the outer, nil `err`. `errors.Is(nil, ...)` is always false, which
made the silent-zero branch unreachable — a resolver that read a
declaring file and returned nothing would have reported **CLEAN with exit
0**. The D01/D22/D23 failure mode, restored by a lint cleanup.

`TestScanFailsWhenResolverReturnsNothingForADeclaringFile` caught it on
the first run. That is the argument for having written it.

Also: three assertions in `sbom_test.go` were written `x != x` where
`x == x` was meant, and `spdxNamespace` had no non-vacuous assertion at
all. Two mutations are now killed that were not before. `epss.go` used
`%v` where `%w` is needed. `osv.go` had a dead `err == io.EOF` clause.
Two test files compared errors with `==` and a type assertion. Six dead
symbols removed.

### 5. Release automation, actually run

`.goreleaser.yml` took five wrong turns, each caught by executing:
`ids:` is not an archive field; `ChangelogGroup` has no `filters:`;
`documents:` takes one entry with `artifacts: binary`; a per-artifact
SBOM step cannot work at all because a darwin/arm64 binary does not
execute on the Linux runner cross-compiling it; and a before-hook writing
into `dist/` loses its output to `--clean`.

Verified with `goreleaser release --snapshot`: 5 cross-compiled binaries,
real checksums, version injection confirmed by running the built binary,
and an SPDX 2.3 + CycloneDX 1.5 pair with 7 packages each, generated by
SCRAM from its own tree.

The cosign loop also had a bug: `dist/scram_*` matches only directories
and the checksums file, so it signed **nothing** and still exited 0. Now
`find`-based with a hard failure on a zero count. Re-run against the real
snapshot: 5 artifacts.

### 6. Measured, not estimated

- **NFR-1 met.** `yargs/yargs`, 492 resolved components: **6,022 ms cold,
  2,256 ms warm, 30 ms SBOM-only.** Against a 30,000 ms target. ~99.5% of
  a cold scan is the OSV lookup, since resolution and serialization with
  no network take 30 ms.
- **Coverage: 67.0%** overall across `internal/...`, median 83.3% per
  package, weakest `cli` at 24.5%. No badge, because no service is
  configured and a badge is a claim about a service.
- **226 top-level tests**, 14 packages, all green; plus the corpus, fuzz,
  mutation, and fetcher suites.

---

## Unverified — needs a real tag, push, or click

Stated plainly rather than presented as done.

| Item | Status | Why |
|---|---|---|
| **GitHub Actions runs** | **unverified** | `gh` is not installed. Every workflow claim here is a claim about YAML, not about a green run. |
| Go/OS CI matrix (3 OS x Go 1.23/1.24) | **unverified** | never executed on a runner |
| Nightly fuzz workflow | **unverified** | enumeration and budget arithmetic run locally (16 targets, 56s each); the scheduled run has not happened |
| cosign signing | **unverified** | loop verified against real artifacts with a stub; needs OIDC, so it needs a real CI run on a tag |
| GoReleaser release | **unverified** | snapshot verified; no tag was cut, so nothing was published |
| Release SBOM attachment | **unverified** | the snapshot produced it; `extra_files` attachment only executes on a real release |
| govulncheck | **unverified** | wired and scheduled, never run |
| Coverage on CI | **unverified** | measured locally at 67.0% |
| Contribution graph | **blocked on a click** | private-contribution setting in GitHub UI |

Because CI has never run, treat the workflow files as **unproven**. The
most likely failure is not a logic error — it is an action version or a
runner default that has moved since this was written.

---

## What is still incomplete

From `STATUS.md`, honestly:

- **Abandonment prediction** — not started, and correctly out of scope.
- **SLSA provenance** — not started. cosign signs the blobs; there is no
  provenance attestation for the build itself.
- **CODE_OF_CONDUCT, GOVERNANCE, ROADMAP, CODEOWNERS, SUPPORT** — none
  written. Several of these are arguably noise for a single-maintainer
  project, which is why they were not written rather than written badly.
- **mkdocs site** — not started.
- **Renovate/Dependabot** — not started.
- **Coverage badge** — deliberately absent, no service configured.
- **`why` / `trend` edge-case audit** — partial. Both run on a real corpus
  repo; neither has been audited for edge cases.
- **`cli` coverage is 24.5%** — the weakest package by a wide margin, and
  the one that decides exit codes.

---

## Gates, and what they caught

Every commit in this session passed: `gofmt`, `go vet`, `golangci-lint`
(pinned v1.64.5, clean), `go test ./... -count=1`, the fetcher suite, the
decision-index check, and a secret-pattern scan.

The harnesses themselves were wrong more often than the code was, which is
the finding I would keep:

- A sed-based mutation silently failed to apply and reported PASS.
- A test-runner capture saved a file before stdout finished, which looked
  like a badge bug and was not.
- `REPRODUCIBILITY.md`'s first draft named four repositories that are not
  in the corpus. Its list is now read from `differential.json` rather than
  retyped.
- `.scram-trend.json` was tracked, so the NFR-1 benchmark runs appended
  four entries for a 492-component fixture to SCRAM's own sparkline. Now
  ignored, and the committed file restored.

**Every fix in this report was made red first.** The two that best
demonstrate the method: the silent-zero invariant caught a lint cleanup
that would have disabled the tool's central guarantee, and the mutation
audit killed a `spdxNamespace` test that could only fail if the function
was already correct.

## Reproduce any of this

```bash
go test ./...                                    # 226 tests, 14 packages
python3 scripts/test_fetch_corpus.py             # fetcher regressions
python3 scripts/mutation_audit.py                # 16 mutants, all must die
go run ./cmd/corpus-check                        # 86 real lockfiles
python3 scripts/gen_decision_index.py --check    # index is current
go test -coverprofile=/tmp/c.out -covermode=atomic ./...
```
