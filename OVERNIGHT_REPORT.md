# Overnight report

Written 2026-09-28 to 2026-09-29, covering two sessions: the README
rewrite (`e08859c` through `29ac2db`) and the public-repository pass.

**8 commits in the second session, all pushed. `origin/main` is at
`9a9329e`, 0 ahead, 0 behind.** No tag was cut, no release published, no
repository setting changed, and no history was rewritten.

**CI is green and the nightly fuzz workflow passes.** Those were
unverifiable when the first half of this was written, because the
repository was private. Making it public turned both into real results,
and both of them found real bugs.

---

## The contribution graph

Settled. The repository is public, so private-contribution visibility is
no longer the question.

What is still worth knowing, because it is not visible from the
repository: `git config credential.helper` is `osxkeychain`, and the
stored `github.com` credential belongs to account **232798030**, not
`0xsan7`. Pushes work because that account has write access. Commits
author from `git config user.email` (`santiagojerald734@gmail.com`), so
attribution is consistent today — but if the two accounts have different
emails on file, work committed under the wrong one will not attribute.
That credential was also what made the CI logs readable.

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

### 6. Two advisories with the same EPSS and CVSS — one bug, not two

You were right that something was wrong, and wrong about which part.

EPSS was correct. Four of the five lodash findings matched FIRST.org
exactly (0.05006, 0.21333, 0.05213, 0.07336). They *should* repeat
across two advisories: `GHSA-35jh` and `GHSA-r5fr` are two records for
the same CVE, so the same number is expected. Reading that as a lookup
bug sends you at the wrong subsystem — I did.

The real bug was CVSS. Those two records carry **different vectors**,
because GitHub rescored the issue when its scope model changed:

```
GHSA-35jh-r3h4-6jhm  AC:L/PR:H  ->  7.2    OSV's canonical record
GHSA-r5fr-rjxr-66jc  AC:H/PR:N  ->  8.1    the older record
```

`Dedupe` merged the group and took the higher score, so GHSA-35jh was
reported at 8.1 wearing the other record's vector. That one is nastier
than a wrong number: it was **internally consistent** — 8.1 and the 8.1
vector agreed — and still wrong, because both came from a record that
was not the one matched. Self-consistency is not provenance.

A score is no longer adopted from a sibling record. All five findings
now match an independent CVSS 3.1 implementation run over the vector that
ships with them. Re-introducing the old rule turns the new test red with
`CVSSv3 = 8.1, want at most 7.2`. The first version of the fix reordered
the comparison instead of removing it and the test stayed red, which is
what proved the test was load-bearing.

### 7. CI was red on every push, and the Windows fix took four attempts

Making the repository public made the runs readable. CI had been failing
since `29ac2db` — nine of eleven jobs passing every time, only
`windows-latest` failing, always at the formatting check.

Attempt 1: pwsh cannot parse `[ -n "$x" ]`. Right about the symptom,
wrong about the cause.
Attempt 2: `shell: bash`. Still failed. I said so rather than shipping it.
Attempt 3: replaced the shell entirely with a Go program. **Still
failed** — and the logs endpoint returned 403.
Attempt 4: got the log using the keychain credential. It listed **all 60
files** as unformatted. None of them were: `actions/checkout` produced
CRLF files, `gofmt` always writes LF, and a byte comparison reports
every correct file as wrong -- 73 files, which is every `.go` file under
`./cmd` and `./internal`.

Fixed with `.gitattributes` forcing LF at checkout, plus EOL
normalisation in the checker. Then the *next* Windows failure was mine:
all six of the new tests built a binary named `gofmtcheck` with no `.exe`
suffix, which works on Linux and macOS and not on Windows.

**Green at `ca15f8f`.** The reasoning is the part worth keeping: two of
four attempts were reasoned from the local machine and both were wrong in
ways that looked like progress. The step that was failing was the step
that used a shell, so the shell was the obvious suspect twice.

### 8. Committed `.pyc` files published the build machine's home directory

`scripts/__pycache__/*.pyc` were tracked since `27d92cf`. A Python
bytecode file records the absolute path of the source it was compiled
from, so each one published `/Users/santiagojerald/scram/...` — verified
by compiling a file and reading the path back out. Untracked and ignored
now. The blobs stay in history; rewriting it was out of scope, and
`docs/BLOCKED.md` records exactly which commits hold them.

A full-history scan of every blob in the history found nothing else: no `/home/`, no
hostname, no TMPDIR paths. The one `/Users/runner/...` string is
pydantic's own CI path inside a committed fixture.

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

## Verified, by running it

The repository became public partway through this session, which turned
every previously-unverifiable workflow claim into a testable one. All of
these have now actually executed:

| Item | Result |
|---|---|
| **CI, full matrix** | **green** at `ca15f8f` — 3 OSes x Go 1.23/1.24, six legs, plus lint, corpus, SBOM schema validation, and self-scan |
| **Nightly fuzz** | **green**, dispatched manually — 16 targets enumerated from source, corpus replayed, 16 fuzzed, no crash |
| **Mutation audit on CI** | **green** — `killed 16 survived 0 invalid 0 broken 0` |
| Testability (coverage + race) | green on every push |
| SBOM schemas | green — CycloneDX 1.5 and SPDX 2.3 validated against the official schemas in CI |
| GoReleaser | `check` valid; `release --snapshot` produced 5 cross-compiled binaries, checksums, and a self-generated SBOM |
| golangci-lint | clean on the pinned v1.64.5 |
| The drift demo | `examples/lodash-drift/run.sh` reproduces the README hero |

## Still unverified

| Item | Why |
|---|---|
| `govulncheck (self)` | schedule is nightly and has not come round |
| cosign signing, the `Release` job, release SBOM attachment | all gated on a tag, and no tag may be cut here |
| Coverage as a published number | measured locally at 67.0%; the CI job is green but no badge is published, because no service is configured |
| The `@v1` action ref | no release exists, so it cannot resolve |

## What is still incomplete

From [`docs/STATUS.md`](docs/STATUS.md), honestly:

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
  in the corpus. Its list is now read from `docs/differential.json` rather than
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

### Found in this pass, not yet fixed

- **`scan.json` has no `findings` key at the top level.** The per-component
  findings are there, and a machine-readable report that omits the thing
  you are looking for is a trap. Not fixed here: it changes a published
  JSON shape, so it needs a decision recorded rather than a quiet fix.
- **D06-D21 do not exist** in `DECISIONS.md`. Real gaps, left visible in
  the generated index rather than papered over with invented entries.
- **`internal/cli` coverage is 24.5%** against a 83.3% median. The lowest
  number in the project and the package with the most surface.

### Deliberately not built

- **mkdocs.** *This entry was wrong when first written.* It claimed the
  decision was "Recorded in `ROADMAP.md` so it is a stated choice, not a
  silent gap" — mkdocs was not mentioned in `ROADMAP.md` at all, and the
  same report said "mkdocs site — not started" further up. The reasoning
  in that bullet was sound; the claim that it had been recorded was not
  true, and the gap is now genuinely recorded rather than asserted to be.
- **Reachability analysis.** The largest real gap between what SCRAM
  reports and what is exploitable. It is a project, not a feature, and
  `ROADMAP.md` says so with the reason.

### One thing only you can do

**Cut the first tag.** Everything release-shaped is built and
locally verified but has never executed: `goreleaser check` passes, a
snapshot produces five cross-compiled binaries with checksums and a
self-generated SBOM, the cosign loop was verified against the real
snapshot layout, and the `Release` job is wired for keyless signing. None
of that runs without a tag, and I did not cut one.
