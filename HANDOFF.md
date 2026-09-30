# HANDOFF — SCRAM, paused 2026-09-30

Work is stopped here deliberately. Nothing is in flight, nothing is dirty, and
no tag has been cut. This file is the only thing to read to pick the project
back up.

## Current state

| | |
|---|---|
| **HEAD** | the tip of `main` — run `git rev-parse HEAD` |

> Written across two commits, so the file could not name its own final hash:
> every commit that corrected the number moved the number again. The tip at
> the time of writing was `a0e6cc2`. Trust `git rev-parse HEAD`, not this
> line, and verify `origin/main` and the remote agree with it.
| **Pushed** | yes — `HEAD` == `origin/main` == remote `refs/heads/main` |
| **Unpushed commits** | 0 |
| **Working tree** | clean |
| **CI on `a0e6cc2`** | **14 green, 2 skipped, 0 failed** |

> CI on `479dbfa` (the commit before this one) was 14 green / 2 skipped / 0
failed. Re-read the conclusion for `a0e6cc2` — do not assume it carried over.

CI detail, as observed on `479dbfa`: all six `Build, test, vet` matrix jobs pass (macOS/Linux/Windows ×
Go 1.23/1.24), plus Race detector, Coverage, Corpus invariant, SCRAM scans
itself, SBOM schema validation, gitleaks (full history), golangci-lint, and
trufflehog cross-check. `Release` is skipped because it waits on a tag, and
`govulncheck (self)` is skipped by design. Nothing is failing and nothing is
waiting.

Local gate at this commit: gofmt clean, `go vet` clean on darwin/linux/windows,
`go test ./...` pass, `golangci-lint v1.64.5` clean, mutation audit **39/39
killed**, gitleaks **no leaks over full history**.

## Resolved

### The grype 5-vs-7 question — CLOSED, and the answer is "not a bug"

`lodash@4.17.11` reported SCRAM 5 / grype 7. That looked like a matcher gap and
would have blocked the release. It is an **alias artefact**.

OSV returns **7 records for 5 advisories**: `GHSA-r5fr-rjxr-66jc` and
`GHSA-xxjr-mmjv-4gpg` are reciprocally aliased to `GHSA-35jh-r3h4-6jhm` and
`GHSA-f23m-r3pf-42rh`. Union-find over the alias graph gives 5 classes from
OSV's 7 and 5 from SCRAM's 5 — **identical sets**. Now an exact 5-vs-5 match
on npm, yarn, pnpm 5.4, pnpm 9.0 and cargo.

Root cause was in the **harness**, not the scanner. `scripts/diff_vulns.py`'s
`canonical()` existed to collapse aliases and silently did nothing:
`aliases_for()` swallowed the `CERTIFICATE_VERIFY_FAILED` from its own
`urlopen` and returned `{vid}` for every id, so canonicalization was the
identity function. Four bugs, in `4bf37c4` and `202752f`:

1. the swallow itself — a comparison step that failed open and reported
   agreement it never established;
2. the transitive closure was a no-op (unioned only ids already in the input);
3. the class representative came from input ids only, so two tools picked
   different names for one advisory;
4. the attribution check indexed a raw-id map with a canonical key and raised
   `KeyError`.

`canonical()` now raises on fetch failure (`--allow-offline` is the explicit
opt-in). Pinned by 4 tests in `internal/resolve/diffvulns_test.go`, **5/5
mutants killed**. Documented in `DECISIONS.md` D46, `docs/adr/0046-*.md`, and
`REPRODUCIBILITY.md` §3c–3d.

### The rest of the v0.2.0 pre-tag gate — CLOSED, on `9a74e53`

- **D45 / `TESTING.md`** — the "guard only catches the phrasing its author
  imagined" pattern, with all four real instances, stated as a standing rule.
- **Differential** — 25 repos, all 15 v0.1.0 ecosystems produce identical
  counts. New coverage: Cargo matches syft exactly (541/541, 63/63, 406/406);
  the pnpm 5.x gap is a syft undercount, verified against 1,598 file keys.
- **NFR-1** — cold scan 2,810 ms against a 30,000 ms target. Both this run and
  the v0.1.0 6,022 ms figure are recorded, not just the flattering one.
- **Release notes** — lead with the breaking change (`schema_version 2.0.0`,
  `repo_score` semantics). `gen_changelog.py --require-breaking` fails the
  build if the section is missing.
- **Full gate** — gofmt, vet, tests, lint, goreleaser, gitleaks, and the
  action-metadata / ADR / changelog checkers all green.

### Also fixed and merged

- **Windows CI** — the D46 tests embedded an absolute path in `python -c`
  program text; it arrived mangled on the runner
  (`D:\a\SCRAM\SCRAM\x07\SCRAM\SCRAM\scripts\diff_vulns.py`). The path now
  travels on stdin, and `runPython` asserts no path appears in program text.
  Recorded as **D47** plus a standing `TESTING.md` rule: a green local run says
  nothing about another platform, and `GOOS=windows go vet` compiles without
  executing. I had committed a *guessed* fix first (`python3` missing from
  PATH) which was wrong — the jobs failed identically after it. That is written
  down rather than quietly amended.

## Still open

Exactly one thing, and it is not an investigation:

### Cut v0.2.0-rc1

Nothing is blocked. The tree is clean, CI is fully green, and the only
remaining step is the release cut itself, which is **waiting on explicit
authorization**.

Standing constraints for that cut, unchanged:

- **No tag beyond rc1 without explicit go-ahead.** Same rule as v0.1.0, no
  exceptions.
- No force-push, no history rewriting, no branch deletion.
- Do not delete or unpublish any release. `v0.1.0` and all prereleases stay
  exactly as they are.
- Run a real full-history secret scan before any push, using the same
  invocation CI uses: gitleaks **v8.30.1** (pinned in
  `.github/workflows/secret-scan.yml`) with
  `detect --source=. --log-opts=--all --redact`, plus a planted positive
  control to prove the scan can fail. `--log-opts=--all` is the whole point:
  without it gitleaks sees only the diff and the scan is theatre.
- Do not hammer OSV, FIRST.org, or GitHub; cache and rate-limit.
- Verify binaries, signatures and provenance, then exercise the Action end to
  end on push and both PR cases — pass on an unchanged tree, fail on a genuine
  new finding — paying particular attention to the PR comment rendering the new
  `/65` score correctly on a real runner.

### Known-benign, do not re-investigate

- `diff_vulns.py` exits non-zero on some PyPI fixtures. That is **correct** —
  SCRAM reports advisories grype's database lacks, each confirmed against OSV
  directly (werkzeug 0.15: OSV 20, SCRAM 11, grype 9). The harness reports a
  real disagreement instead of hiding it.
- pnpm 5.3/5.4/6.0: SCRAM 1,598 components vs syft 592. Ground truth is 1,598
  file keys; **syft undercounts**.
- Maven is tracked but deliberately deferred (`ROADMAP.md`).
- `ping github.com` fails from this machine while HTTPS to it works — a DNS
  quirk, not a network outage. Don't gate a push on `ping`.

## To resume

Paste this:

> Resume SCRAM at the tip of main. Cut v0.2.0-rc1 — and only rc1. Verify binaries,
> signatures and provenance, exercise the Action end to end on push and both PR
> cases (pass on unchanged tree, fail on a genuine new finding) with attention
> to the PR comment rendering the new /65 score on a real runner, then report
> back. No tag beyond rc1 without my explicit go-ahead. Start by re-verifying
> HEAD, the pushed state, and CI on that exact SHA rather than trusting this
> file.

First three things to do on resuming:

1. `git log --oneline -3` and `git rev-parse HEAD origin/main` — confirm the
   repo is still where this file says. Do not trust this document; verify it.
2. Re-read the check-runs for the current HEAD over the API. Every status in
   this file was true when written and will not stay true.
3. Read `HANDOFF.md`, `DECISIONS.md` (D44–D47), and `TESTING.md` before
   touching anything.

## Where the evidence lives

| | |
|---|---|
| corpus + fixtures | `testdata/fixtures/` — 224 files on disk. The silent-zero invariant reports 202 lockfiles / 18 genuinely empty; that figure comes from the CI `Corpus invariant` job, not a test you can re-run locally. |
| recorded OSV responses | `testdata/osv/` (regenerate: `scripts/record_osv_fixtures.py`) |
| mutation harness | `scripts/mutation_audit.py` — 39/39 killed |
| component differential | `docs/differential.json` (25 repos), `scripts/differential.py` |
| ID-level differential | `scripts/diff_vulns.py` — needs syft/grype in `/tmp/diftools` |
| decisions | `DECISIONS.md`, `docs/adr/d44`–`d47` (31 ADRs total) |
| permanent test limits | `TESTING.md`, `CONTRIBUTING.md` (known-vulnerable roundtrip rule) |
| breaking change | `docs/BREAKING-2.0.0.md`, `schema_version 2.0.0` |

Comparison tools live in `/tmp/diftools` and `~/go/bin`; `/tmp` does not
survive a reboot, so they will need reinstalling.
