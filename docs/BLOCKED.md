# BLOCKED

Items that could not be completed in this session, with what was tried.
Each one is a real blocker, not a deferred preference.

---

## 1. RESOLVED — GitHub Actions status is now verified

The repository became public, so the runs API is readable without
authentication and `gh` is no longer needed to see what happened.

**CI was red on every push from `29ac2db` to `8d0176b`, and is green at
`ca15f8f`.** All nine jobs pass: six matrix legs (ubuntu, macos, windows
x Go 1.23 and 1.24), plus golangci-lint, the corpus invariant, SBOM
schema validation against the official CycloneDX 1.5 and SPDX 2.3
schemas, and SCRAM scanning itself.

The failure took four attempts and is written up as `DECISIONS.md` D43.
In short: `windows-latest` failed at a formatting check whose real cause
was CRLF, and the first three diagnoses -- pwsh syntax, then `shell:
bash`, then replacing the shell with a Go program -- were each wrong in
ways that looked like progress. The fourth attempt read the log.

Reading the log needed the credential in the keychain, because the logs
endpoint returns 403 without admin rights. That credential belongs to
account `232798030`, not `0xsan7`; it was used read-only to fetch logs
and nothing in this repository changed as a result.

`govulncheck (self)` and `Release` show as `skipped`, correctly: the
former is schedule-only and the latter requires a tag.

**The Fuzz workflow was dispatched manually and passes.** 16 targets
enumerated from the source (so a new target cannot silently never be
fuzzed), the committed corpus replayed, all 16 fuzzed with no crash, and
the mutation audit reporting `killed 16 survived 0 invalid 0 broken 0`.

`v0.1.0-rc1` has since been tagged, and the items that were waiting on a
tag are now verified rather than pending — see `docs/STATUS.md` for the
full evidence table.

### v0.1.0-rc1, -rc2, and -rc3 must not be used

All three tags and all three releases are still public and still
resolve. rc1's Action cannot be loaded by the runner at all, and rc2's
loads and scans but inverts its own drift gate, reporting every
pre-existing finding as new. rc3 is the first of the three that works
on both events. `v0.1.0` supersedes all three and is the same code
with the release promoted.

They were left in place deliberately rather than deleted, because
deleting a published release destroys the evidence for why the fixes
exist. Each carries a one-line note at the top of its notes saying so.

`releases/latest` now resolves to `v0.1.0`, and `v0.1.0` is not marked
as a prerelease. The `v1` ref still does not resolve and is not a
substitute for the version tag: `uses: 0xsan7/SCRAM@v1` would install
an unpinned binary, which is the thing the version-tag requirement
exists to prevent.

What remains unverified is now only:

- `govulncheck (self)` — the schedule is nightly and has not come round
- coverage measured locally at 67.0%; the CI job that reports it is
  green, but no badge is published because no service is configured

## 2. ~~The repository is private~~ — RESOLVED, and the original diagnosis was wrong

**This section previously asserted that `0xsan7/SCRAM` was private, on the
strength of a 404 from the unauthenticated API.** That inference was
wrong. The repository is public, `https://api.github.com/repos/0xsan7/SCRAM`
returns 200 unauthenticated, and `raw.githubusercontent.com` serves
`main` without a token. Confirmed again after the release was published.

**Why the 404 happened, and why it mattered.** An unauthenticated 404 is
indistinguishable from "private" and "does not exist", and the section
below it turned that ambiguity into a confident claim, then built a
detailed explanation — two identities, a contribution-graph mechanism,
a two-step unblock — on top of it. The push credential belongs to
account `232798030` while commits are authored by `0xsan7`, which is
real and is still worth knowing. But it was not the cause of anything,
because the repository was never private.

The lesson is the one this project keeps re-learning: a 404 is evidence
of *absence of permission*, not evidence of *absence of object*.

**Still true, and still unexplained:** commits pushed with a credential
belonging to `232798030` may not appear on the `0xsan7` contribution
graph, because GitHub attributes a push to the pushing account. That is
a question about GitHub's attribution rules and the account's own
contribution-visibility settings, not about SCRAM, and it is not
something this repository can fix or verify from here.

**Not done here:** no repository setting was changed as part of this
investigation. Visibility, topics, and description were set separately and
explicitly, at the maintainer's request.

---

## 3. Release automation cannot be verified end to end

**Blocked by:** cutting a tag is forbidden by the brief, and signing,
provenance, and multi-platform binaries all require one to exist.

**Consequence:** everything in Phase 3A is config-only. `goreleaser
check` and `goreleaser release --snapshot --clean` can be run locally and
are meaningful, but "the signature verifies" and "the provenance attests"
cannot be demonstrated without a real release.

**To unblock:** cut the first tag by hand, then re-run the release job.

---

## 4. osv-scanner could not be used as a differential oracle

Not a blocker on the work, recorded so the gap is not mistaken for
coverage. osv-scanner v2.6.0 publishes no darwin/arm64 release archive,
only a raw binary (SHA256 verified against the release's
`osv-scanner_SHA256SUMS`). Installed and invoked, it resolves packages
correctly but reports zero vulnerabilities on inputs where both SCRAM and
grype find 14, and its v2 `scan source` JSON schema emits no
`vulnerabilities` array.

The differential conclusion therefore rests on **syft 1.52.0** and
**grype 0.119.0** only. See `REPRODUCIBILITY.md`.

---

## 5. Absolute host paths in git history

Audited 2026-09-28 after the repository became public. Method: every blob
in `git rev-list --all --objects` was read and searched for `/Users/`,
`/home/`, the account name, and RFC1918-style hostnames.

**Found: 3 committed `.pyc` files, since removed from the index.**

| commit | file |
|---|---|
| `27d92cf` | `scripts/__pycache__/fetch_corpus.cpython-314.pyc` |
| `160f3e6` | `scripts/__pycache__/diff_vulns.cpython-314.pyc` |
| `160f3e6` | `scripts/__pycache__/differential.cpython-314.pyc` |

A Python bytecode file records the absolute path of the source it was
compiled from, so each one published `/Users/santiagojerald/scram/...`.
Verified by compiling a file and reading the string back out of the
resulting `.pyc`, so this is a property of the format rather than a guess.

Fixed by `git rm --cached` plus a `__pycache__/` and `*.py[cod]` rule in
`.gitignore`. The blobs **remain in history** and are still reachable at
those commits.

**Not fixed here:** history was not rewritten, per instruction. On a
public repository this means the home directory path is permanently
visible to anyone who reads those commits. A path is not a credential and
reveals no secret, but it does disclose the account name and directory
layout, and it is the kind of thing that should not be published. If it
needs to be gone, the options are `git filter-repo --path scripts/__pycache__
--invert-paths` followed by a force-push, or GitHub Support. Both rewrite
history or require someone else's action, so neither was done.

**Clean:** `/home/` (0 hits), the local hostname (0 hits),
`/var/folders/...` TMPDIR paths (0 hits), and `*.local`/`*.lan` hostnames
(0 hits). The single `env.local` hit is a `.gitignore` entry naming a file
to exclude, not a hostname.

**Also present and correct:** one `/Users/runner/...` string inside
`testdata/fixtures/pypi/real/pp/pydantic/pydantic/pyproject.toml`. That is
pydantic's own CI path, part of the upstream file, and part of what the
fixture is for.

---

## 6. Security and confidentiality audit — 2026-09-29

The repository is public, so this was run with real tools against the
full history rather than read off the working tree.

### Tools and scope

| Tool | Version | Scope |
|---|---|---|
| gitleaks | 8.30.1 | `--log-opts=--all`, every commit, 31 commits / 13.60 MB |
| trufflehog | 3.97.9 | `git file://`, full history, unverified results included |

**No real secret was found. No credential was rotated, and history was
not rewritten.**

gitleaks: **0 findings.**

trufflehog: **3 results, all false positives**, shown here rather than
summarised, because "3 hits" is the number a reader would otherwise see:

| Detector | Where | What it actually is |
|---|---|---|
| `Box` | `4a576975`, `testdata/fixtures/gomod/real/traefik/traefik/go.sum` | `h1:1eFIGcM4lI+AfFOUpbs548SFGz1ZWoMOGbECBmkghw4=` — a Go module checksum |
| `TLy` x2 | `27d92cf`, `testdata/fixtures/npm/real/mochajs-mocha@{8.0.0,9.0.0}/package-lock.json` | `"integrity": "sha512-P8WRou2S+oe2...SIsVJh52VP4lvXkaFVnOFFdoWv1H1Jjvel1aI6NCFOAaeAVm8qrI0odiLcww=="` — an npm integrity field |

Both are base64 content hashes in the vendored fixture corpus, matched
by entropy rather than by structure. They are unverified against any
provider, which is the correct state for a checksum: a module hash is not
a credential and must never authenticate anything. Both remain in HEAD
and both are supposed to.

### Confirmed clean

- **Network code carries no credential.** `scripts/fetch_corpus.py` reads
  public URLs from `raw.githubusercontent.com` with a `User-Agent` and no
  `Authorization` header. There is no token to leak, so there is no
  environment variable to move into one.
- **`.gitignore` covers the right patterns** — `.env`, `.env.local`,
  `*.pem`, `__pycache__/`, `*.py[cod]`, `.DS_Store`, editor swap files,
  `/dist/`, `/scram-output/`, `*.sarif`, `.scram-trend.json`.
- **Nothing matching those patterns is tracked.** `git ls-files` against
  every one of them returns nothing: no `.env`, no `__pycache__`, no
  `.pyc`, no `*.pem`, no editor junk. (`env.local` appears in
  `.gitignore` as an ignore rule, which is a different thing from a
  tracked file.)
- **cosign is keyless.** `ci.yml` signs with `sign-blob` against an OIDC
  `id-token: write` permission. There is no stored signing key anywhere
  in the repository. The one guard worth naming: the step counts what it
  signed and fails with `::error::no artifacts were signed` if the count
  is zero, because a signing step that signs nothing and exits 0 is
  worse than one that fails. `set -euo pipefail` is in force, so a
  cosign fetch or sign failure aborts rather than being skipped.
- **No workflow silently skips on an unset secret.** The only secret
  reference in the whole CI file is `secrets.GITHUB_TOKEN`, passed to
  GoReleaser. There is no `if: secrets.X != ''` guard anywhere, so
  nothing degrades quietly.

### Confidentiality findings

**Absolute home-directory paths.** `/Users/santiagojerald/...` appears in
this file and in `OVERNIGHT_REPORT.md` — in both cases inside a sentence
*describing* the `.pyc` leak that was fixed, not leaking anything new. The
only other `/Users/` string in the tree is
`testdata/fixtures/pypi/real/pp/pydantic/pydantic/pyproject.toml:295`,
which is pydantic's own CI path, upstream content in a fixture. No
`/home/` paths, no `*.local` or `*.internal` hostnames, no hostnames of
any kind.

**A real email address**, `santiagojerald734@gmail.com`, in
`OVERNIGHT_REPORT.md` and this file. Left in place deliberately: it is the
author of all 31 commits, so it is already in the git history
permanently and removing it from two prose files would not reduce
exposure by one byte. It is there because the contribution-attribution
finding is stated in terms of it, and stating a finding without the
evidence is how a report stops being checkable.

**A stale claim in this file.** Item 2 below still reports the repository
as private, which it is not. Recorded rather than quietly deleted,
because the correction is itself a finding: it shows that the
private-repository reading was an inference from a 404 rather than a
fact, and that the inference was wrong.

### Genuine gap: the fixture corpus has no attribution

**197 upstream projects** are vendored under `testdata/fixtures/`: 50 Go
repositories, 103 npm projects, and 44 PyPI packages drawn from 32
organisations. That is 197 real `go.sum`, `package-lock.json`,
`pyproject.toml` and `requirements.txt` files, one per project. There is no `NOTICE`, no provenance manifest,
and no statement anywhere in the repository that these are third-party
files.

The directory names carry the upstream organisation, so the fixtures are
traceable, but traceable is not attributed. Each upstream project carries
its own licence — MIT, Apache-2.0, BSD, MPL-2.0 and others — and none of
those licences is recorded here.

**This is not a licence violation on the evidence available**, and it is
not certain to be one. These files are dependency manifests, not source
code: they are facts about a dependency graph, which is what a scanner
must parse, and the repositories are named in the path. The
transformative-testing argument is reasonable.

**But it is not my call to make silently.** Whether redistributing 197
projects' manifests needs a NOTICE is a question for whoever owns this
repository, so it is logged here instead of answered by me. What should
not happen is a public repository shipping 197 third-party files with no
recorded provenance, which is the state it is in now.

The fix, when someone decides to make it, is mechanical:
`scripts/fetch_corpus.py` already knows every URL it fetched, so a
generated `testdata/fixtures/SOURCES.md` listing repo, path, commit and
licence is a small change to a script that exists. The licences would
have to be fetched per project, which is the part that takes time.
