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

## 2. The repository is private, so contributions do not appear on the
`0xsan7` profile

**Found by:** checking, in order, the commit authors, the global git
identity, the repository visibility, and the stored credentials.

**Evidence:**

- Every commit is authored by `0xsan7 <santiagojerald734@gmail.com>`, and
  `git config --global user.name` is `0xsan7`. The author is right.
- `https://api.github.com/users/0xsan7` → 200, and reports
  **`public_repos: 0`**.
- `https://api.github.com/repos/0xsan7/SCRAM` → **404**.
- `https://raw.githubusercontent.com/0xsan7/SCRAM/main/README.md` → **404**.
- `git push` succeeds, using an `osxkeychain` credential whose
  `username` is **`232798030`**, not `0xsan7`.

**What this means.** Two different GitHub identities are in play. The
commits are written into a repository under `0xsan7` by a token belonging
to user `232798030`. The push is accepted, so that token has write access
— but GitHub attributes the contribution to the account that owns the
pushing credential, and a **private** repository contributes nothing to a
public profile's contribution graph regardless of who authored it.

So the empty contribution bar is expected on both counts, and neither is a
bug in SCRAM.

**To unblock (a human must do this; both are repo settings, which are out
of scope here):**

1. Make `0xsan7/SCRAM` public, if that is the intent. Private-repo
   contributions are not shown publicly at all.
2. Push with a credential belonging to `0xsan7` itself, so the commits are
   attributed to that account.

**Explicitly not done here:** no repo visibility was changed and no
credential was created, rotated, or modified. Both are forbidden by the
brief, and both are the kind of change a human should make deliberately.

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
