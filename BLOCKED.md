# BLOCKED

Items that could not be completed in this session, with what was tried.
Each one is a real blocker, not a deferred preference.

---

## 1. GitHub Actions status cannot be verified

**Blocked by:** `gh` is not installed on this machine, and there is no
other way to read a workflow run without authentication.

**Tried:**

- `command -v gh` → not installed.
- Unauthenticated REST (`https://api.github.com/repos/0xsan7/SCRAM`)
  → **404**, because the repository is private.
- The repository web page and `raw.githubusercontent.com` → 404
  unauthenticated, confirming the same thing.

**Consequence:** CI is **unverified**, not passing. Every local gate is
green (`gofmt`, `go vet`, `go test ./...`, corpus check, secret scan), and
the full suite was additionally run from a cold `git clone`, but a
CI-only failure — a missing tool in the runner image, a workflow syntax
error, a permissions problem — would not appear in any of that.

**To unblock:** install `gh`, run `gh auth login`, then
`gh run list --repo 0xsan7/SCRAM`.

---

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
