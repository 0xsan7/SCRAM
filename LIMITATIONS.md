# SCRAM limitations

Stated plainly, and each claim here is checked by a test. If a limitation
below stops being true, a test fails and this file has to change — that is the
same rule the rest of the project runs on, and it applies to documentation
too: a stale claim in a README is the "guard that can't fail" failure mode
moved out of the test suite.

Nothing on this page is aspirational. If SCRAM does not do something, it says
so here rather than failing quietly at scan time.

---

## Ecosystems

| Ecosystem | Files read | Real-fixture coverage | Gaps |
|---|---|---|---|
| **npm** | `package-lock.json`, `npm-shrinkwrap.json` | 16 lockfiles: **6 × v1, 1 × v2, 9 × v3** | See "npm lockfileVersion 1" below |
| **PyPI** | `poetry.lock`, `Pipfile.lock`, `requirements*.txt`, `pyproject.toml` | 7 lockfiles + 44 `pyproject.toml` | See "Python resolution" below |
| **Go** | `go.sum` | 63 files, 16,832 components | `go.mod` is not read; a module with no `go.sum` is not scanned (fails closed, exit 1) |

Each fixture is unmodified output from a real project at a pinned tag or
branch, fetched by `scripts/fetch_corpus.py` and committed under
`testdata/fixtures/<eco>/real/`. The counts above are asserted by
`TestNpmCorpusCoversEveryLockfileVersion` and the corpus invariant tests, not
maintained by hand.

### npm lockfileVersion 1

v1 (npm 5/6, 2017–2020) is parsed, and **is** covered by real fixtures: mocha
6.2.0 / 8.0.0 / 9.0.0, marked 0.6.0 / 0.8.0, and less 3.13.0 — six lockfiles
totalling 2.8 MB, all resolving non-empty (829 to 2,492 components each).

The actual limitation is **not** missing coverage. It is that the v1 format
records no dependency flags: v2/v3 carry `dev`, `optional` and `peer` in the
`packages` map, and v1 carries nothing. SCRAM therefore **cannot distinguish a
production dependency from a development-only one** in a v1 lockfile, and
reports both in the component list. A v1 project's dev/prod split in the
report is not reliable.

SCRAM emits a warning to that effect on every v1 scan, in the normal output
rather than behind `--verbose`, because a silently-incomplete answer from a
security tool is the failure mode this project cares most about. The warning
states the corpus count it is relying on, computed at runtime from the
fixtures rather than hardcoded, so it cannot drift into a claim the corpus
does not support.

Fix: regenerate the lockfile with npm 7 or later.

### Python resolution

`pyproject.toml` reports **declared ranges, not installed versions**. PEP 621
and Poetry both record what a project asked for (`starlette>=0.46.0`), which
SCRAM resolves to the floor of that range when recording the component. It
does not know which version is actually installed. Where a `poetry.lock` or
`Pipfile.lock` exists, that file is used instead and versions are exact —
`poetry.lock` is a detection candidate ahead of `pyproject.toml`, and the
precedence is explicit in the resolver registry rather than incidental.

Requirements files have the same property, with one extra gap: a VCS or URL
requirement (`git+https://…`, `name @ URL`) is **skipped**, because no exact
version can be obtained from the declaration alone. A project depending on a
`git+` URL is scanned without that dependency, and SCRAM does not currently
warn about it.

A dependency whose specifier is a bare name with no version at all
(`requests`) is reported at an empty version. It is not dropped, but the
resulting PURL cannot be matched against OSV.

### Go

Only `go.sum` is read, so it carries module paths and hashes but **no version
for the main module itself**. A repository with `go.mod` and no `go.sum` is
therefore not scanned, and SCRAM does not read the `require` block to
reconstruct it.

This is a coverage gap, and it fails closed rather than silently: a repo with
no recognised lockfile produces `no dependency lockfiles found, so nothing
was scanned; this is not a clean result`, a warning listing every filename
that was looked for, and **exit code 1**. It never reports CLEAN on a project
it did not read.

The practical consequence is that a Go module whose dependencies have never
been downloaded (`go mod download` has not been run) is invisible to SCRAM
until they are. Note that `go.mod` on its own *does* declare dependencies, so
this is a deliberate choice to read only the resolved file rather than an
oversight in the silent-zero guard.

---

## Vulnerability data

**OSV is the only source.** NVD and GHSA are not queried directly; GHSA records
arrive through OSV, which is where they are published. G2's "optional NVD/GHSA
enrichment" is not implemented.

**EPSS is best-effort and may be absent.** FIRST.org's API is queried per CVE.
It rate-limits, and a failure is recorded as a warning with the scan marked
degraded, rather than silently scoring a component as if it had no EPSS.

**CVSS vectors are parsed, not scored by SCRAM.** The severity comes from the
vector in the OSV record. Where a record carries no CVSS at all, severity is
`unknown` and the component is not counted in any severity bucket — it is
neither reported clean nor counted against the score.

**Alias deduplication matters.** A single vulnerability is frequently
published under several IDs (CVE, GHSA, and a package-ecosystem advisory)
that OSV links via `aliases`. Matching is done across that alias graph, so one
issue is reported once. This was not true in the first implementation: PyPI
findings dropped from 76 to 41 once the existing dedupe logic was actually
called from the scan path.

---

## Scoring and policy

**The score is SCRAM's own opinion, not a standard.** It is a weighted
combination of finding count, severity, CVSS, EPSS, and dependency count,
documented in `README.md`. It is not comparable to any other tool's score and
should not be presented as one.

**Drift is a baseline diff, not a vulnerability lifecycle.** Comparing two
scans tells you what changed between them. It does not know whether a new
finding is already fixed upstream, already present in the base branch, or a
duplicate of something already counted.

**Waivers are exact-match only** — package, vulnerability ID, or both. There
is no wildcard or reason-code requirement, and an expired waiver is
re-reported as a finding (it is not silently reinstated).

---

## Operational

**A scan with no reachable OSV fails closed.** If vulnerability data cannot be
retrieved, SCRAM reports a degraded scan and exits non-zero. It does not
report CLEAN. A scanner that says "clean" because it could not look is worse
than one that says nothing.

**A lockfile that declares dependencies but resolves zero components is a
hard error**, never a clean result. This is the invariant from D26, and it
exists because D01, D22 and D23 each shipped a version of this bug
independently. Genuinely empty lockfiles (e.g. Ceph's committed
`"packages": {}`) remain valid and are distinguished by counting declarations
independently of the resolver.

**Cache TTL is 6 hours** for OSV records and EPSS. There is no cache
invalidation on a CVE update; a record corrected upstream is picked up at the
next expiry.

**Monorepo detection is directory-scanning, not workspace-aware.** Each
lockfile is resolved independently. npm/yarn/pnpm workspace members that share
one root lockfile are scanned once, at the root, and cross-package usage is
not attributed to the individual package that introduced a dependency.
