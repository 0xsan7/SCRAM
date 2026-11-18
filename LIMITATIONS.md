# SCRAM limitations

Current coverage and known gaps. The resolver and corpus tests exercise the
implemented formats; they do not establish that every dependency in an
installed environment was found. The supported-format overview is in
[README.md](README.md#ecosystems).

---

## Ecosystems

| Ecosystem | Files read | Real-fixture coverage | Gaps |
|---|---|---|---|
| **npm** | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` | npm v1/v2/v3, Yarn classic/Berry, pnpm 5.x/6.x/9.x | Yarn and pnpm are formats within npm, not separate ecosystems; see the npm v1 and JavaScript limits below |
| **PyPI** | `poetry.lock`, `Pipfile.lock`, the detector's explicit requirements filenames, `pyproject.toml` | Poetry/Pipenv/requirements files and real `pyproject.toml` fixtures | Arbitrary `requirements*.txt` filenames are not globbed; see "Python resolution" below |
| **Go** | `go.sum`, falling back to `go.mod` | Real `go.sum` and `go.mod` fixtures, including the fallback and OSV lookup-key checks | `go.mod` is a declared-dependency floor, not a complete resolved module graph |
| **Rust/Cargo** | `Cargo.lock` (v1–v4); `Cargo.toml` for direct dependencies | Versioned and versionless real Cargo lockfiles | Path/workspace and git sources are not a crates.io provenance guarantee; see "Rust/Cargo" below |

The committed real-world corpus lives under `testdata/fixtures/`. Run
`go test ./internal/resolve` for all resolver checks; `go run ./cmd/corpus-check`
summarizes the original npm/PyPI/Go-sum corpus. Format-generation checks live
in `internal/resolve/keyformat_test.go`. Exact npm v1/v2/v3 fixture counts are
asserted by `TestNpmCorpusCoversEveryLockfileVersion`.

### JavaScript formats

The detector chooses the first supported npm-ecosystem lockfile in each
directory: npm lockfiles before Yarn, then pnpm. It does not merge competing
lockfiles or verify which package manager built a deployed application.
Workspace members sharing a root lockfile are not given separate usage
attribution. A committed fixture for a format is evidence about that fixture,
not a guarantee about all future package-manager releases.

### npm lockfileVersion 1

v1 (npm 5/6, 2017–2020) is parsed, and **is** covered by real fixtures: mocha
6.2.0 / 8.0.0 / 9.0.0, marked 0.6.0 / 0.8.0, and less 3.13.0 — six lockfiles
totalling 2.8 MB, all resolving non-empty (829 to 2,492 components each).

Real v1 files can contain `dev` and `optional` flags. The gap is in SCRAM's
output: its component model does not expose development/optional/peer
classifications, in v1 or in v2/v3. `direct` means declared versus transitive;
it is not a production-versus-development flag. Development-only packages
may therefore appear in the inventory.

SCRAM's v1 warning describes that limitation. Regenerating with npm 7 or later
changes the lockfile layout but does not add a production-only filter to
SCRAM. Fixture coverage belongs to the test results, not a runtime count
dependent on the launch directory or an installed binary bundling test data.

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

`go.sum` is preferred when present. It records downloaded module versions,
not necessarily only the modules selected for the current build. SCRAM keeps
the highest recorded version per module and does not run Go's module graph
selection or apply `replace` directives.

When `go.sum` is absent, the resolver reads `go.mod` requirements. This scans
declared modules but cannot reconstruct undeclared transitive dependencies.
Both paths use full module paths for OSV lookup. Neither gives a version for
the main module itself or proves the exact contents of a deployed binary.
A repository with neither supported input still fails the no-lockfile check;
a genuinely dependency-free Go module is a different case and may have an
empty inventory.

### Rust/Cargo

The resolver reads package name/version pairs from `Cargo.lock` and marks
direct dependencies from `Cargo.toml`. Local path/workspace packages are
included and marked direct. The component model does not preserve their
source kind; git and local package names/versions must not be treated as
proof that the code came from crates.io. A matching name/version alone does
not establish that an advisory applies to a private or modified source.

---

## Project-level data

**The maintenance term is repository-level, not per-dependency.** The
OpenSSF Scorecard measures the project being scanned, so all components in
one scan get the same maintenance points. The Scorecard has no
per-dependency view, and deriving one from a dependency's own repository
would be a different feature with different failure modes.

**A project with no Scorecard scores 0 points on maintenance — which is
not the same as scoring badly.** Scorecard only runs on projects it has
been asked to scan, so small and new repositories are routinely absent.
The term contributes nothing, the scan is not failed, and `--explain`
says "no OpenSSF Scorecard available" rather than implying a measurement.
A missing input is not evidence of a problem.

**Inapplicable Scorecard checks are excluded, which can flatter a
project.** Roughly a fifth of checks return `-1` on any given repository
("packaging workflow not detected", "no releases found"). Averaging those
as zeroes would understate every project, so they are dropped — and
`--explain` prints how many were dropped, because a score computed from
11 of 14 checks is a weaker claim than one computed from all 14.

**The Scorecard is a third-party opinion and it goes stale.** The score
reflects when the Scorecard last ran, not when you last scanned;
`--explain` prints that date and the commit it evaluated. The upstream
API is also intermittently slow to answer, and a project can be absent
from it for a long time.

**`--scorecard` reads `.git/config` directly** and does not shell out to
git, so a scan cannot hang on a credential prompt. In a linked worktree or
a submodule, where `.git` is a file rather than a directory, it follows
`commondir` to the shared repository. An exotic layout it does not
recognise falls back to no maintenance score rather than a guess.

## Vulnerability data

**OSV is the only source.** NVD and GHSA are not queried directly; GHSA records
arrive through OSV, which is where they are published. G2's "optional NVD/GHSA
enrichment" is not implemented.

**EPSS is best-effort and may be absent.** FIRST.org's API is queried per CVE.
It rate-limits, and a failure is recorded as a warning with the scan marked
degraded, rather than silently scoring a component as if it had no EPSS.

**CVSS v3 base scores are reconstructed from OSV vectors.** Numeric v3
scores are also accepted. CVSS v4 is not implemented. Where a record carries no CVSS at all, severity is
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

**Advisory-detail cache TTL defaults to 6 hours** and honors the configured
override. Package matching still queries OSV on warm scans. EPSS is not
persistently cached. Offline vulnerability scanning remains unavailable: the
CLI fails explicitly rather than claiming a cached all-clear. Advisory
corrections are picked up when cached detail records expire.

**Monorepo detection is directory-scanning, not workspace-aware.** Each
lockfile is resolved independently. npm/yarn/pnpm workspace members that share
one root lockfile are scanned once, at the root, and cross-package usage is
not attributed to the individual package that introduced a dependency.
