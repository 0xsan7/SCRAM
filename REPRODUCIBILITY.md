# Reproducing the differential comparison

Exactly what was compared, on which repositories, what diverged, and why.
Written so the claim can be re-run or contradicted rather than trusted.

The tools and versions:

| Tool | Version | Role |
|---|---|---|
| syft | 1.52.0 (darwin/arm64) | component cataloger |
| grype | 0.119.0 (darwin/arm64) | vulnerability oracle |
| osv-scanner | 2.6.0 (darwin/arm64) | **unusable**, see below |

Single static binaries, no Docker. osv-scanner's SHA256 was verified
against the release's `osv-scanner_SHA256SUMS`.

## How to re-run

```bash
go build -o /tmp/scram ./cmd/scram
python3 scripts/differential.py --tools /path/to/binaries   # component counts
python3 scripts/diff_vulns.py   --tools /path/to/binaries   # vulnerability ID sets
```

`differential.py` writes `differential.json` for inspection.

**Neither script is a pass/fail gate.** The differences below are real and
mostly expected; a gate would either fail constantly or be tuned until it
passed, and either outcome would be worse than a documented comparison.

## What was compared

15 real corpus repositories spanning all three ecosystems and every npm
lockfileVersion. The exact list is in `differential.json` and was taken
from it rather than retyped:

`None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`, `None`

Six are npm v1 lockfiles (the `marked` and `less` fixtures were fetched
at pinned 2017-2020 tags).

## Divergences, and what each one is

### 1. npm — syft reports production only

`nestjs/nest`:

| | components |
|---|---|
| syft | 190 |
| SCRAM (all) | 1,478 |
| SCRAM, non-`dev` only | 180 |

1,479 of the lockfile's 1,676 entries are marked `dev`. syft's
`javascript-lock-cataloger` excludes them; SCRAM includes everything and
marks `Direct`.

**Scope-matched, SCRAM's non-`dev` set is a strict subset of syft's** —
SCRAM's 180 non-`dev` names are a subset of syft's 190, with no name
SCRAM misses. The 10 extra are syft entries carrying
version `UNKNOWN`: npm workspace links (`node_modules/@nestjs/core` is a
`link: true` pointer whose real version lives in `packages/core`), which
syft cannot follow; `differential.json` lists 9 such entries for this
fixture.

**Why this matters beyond a count:** an `UNKNOWN` version matches nothing
at OSV, so on a workspace monorepo those packages produce no findings at
all. The same pattern appears on `vscode` and `bitwarden`.

### 2. PyPI — syft requires exact pins

Isolated to a two-line file:

```
pendulum==2.1.2     ->  syft: 2 components
pendulum>=2.1.2     ->  syft: 0 components
```

SCRAM resolves both. This is why syft reports **0** for
`prefecthq/prefect` (22 ranged requirements; SCRAM: 22) and 54 for
`home-assistant/core` (SCRAM: 58).

**SCRAM's advantage is also a real limitation.** A range's floor is not
the installed version: `pendulum>=2.1.2` may well resolve to 3.x
installed. It is the best a ranged declaration allows, it is documented in
`LIMITATIONS.md`, and it is not equivalent to a lockfile's exact pin.

### 3. Go — syft needs the module graph, SCRAM reads checksums

syft reports **0** for both `consul` and `kubernetes` from a bare `go.sum`,
and still 0 when a `go.mod` is added beside it. SCRAM: 307 and 204
components.

The caveat runs the other way here: `go.sum` records what was downloaded,
not what a fresh `go mod tidy` would select.

### 4. Vulnerability IDs — SCRAM 16, grype 12 for `cryptography==3.2`

Compared by **identity, not by ID string**, because OSV and grype report
under different schemes for the same record:

```
SCRAM : PYSEC-2026-2141
grype : GHSA-r6ph-v2qm-q3c2     -- aliases of the same CVE
```

Resolving every ID to its alias group through OSV and using the CVE when
one exists removes the naming difference. What remains:

| | distinct vulnerabilities |
|---|---|
| SCRAM | 16 |
| grype | 12 |
| SCRAM only | CVE-2020-25659, CVE-2024-26130, CVE-2026-69248, CVE-2026-69249 |
| grype only | none |

All four extras are confirmed live in OSV and genuinely affect
`cryptography`; two are 2026 advisories. Grype's database is **not
stale** — it was built the same day (`2026-09-27`, `valid: true`) — so
this is provider coverage, not a caching artefact.

**This is not evidence that SCRAM is better in general.** It is one
ecosystem, one package version, and the disagreement happens to favour
the new tool. Where syft was stronger it went the other way: 10 workspace
components whose real versions SCRAM cannot recover from link entries.

Identical sets once normalized, with per-component attribution matching
exactly: `requests 2.19.1 / jinja2 2.10 / pyyaml 5.1` (14 each),
`urllib3 1.23` (16), `lodash 4.17.4` (0 both), `django 2.0.2` (22 vs 21),
`Pillow 5.0.0` (54 vs 49), `flask+werkzeug` (13 vs 11), `idna 2.7` (5 vs 4).

## The bug this found

syft reported 0 components for `psf/requests`, and SCRAM agreed: 0, CLEAN,
exit 0. The repository's only Python file is a `requirements-dev.txt`
declaring five packages, which had been invisible since the beginning.

Three lists disagreed — the detector listed `requirements.txt` alone, the
resolver's `Handles` claimed fifteen names, and the resolver's own
`Resolve` switch claimed three. Fixed in `160f3e6`; see `DECISIONS.md`
D37.

## osv-scanner could not be used

v2.6.0 publishes no darwin/arm64 release archive, only a raw binary
(SHA256 verified). It resolves packages correctly but reported **zero**
vulnerabilities on inputs where SCRAM and grype both find 14, and its v2
`scan source` JSON emits no `vulnerabilities` array.

The conclusion above rests on syft and grype only. This is stated rather
than left as a silently-zero column in a harness, because a column that
always reads zero looks like a passing result.
