# SCRAM

**Supply Chain Risk Assessment & Monitoring** — *pull the fail-safe on supply chain risk before it ships.*

Most dependency scanners tell you the current state. Almost none of them tell you **what a specific pull request changed**. That gap is what SCRAM fills: drift-aware, PR-native risk delta, with a scoring model you can inspect line by line.

```
$ scram scan .

SCRAM supply chain scan
────────────────────────────────────────────────────────────────
  repo        my-app
  components  412
  findings    3 vulnerability record(s)
  repo score  36/100  LOW

  Drift since baseline
    added 1   version-changed 2   removed 0
    new vulnerabilities 3   resolved 1

  CHG  MEDIUM  pkg:npm/lodash@4.17.11
        score 36/100, 2 finding(s)
        N CVE-2019-10744  cvss 9.1  epss 5.01%  fixed in 4.17.12
        N CVE-2021-23337  cvss 7.2  epss 21.33% fixed in 4.17.21

FAIL  (fail-on: high, new findings only: true)
  - CVE-2019-10744 affects pkg:npm/lodash@4.17.11 (severity critical, at or above fail-on high)
```

---

## Why

A team with 200 pre-existing medium findings will disable any tool that blocks every PR on day one. So SCRAM gates on **new** findings by default:

| Scenario | Default behavior |
|---|---|
| 200 pre-existing mediums, PR changes nothing | **Passes** |
| PR downgrades `lodash` and introduces a 9.1 CVE | **Fails**, naming the CVE |
| A known-unreachable finding with a current waiver | **Passes** |
| Same finding, waiver expired yesterday | **Fails** — expired waivers re-trigger |
| OSV is unreachable | **Fails** — see [Failing closed](#failing-closed) |

That last row matters more than it looks.

## Install

```bash
# macOS / Linux
curl -sSfL https://github.com/0xsan7/SCRAM/releases/latest/download/scram-linux-amd64 -o scram
chmod +x scram && sudo mv scram /usr/local/bin/

# or from source
go install github.com/0xsan7/scram/cmd/scram@latest
```

Ships as a single static binary. No runtime, no config file required.

## Quick start

```bash
scram init                    # write a starter .scram.yml
scram scan                    # scan the current directory
scram baseline update         # capture today's state as the baseline
scram scan                    # now every run reports only what changed
```

## CI integration

```yaml
# .github/workflows/scram.yml
name: SCRAM
on: [pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  scram:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # needed to diff against the base branch

      - uses: 0xsan7/SCRAM@v1
        with:
          fail-on: high
          comment-on-pr: true

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: scram-output/scan.json   # or a .sarif file
```

The Action resolves the baseline from the PR's base branch automatically, so there's no baseline file to maintain. It also updates a single PR comment on each push rather than posting a new one every time.

**Outputs:** `sbom-path`, `repo-score`, `repo-bucket`, `new-critical-count`, `new-high-count`.

## Failing closed

If a vulnerability source is unreachable, SCRAM warns and then **fails the run**. It will not report a clean bill of health it never verified — "no findings" when there was no data is worse than a red build, because it is a false all-clear.

Set `allow_degraded_scan: true` in `.scram.yml` if you accept that risk, for example on a network-isolated runner.

A scan that finds no lockfiles at all is also treated as a failure, not a pass.

## Scoring

Every score is a weighted sum, capped at 100, and `--explain` shows the arithmetic:

```
severity        36 / 40   max CVSS v3 across 7 known vulns
exploitability   5 / 25   EPSS probability × 25
maintenance     0 / 20   OpenSSF Scorecard (not yet integrated)
freshness       0 / 15   version distance behind latest
= total          41 / 100   bucket: medium
```

```bash
scram scan --explain pkg:npm/lodash@4.17.11
```

| Bucket | Score |
|---|---|
| Critical | 90–100 |
| High | 70–89 |
| Medium | 40–69 |
| Low | 1–39 |
| Clean | 0 |

Repo-level severity escalates on count as well as on the max score, because ten high findings are a high-severity situation even when no single component reaches 70.

A component with **no known vulnerabilities scores 0 on severity**. That is deliberate: absence of a CVE is not evidence of safety, so it shouldn't manufacture risk. The freshness and maintenance terms are what surface latent risk in a clean-looking tree.

## Output formats

```bash
scram scan --format table    # human-readable, color-coded, drift-marked
scram scan --format json     # full result object, versioned schema
scram scan --format sarif    # for the GitHub Security tab
```

For `--format json` and `--format sarif`, stdout stays a clean parseable document and the human-readable policy summary goes to stderr, so `scram scan --format json | jq` always works.

Re-render a prior scan without re-querying anything:

```bash
scram scan --format json > scan.json
scram report --from scan.json --format sarif --out results.sarif
```

## SBOMs

CycloneDX 1.5 and SPDX 2.3, generated from the same component list so the two artifacts can never disagree. Validated in CI against the official schema validators.

```bash
scram sbom generate . --format both
```

```yaml
sbom:
  formats: [cyclonedx, spdx]
```

## Configuration

```yaml
version: 1
ecosystems: [npm, pypi, go]    # omit to auto-detect
fail_on: high                  # applies to NEW findings vs baseline
fail_on_existing: false

sbom:
  formats: [cyclonedx, spdx]

sources:
  osv: true
  nvd: false                   # requires NVD_API_KEY
  ghsa: false

waivers:
  - id: CVE-2024-12345
    reason: "Build tooling only, not reachable"
    expires: 2026-12-31        # omit for a permanent waiver

licenses:
  deny: [GPL-3.0-only]

epss: false                    # exploitability scoring; ~2x requests
allow_degraded_scan: false     # fail closed when a source is unreachable
cache_ttl_hours: 6
```

## Ecosystems

| Ecosystem | Reads | Direct/transitive |
|---|---|---|
| npm | `package-lock.json` (v1, v2, v3), `npm-shrinkwrap.json` | from `package.json` |
| PyPI | `requirements.txt`, `poetry.lock`, `Pipfile.lock` | from `pyproject.toml` |
| Go | `go.sum` | from `go.mod` |

Lockfiles are parsed directly — no `npm install`, no build step, no network. Maven, Cargo, and RubyGems are on the roadmap.

### Adding a resolver

This is the highest-leverage contribution and the lowest barrier. Write one file:

```go
package resolve

func init() { Register(cargoResolver{}) }

type cargoResolver struct{}

func (cargoResolver) Ecosystem() string { return "cargo" }

func (r cargoResolver) Resolve(root, path string) ([]model.Component, error) {
    // parse Cargo.lock, return components with Purl set
}
```

Then add the lockfile to `candidates` in `internal/detect`. Nothing else changes — detection, SBOM generation, scoring, drift, policy, and all output formats pick it up automatically.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass |
| 1 | Policy failure — findings at or above threshold |
| 2 | Scanner error — the scan didn't complete |

Distinguishing 1 from 2 lets CI tell "found something" from "the scanner broke."

## Design notes

**Minimal dependencies.** Three non-stdlib imports: `cobra`, `packageurl-go`, `yaml.v3`. For a supply chain tool, its own supply chain is the credibility test. CycloneDX, SPDX, SARIF, and the CVSS 3.1 equation are implemented in-tree rather than pulled in.

**No telemetry.** No phone-home, ever. If usage analytics are added they will be opt-in and disclosed.

**Reproducible output.** Components are sorted, document serial numbers are derived from a hash rather than random, and baselines are written as sorted JSON — so an unchanged repo produces a byte-identical artifact and shows up as no diff.

**Graceful degradation, but not graceful silence.** A downed upstream produces a warning and a partial scan, and the run still fails. Degrading is fine; degrading *silently green* is not.

## Development

```bash
go test ./...
go build ./cmd/scram
./scram scan .          # SCRAM scans itself in CI
```

Requires Go 1.23+.

## License

Apache-2.0 — includes the explicit patent grant, which matters for a security tool enterprises will actually adopt.
