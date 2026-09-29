# SCRAM

**Supply Chain Risk Assessment & Monitoring** — a dependency scanner that
answers the question PR gates actually ask: *what did this change?*

```
 ___  ___ ___    _   __  __ 
/ __|/ __| _ \  /_\ |  \/  |
\__ \ (__|   / / _ \| |\/| |
|___/\___|_|_\/_/ \_\_|  |_|
```

`v0.1.0` · pre-release · no release tag published yet

Most scanners tell you the current state. Almost none tell you what a
specific pull request *changed* — and that is the only question a reviewer
can act on.

```console
$ scram scan --epss
SCRAM supply chain scan
────────────────────────────────────────────────────────────────
  repo        demo-app
  components  1
  findings    2 vulnerability record(s)
  repo score  37/100  LOW
  breakdown   critical 0  high 0  medium 0  low 1  clean 0

  Drift since baseline
    added 0   version-changed 1   removed 0
    new vulnerabilities 1   resolved 4
        new high 1, new critical 0

CHG  LOW       pkg:npm/lodash@4.17.21
         score 37/100, 2 finding(s)
         N GHSA-r5fr-rjxr-66jc cvss 8.1  epss 21.33%  fixed in 4.18.0
           GHSA-f23m-r3pf-42rh cvss 6.5  epss   -    fixed in 4.18.0

FAIL  (fail-on: high, new findings only: true)
  - GHSA-r5fr-rjxr-66jc affects pkg:npm/lodash@4.17.21 (severity high, at or above fail-on high)
```

*Real output, from `./examples/lodash-drift/run.sh`: `lodash` 4.17.11 →
4.17.21 in a git repo with a committed baseline. The `commit` line is the
one field that differs on every run; everything else is reproduced
byte-for-byte, including the FAIL and the exit code. Run the script to
confirm it against whatever OSV says today.*

---

## Contents

- [Why drift beats a score](#why-drift-beats-a-score)
- [Install](#install)
- [Quick start](#quick-start)
- [What a real finding looks like](#what-a-real-finding-looks-like)
- [Failing closed](#failing-closed)
- [Scoring, in the open](#scoring-in-the-open)
- [CI integration](#ci-integration)
- [Output formats](#output-formats)
- [Configuration](#configuration)
- [Ecosystems](#ecosystems)
- [Limitations](#limitations)
- [Design notes](#design-notes)
- [Development](#development)

---

## Why drift beats a score

A team with 200 pre-existing medium findings will switch off any tool that
blocks every PR on day one. So SCRAM gates on **new** findings by default,
and treats a baseline as a first-class input.

| Situation | Default result |
|---|---|
| 200 pre-existing mediums, PR changes nothing | **Passes** |
| PR bumps `lodash` 4.17.11 → 4.17.21, which *resolves* four findings and pulls in an 8.1 one | **Fails**, naming `GHSA-r5fr-rjxr-66jc` |
| A known-unreachable finding with a current waiver | **Passes** |
| Same finding, waiver expired yesterday | **Fails** — expired waivers re-trigger |
| OSV is unreachable | **Fails** — see [Failing closed](#failing-closed) |
| Lockfile present, zero components resolved | **Fails** — see [Failing closed](#failing-closed) |

The last two matter more than they look. Both are cases where the honest
answer is "I don't know", and a scanner that answers "clean" is worse than
one that fails, because the failure is visible.

Two supporting commands exist for the case where *when* something landed
matters as much as what it is:

```console
$ cd /tmp && git clone https://github.com/lodash/lodash.git && cd lodash
$ scram blame pkg:npm/ajv@6.10.2

pkg:npm/ajv@6.10.2
  current version   6.10.2
  introduced       8.1y ago, eaa9f36, by John-David Dalton
                     at 5.5.2
  last changed      7.2y ago, b185fce, by John-David Dalton
                     to 6.10.2 — Rebuild lodash and docs.
  commits scanned   16

  Version history:
   * 5.5.2      eaa9f36       8.1y ago  John-David Dalton
     6.10.2     b185fce       7.2y ago  John-David Dalton
```

An advisory disclosed against a package that has been pinned for two years
is a different problem from one disclosed against a package added last
week. `scram why` answers the related question of *how* it got in —
direct or transitive, and via what.

In a **shallow clone** (`git clone --depth 1`, which is what CI does by
default) blame refuses to guess, and says so rather than reporting the
clone date as the arrival date:

```
$ git clone --depth 1 https://github.com/lodash/lodash.git && cd lodash
$ scram blame pkg:npm/ajv@6.10.2

pkg:npm/ajv@6.10.2
  current version   6.10.2
  WARNING           shallow clone: this is the first commit in the LOCAL history, not necessarily when the dependency arrived
  first seen       17d ago, 2b5e6f7, by Jon Church
                     at 6.10.2
  commits scanned   1
```

Note the difference against the same command in the full clone above:
`17d ago ... first seen` instead of `8.1y ago ... introduced at 5.5.2`. The
commit hash and date are the clone's, not the project's.

## Install

SCRAM is a single static binary with no runtime dependencies. Every
release is published for five platforms, checksummed, and signed
keyless.

```bash
# Pick the asset for your platform and verify it before running it.
VERSION=0.1.0-rc1
BASE=https://github.com/0xsan7/SCRAM/releases/download/v$VERSION

curl -sSfLO "$BASE/scram_${VERSION}_checksums.txt"      # note: underscores
curl -sSfLO "$BASE/scram-$VERSION-linux-amd64"          # or -darwin-arm64, -linux-arm64, -windows-amd64.exe
curl -sSfLO "$BASE/scram-$VERSION-linux-amd64.pem"
curl -sSfLO "$BASE/scram-$VERSION-linux-amd64.sig"

# Verify just the binary you downloaded; -c against the whole file would
# also report the four platforms you did not download as failures.
grep "linux-amd64$" scram_${VERSION}_checksums.txt | shasum -a 256 -c -
# Linux: the same works with sha256sum

cosign verify-blob \
  --certificate scram-$VERSION-linux-amd64.pem \
  --signature    scram-$VERSION-linux-amd64.sig \
  --certificate-identity-regexp 'https://github.com/0xsan7/SCRAM/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  scram-$VERSION-linux-amd64
```

`Verified OK` means the binary is the one this repository's CI built and
signed for this tag; the signature is in the public Rekor log, so you
do not have to trust GitHub to tell you so. See
[the v0.1.0-rc1 release](https://github.com/0xsan7/SCRAM/releases/tag/v0.1.0-rc1)
for the full asset list, and the release notes there for the same
instructions in copy-pasteable form.

Build from source instead:

```bash
git clone https://github.com/0xsan7/SCRAM.git && cd SCRAM
go build -o scram ./cmd/scram
```

## Quick start

Requires Go 1.23+. No config file is required; no network is needed to
resolve dependencies.

```bash
git clone https://github.com/0xsan7/SCRAM.git && cd SCRAM
go build -o scram ./cmd/scram

./scram init                    # write a starter .scram.yml
./scram scan --epss             # scan the current directory
./scram baseline update         # capture today's state as the baseline
```

Then change a dependency and scan again:

```bash
./scram scan --epss
```

The second run reports what changed against the baseline and gates on what
is new.

To reproduce the output at the top of this file exactly, run the script
that generates it. It builds the project, the git repository, the
baseline, and the bump — every step, nothing transcribed:

```bash
./examples/lodash-drift/run.sh
```

It takes about ten seconds, needs no Node toolchain, and prints the
summary above along with the exit code the gate returned.

## What a real finding looks like

```
   MEDIUM    pkg:npm/lodash@4.17.11
         score 41/100, 5 finding(s)
           GHSA-jf85-cpcp-j695 cvss 9.1  epss 5.01%  fixed in 4.17.12
           GHSA-p6mc-m468-83gw cvss 7.4  epss 5.21%  fixed in 4.17.19
           GHSA-35jh-r3h4-6jhm cvss 7.2  epss 21.33%  fixed in 4.17.21
           GHSA-f23m-r3pf-42rh cvss 6.5  epss   -    fixed in 4.18.0
           GHSA-29mw-wpgm-hmr9 cvss 5.3  epss 7.34%  fixed in 4.17.21
```

Every field is real OSV data plus FIRST.org EPSS, and the component is
matched by PURL, so a transitive package is found without a guess about
the dependency path.

## Failing closed

If a vulnerability source is unreachable, SCRAM warns **and fails the run**.
It will not report a clean bill of health it never verified.

The same applies to resolution. A file that declares dependencies and
resolves **zero** of them is treated as an operational failure, not a
clean scan — the failure mode this whole project exists to eliminate,
found five separate times in its own corpus and fixed each time. A
genuinely dependency-free project (a `pyproject.toml` with no
`dependencies` key) is still a valid pass, and the two are told apart by
counting declarations independently of the parser.

```yaml
allow_degraded_scan: true     # opt in to a partial scan, e.g. an air-gapped runner
```

## Scoring, in the open

Every number is a weighted sum, and `--explain` prints the arithmetic:

```console
$ scram scan --epss --explain pkg:npm/lodash@4.17.11

pkg:npm/lodash@4.17.11
  ecosystem     npm
  direct        true
  license       MIT

  severity         36 / 40   (max CVSS v3 across 5 known vulns)
      GHSA-jf85-cpcp-j695 CVSS 9.1     EPSS 0.0501
      GHSA-p6mc-m468-83gw CVSS 7.4     EPSS 0.0521
      GHSA-35jh-r3h4-6jhm CVSS 7.2     EPSS 0.2133
      GHSA-f23m-r3pf-42rh CVSS 6.5     no EPSS
      GHSA-29mw-wpgm-hmr9 CVSS 5.3     EPSS 0.0734

  exploitability    5 / 25   (EPSS probability x 25)
  maintenance       0 / 20   (OpenSSF Scorecard, not yet integrated)
  freshness         0 / 15   (version distance behind latest)

  = total          41 / 100   bucket: medium
```

| Bucket | Score |
|---|---|
| Critical | 90–100 |
| High | 70–89 |
| Medium | 40–69 |
| Low | 1–39 |
| Clean | 0 |

Two deliberate choices, both load-bearing:

- **A component with no known vulnerabilities scores 0 on severity.**
  Absence of a CVE is not evidence of safety, so it must not manufacture
  risk. The freshness and maintenance terms are what surface latent risk in
  a clean-looking tree.
- **The repo score escalates on count as well as on the max component
  score**, because ten high findings are a high-severity situation even
  when no single component reaches 70.

`maintenance` is scored 0/20 today and says so in the output — the
OpenSSF Scorecard integration is not built.

## CI integration

> **The action ref must be a version tag.** It installs the binary published
> under that same tag, so `uses: 0xsan7/SCRAM@v0.1.0-rc2` gets exactly
> `0.1.0-rc2`. A branch or SHA cannot name a release, and the action fails
> with an explicit message rather than downloading something unverified.

```yaml
# .github/workflows/scram.yml
name: SCRAM
on: [pull_request]

permissions:
  contents: read
  security-events: write      # required by upload-sarif
  pull-requests: write        # required by comment-on-pr

jobs:
  scram:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # blame needs real history; see above

      - uses: 0xsan7/SCRAM@v0.1.0-rc2
        with:
          fail-on: high
          comment-on-pr: true
          upload-sarif: true
```

That is the whole workflow. `upload-sarif: true` uploads from inside the
action, so there is no second `codeql-action` step to add — the previous
version of this section had one, and it was both wrong (`category` was
misindented out of `with:`) and redundant.

The minimum is `uses` and nothing else:

```yaml
      - uses: 0xsan7/SCRAM@v0.1.0-rc2
```

**No token is required.** A composite action cannot read the `secrets`
context at all — the runner rejects the whole manifest if one tries — so
the token arrives through a `github-token` input that defaults to
`${{ github.token }}`, the workflow's own token. Override it only if you
need permissions the workflow's token does not have:

```yaml
        with:
          github-token: ${{ secrets.MY_PAT }}
```

The action verifies the downloaded binary against the release's published
`sha256` before running it, so a truncated download or a tampered asset
fails the step instead of being scanned.

The Action resolves the baseline from the PR's base branch, so there is no
baseline file to maintain, and it updates a single PR comment rather than
posting a new one on every push.

`fetch-depth: 0` matters: with the default depth of 1, `scram blame`
correctly refuses to report an introduction date (see above), so the
command still works but tells you less.

**`upload-sarif: true`** produces `scram-output/scan.sarif` and uploads it
itself, using the same `github-token` input. SARIF is written to stdout
and redirected, because `--out` is the SBOM directory — the machine
formats keep stdout a single valid document by design. The step verifies
the output really is SARIF 2.1.0 before handing it over, because an
invalid upload is dropped silently by the Security tab and looks
identical to "no vulnerabilities found".

**Outputs:** `sbom-path`, `repo-score`, `repo-bucket`, `new-critical-count`,
`new-high-count`.


## Output formats

```bash
scram scan --format table    # human-readable, color-coded, drift-marked
scram scan --format json     # full result object, versioned schema
scram scan --format sarif    # for the GitHub Security tab
```

For `--format json` and `--format sarif`, stdout stays a clean parseable
document and the human-readable policy summary goes to stderr, so
`scram scan --format json | jq` always works.

Re-render a prior scan without re-querying anything:

```bash
scram scan --format json > scan.json
scram report --from scan.json --format sarif --out results.sarif
```

A self-score badge, for a README. It reads a scan document rather than
taking a number, so the badge cannot claim a score nobody measured:

```bash
scram scan --format json > scan.json
scram badge --in scan.json
# {"schemaVersion":1,"label":"self score","message":"36/100 low","color":"yellowgreen"}
```

## Configuration

Every key below is read by the tool; there are no aspirational ones.

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

ignore_paths: [vendor, third_party]

epss: false                    # exploitability scoring; ~2x requests
allow_degraded_scan: false     # fail closed when a source is unreachable
offline: false                 # cache-only operation
cache_ttl_hours: 6
```

## Ecosystems

| Ecosystem | Reads | Direct/transitive from |
|---|---|---|
| npm | `package-lock.json` (v1, v2, v3), `npm-shrinkwrap.json` | `package.json` |
| PyPI | `requirements.txt` and 14 other requirements filenames (`requirements-dev.txt`, `dev.txt`, `constraints.txt`, …), `poetry.lock`, `Pipfile.lock`, `pyproject.toml` (PEP 621 + Poetry) | `pyproject.toml`, `requirements.txt` |
| Go | `go.sum` | `go.mod` |

Lockfiles are parsed directly — no `npm install`, no build step, no network
access to a package registry. Maven, Cargo, and RubyGems are not
implemented.

Two behaviours worth knowing, both tested:

- **A lockfile always outranks a manifest.** A project with both
  `poetry.lock` and `pyproject.toml` is read through the lockfile, because
  the lockfile carries exact installed versions and the manifest only
  ranges.
- **Poetry's `python = ">=3.9"` is an interpreter constraint, not a
  package.** It is never emitted as a component named `python`.

### Adding a resolver

The highest-leverage contribution and the lowest barrier. This walkthrough
was executed against the current registry — the `dummy` ecosystem below
resolved, produced SBOMs, SARIF, scores, and drift with no other code
changed.

**1. Write the resolver.** One file, `internal/resolve/<name>.go`:

```go
package resolve

func init() { Register(cargoResolver{}) }

type cargoResolver struct{}

func (cargoResolver) Ecosystem() string { return model.EcoCargo }

func (r cargoResolver) Resolve(root, path string) ([]model.Component, error) {
    // parse Cargo.lock, return components with Purl set
    return nil, nil
}
```

**2. Declare the ecosystem** in `internal/model/model.go`, next to the
existing ones:

```go
const (
    EcoNPM   = "npm"
    EcoPyPI  = "pypi"
    EcoGo    = "go"
    EcoCargo = "cargo"   // add yours
)
```

`detect.go` uses plain strings rather than these constants, so in step 4
write the literal (`{Ecosystem: "cargo", ...}`) — the package does not
import `model`.

**3. Teach OSV about it** in `osvEcosystem` in `internal/vuln/osv.go`. The
map is small and it returns `false` for anything unknown, so without this
step your components are detected, scored, and shipped — and silently
never vulnerability-matched, with a warning rather than a failure:

```go
func osvEcosystem(eco string) (string, bool) {
    switch eco {
    case model.EcoCargo:
        return "crates.io", true
    ...
    }
    return "", false
}
```

**4. Add the lockfile to `candidates`** in `internal/detect/detect.go`:

```go
{Ecosystem: "cargo", File: "Cargo.lock", RelPath: "Cargo.toml"},
```

**Expect one test to fail and fix it.** `TestResolverRegistry` in
`internal/resolve/resolve_test.go` asserts `len(Supported()) == 3` and
expects `cargo` to be unregistered. Both are correct today and both are
wrong the moment you add an ecosystem:

```go
-	if _, err := GetFor("cargo", "Cargo.lock"); err != ErrUnsupported {
-		t.Error("expected ErrUnsupported for an unregistered ecosystem")
-	}
-	if len(Supported()) != 3 {
-		t.Errorf("Supported() = %v, want 3 ecosystems", Supported())
-	}
+	if _, err := GetFor("nonesuch", "nope.lock"); err != ErrUnsupported {
+		t.Error("expected ErrUnsupported for an unregistered ecosystem")
+	}
+	if len(Supported()) != 4 {
+		t.Errorf("Supported() = %v, want 4 ecosystems", Supported())
+	}
```

Only the first matching candidate per ecosystem per directory is used, so
ordering is a fallback chain: a lockfile must come before a manifest.

That is the whole change. Detection, SBOM generation (both formats),
scoring, drift, policy, and every output format pick it up automatically —
verified, not assumed.

**What you also owe the project.** A resolver that declares dependencies
and resolves zero is a silent false clean, and the invariant that catches
it needs a real corpus to be worth anything. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the required fixture corpus,
invariant test, fuzz target, and mutation audit.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass |
| 1 | Policy failure — findings at or above threshold |
| 2 | Scanner error — the scan did not complete |

Telling 1 from 2 is what lets CI distinguish "found something" from "the
scanner broke".

## Limitations

[See LIMITATIONS.md](LIMITATIONS.md) for the full list. The two most likely
to matter to you:

- **npm v1 lockfiles carry no `dev`/`optional`/`peer` flags**, so a v1
  scan cannot separate production from test-only dependencies. Real v1
  fixtures are covered; the *distinction* is not derivable from the format.
- **PyPI ranges resolve to their floor.** A `>=2.1.2` requirement is
  recorded as 2.1.2, which is the best a ranged declaration allows and is
  *not* the same as a lockfile's exact version.

## Design notes

**Minimal dependencies.** Four non-stdlib imports: `cobra`,
`packageurl-go`, `yaml.v3`, and `BurntSushi/toml`. For a supply chain tool,
its own supply chain is part of the credibility test — the TOML parser was
added specifically because hand-rolling one to avoid a dependency was the
worse trade.

**No telemetry.** No phone-home. If usage analytics are ever added they will
be opt-in and disclosed.

**Reproducible output.** Components are sorted, serial numbers derive from a
hash rather than randomness, and baselines are written as sorted JSON, so an
unchanged repo produces a byte-identical artifact and shows up as no diff.

**Degrading is fine; degrading silently green is not.** A downed upstream
produces a warning, a partial scan, and a failing exit code.

**Validated, not asserted.** The CycloneDX and SPDX output is checked
against the official schemas in CI, and a mutation audit re-breaks each
fixed bug to confirm the test suite catches its return.

## Development

```bash
go build ./cmd/scram
go test ./...                                   # 229 tests
go test ./internal/resolve/ -run '^$' -bench . -benchmem

# validation tooling, all runnable offline against the committed corpus
python3 scripts/test_fetch_corpus.py            # fetcher regression tests
python3 scripts/mutation_audit.py               # re-break each fix, expect red
go test ./internal/resolve/ -run '^Fuzz' -count=1
```

Benchmarks and the baseline they were measured against: [BENCHMARKS.md](BENCHMARKS.md).
Decision log, including every bug the corpus and fuzzing found:
[DECISIONS.md](DECISIONS.md).

## Project documents

Each of these exists because something in the repository needed to be
stated somewhere a reader would look for it.

| Document | What it is for |
|---|---|
| [ROADMAP.md](ROADMAP.md) | What is not built yet, ordered, with the evidence for each gap |
| [docs/STATUS.md](docs/STATUS.md) | Every phase and item, DONE / PARTIAL / NOT STARTED, with a commit hash or a measurement |
| [docs/BLOCKED.md](docs/BLOCKED.md) | What could not be done here and why — including everything unverified |
| [DECISIONS.md](DECISIONS.md) | Every bug found and what it changed, numbered and indexed |
| [RELEASE-NOTES.md](RELEASE-NOTES.md) | How release notes are generated, and why there is no committed CHANGELOG.md |
| [docs/adr/](docs/adr/) | The same 27 decisions as one MADR file each, with a generated index and a check that no content was lost in the split |
| [LIMITATIONS.md](LIMITATIONS.md) | Where the tool is wrong or incomplete, checked rather than asserted |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Resolver, fixture, fuzzing and schema standards |
| [REPRODUCIBILITY.md](REPRODUCIBILITY.md) | The differential comparison, and exactly where it diverges |
| [BENCHMARKS.md](BENCHMARKS.md) | Measured numbers and the machine they were taken on |
| [OVERNIGHT_REPORT.md](OVERNIGHT_REPORT.md) | The most recent working session, including what it could not verify |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |
| [GOVERNANCE.md](GOVERNANCE.md) | Who decides, and the three things a maintainer may not do alone |
| [SUPPORT.md](SUPPORT.md) | What this project will and will not help with |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Expectations |

## License

Apache-2.0 — includes the explicit patent grant, which matters for a
security tool enterprises will actually adopt.
