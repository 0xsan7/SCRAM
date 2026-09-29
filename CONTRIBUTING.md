# Contributing to SCRAM

Thanks for considering it. This document covers the two things that actually
matter for contributions here.

## The highest-leverage contribution: a new ecosystem resolver

Adding an ecosystem is the most useful thing you can do, and it should take
about an hour. Ecosystem parsing is a long tail — every lockfile format churns
— and each resolver you add removes a reason for someone to reach for a
heavier tool.

### 1. Write one file

Create `internal/resolve/<ecosystem>.go`:

```go
package resolve

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/0xsan7/scram/internal/model"
)

func init() { Register(cargoResolver{}) }

type cargoResolver struct{}

func (cargoResolver) Ecosystem() string { return "cargo" }

func (r cargoResolver) Resolve(root, path string) ([]model.Component, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil, err
	}
	// parse the lockfile...
	return []model.Component{
		{
			Purl:      makeSimplePURL("cargo", "serde", "1.0.188"),
			Name:      "serde",
			Version:   "1.0.188",
			Ecosystem: "cargo",
			Direct:    true,
		},
	}, nil
}
```

### 2. Register the lockfile for detection

Add one entry to `candidates` in `internal/detect/detect.go`, **ordering
lockfiles before bare manifests** so the most precise source wins:

```go
{Ecosystem: "cargo", File: "Cargo.lock", RelPath: "Cargo.toml"},
```

### 3. Map the ecosystem name for OSV

In `internal/vuln/osv.go`, `osvEcosystem` maps SCRAM's ecosystem names onto
OSV's, which are capitalized differently. Check
<https://ossf.github.io/osv-schema/#affectedpackage-field> for the right
value.

### That's it

Detection, SBOM generation, scoring, drift tracking, policy, and every output
format pick it up automatically. No other file needs to change.

### Rules for resolvers

- **Never shell out to a package manager.** Parse the lockfile directly. A
  scan must not need a network fetch or a build step.
- **Set `Direct` from the manifest**, not the lockfile. Only the root manifest
  states what the project actually asked for; a lockfile flattens everything.
- **Use a real PURL.** Downstream dedup, SBOM output, and the drift engine all
  key on it.
- **Be tolerant of format drift.** Lockfiles gain fields between versions.
  Unknown fields must not break parsing, and a missing optional field must not
  fail the whole scan.

## Testing

```bash
go test ./...
go test -race ./...
```

Tests use real lockfile fixtures, not synthetic ones. When you add a resolver,
commit a real-world lockfile under `testdata/fixtures/<ecosystem>/` — a trimmed
one is fine, but it must be genuine output from the real tool, because
synthetic fixtures miss exactly the fields that break parsers.

A resolver test should cover at least: the current lockfile format, the
previous format if one exists, and a file with unusual-but-valid content.

See [TESTING.md](TESTING.md) for the full testing standard, including what
the silent-zero invariant does **not** cover and the two failure shapes it
structurally cannot see.

## Known-vulnerable roundtrip (required)

**Any resolver or vulnerability matcher, new or existing, must be validated
with a known-vulnerable roundtrip.** Take one real package from the real
corpus that has a known, currently-valid OSV advisory, and assert the matcher
actually returns it.

```bash
go test ./internal/resolve/ -run TestKnownVulnerableRoundtripOffline -v
```

**A correct-looking PURL is not sufficient evidence that the lookup key is
correct.** This is not a hypothetical. Two bugs shipped with perfect PURLs,
plausible names, real versions and green CI:

- **pnpm 6.0** (`9f4ae85`) parsed keys into names like `lodash@4.17.21` with
  an empty version. The component looked plausible and matched nothing. 361
  components instead of 1523, no error.
- **The go.mod fallback** (`af8e58f`) set `Name` to the bare last path
  segment, so `github.com/gin-gonic/gin` was sent to OSV as `gin`. OSV keys
  its Go ecosystem on the **module path**, so it matched nothing and the scan
  reported **CLEAN** — while the same project's `go.sum` reported 9 findings.

The silent-zero invariant caught neither and cannot: it checks that
*resolution produced components*, not that *matching found what a
known-vulnerable package should yield*. A component with a good name and a
correct PURL is exactly what it calls healthy. [TESTING.md](TESTING.md)
documents this limit in full.

Rules for the roundtrip:

- **Use the production lookup path.** A test that constructs its own query
  passes while the shipped code uses the wrong key. The committed test asserts
  through `vuln.Client` and answers from recorded real OSV responses, so it
  needs no network.
- **The stub must return advisories only for the correct key.** A permissive
  fake that answers anything passes while a real registry would not.
- **Cover Go specially.** There is one OSV Go ecosystem, keyed on the module
  path, reached by two different resolvers (`go.sum` and `go.mod`). Both must
  be covered, and where a project ships both files, they must be asserted to
  find the **same** vulnerabilities. That comparison is what exposed
  `af8e58f`.
- **If you add an ecosystem, add it to `scripts/record_osv_fixtures.py`** and
  re-record. The script fails loudly if the recorded package has been
  patched, because an empty recording would let a broken key pass.

## Design principles

These are load-bearing. Please don't work around them.

**Fail closed.** A scan that could not reach its vulnerability sources must
fail, not report a clean result. "No findings" when there was no data is a
false all-clear, and it is the worst thing a security tool can do. Same for a
scan that finds no lockfiles at all.

**Gate on new findings.** Pre-existing findings must not block PRs, or nobody
will adopt the tool. This is why the drift engine exists.

**Be inspectable.** A score a user cannot interrogate is a score they will
turn off. `--explain` must keep showing the arithmetic.

**Keep the dependency footprint minimal.** We ship three non-stdlib
dependencies. CycloneDX, SPDX, SARIF, and the CVSS 3.1 equation are implemented
in-tree on purpose: a supply chain scanner's own supply chain is its
credibility. Adding a dependency needs a good reason.

**Degrade loudly, never silently.** Upstream failures produce warnings that
surface in every output format, including SARIF's invocation notifications.

## Commit messages

Conventional commits, because the changelog is generated from them:

```
fix(resolver): handle npm lockfileVersion 4 "packages" key
feat(score): add OpenSSF Scorecard maintenance component
docs: explain the drift model in the README
```

## Reporting security issues

Please do not open a public issue for a vulnerability in SCRAM. Use GitHub's
private vulnerability reporting, or email the maintainer directly.
