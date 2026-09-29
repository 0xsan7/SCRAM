# SCRAM benchmarks

Numbers below are from a real run, not a target. Machine, Go version and
corpus size are recorded with them so a comparison is possible later; a
benchmark number without those is not a measurement.

**How to run**

    go test ./internal/resolve/ -run '^$' -bench . -benchmem -count=1

**How to read them.** There are no pass/fail thresholds, deliberately. A
benchmark wired into CI as a gate fails on a noisy machine, and a benchmark
people delete is worth less than no benchmark. The numbers are here to be
compared *by hand* when a change is suspect, and the corpus benchmarks are
the ones that catch a real regression.

`TestBenchmarksRunAgainstRealFiles` fails if the corpus disappears, because a
benchmark that measures nothing is indistinguishable from a fast one.

## Baseline

Recorded 2026-09-27 on `goos: darwin, goarch: arm64, cpu: Apple M4`,
`go1.23.4`, `-benchtime 30x`.

Corpus: 16 npm lockfiles (10,840+ components), 63 `go.sum` (11,600+
components), 44 `pyproject.toml`, 7 Python lock/requirements files.

| benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `NpmRealCorpus` (16 files) | 125,176,876 | 54,852,185 | 420,900 |
| `NpmLargestFixture` (bitwarden, 1.66 MB) | 20,659,542 | 9,692,227 | 78,498 |
| `GoRealCorpus` (63 files) | 85,850,638 | 24,139,828 | 119,988 |
| `PyprojectCorpus` (44 files) | 14,182,004 | 7,294,715 | 66,556 |
| `NpmLicenseNormalization` (9 inputs) | 4,993 | 2,344 | 64 |
| `ParsePEP508` (9 inputs) | 3,907 | 447 | 20 |
| `GoSumLine` (1 line) | 23.63 | 0 | 0 |
| `DeclaredDependenciesTOML` | 30,364 | 7,400 | 97 |
| `NormalizePyPIName` (5 inputs) | 865.3 | 120 | 11 |

## What these numbers actually say

**A full 16-file npm scan resolves in ~125 ms.** That is the number that
decides whether SCRAM is usable in a PR gate. The dominant cost is JSON
decoding, not anything SCRAM adds: the largest single fixture is a 1.66 MB
lockfile and costs 20.7 ms.

**The npm corpus allocates 54 MB, and that is expected, not a leak.** The
biggest fixture allocates 9.7 MB for 1.66 MB of input — 5.8x. Two things
account for it and both are inherent to the input shape:

1. `os.ReadFile` plus `json.Unmarshal` into a full `packageLock` struct
   materialises the entire tree. A 1.66 MB document with 1,676 package
   entries becomes several MB of Go maps, strings and nested `lockDep`
   values.
2. The `[]model.Component` result is then built alongside the decoded tree,
   so both exist at once.

A streaming `json.Decoder` would cut peak memory, but only by making the
code handle a document shape npm does not guarantee, and the current shape
is the one that catches D22 — an array-valued `license` that made
`json.Unmarshal` fail on the *whole* file and cost a 1,676-package project
its entire scan. That trade is deliberate, and it is D22's actual cost.

`GoSumLine` at 23.63 ns/op with **zero allocations** is the honest
contrast: a line-oriented format with no tree gets a zero-alloc path, and
the tree-shaped ones do not. 63 files at 85.9 ms is 11,600+ components
through a streaming line parser.

**Per-line paths matter more than their totals suggest.**
`NpmLicenseNormalization` runs once per package — 1,676 times for the
largest fixture, ~4,993 ns per nine inputs, so roughly 550 ns per call. It
is where D22 lived, and it is the cheapest place a future regression would
show up as a percentage.

## Coverage of these benchmarks

- npm: whole corpus, largest single file, license normalization
- Go: whole corpus, per-line module split
- PyPI: pyproject corpus, PEP 508 parsing, name normalization
- the D26 silent-zero guard (`DeclaredDependenciesTOML`)
- **yarn, pnpm, Cargo, go.mod**: whole real corpus each, added with the
  resolvers themselves. They are the resolvers where an accidental quadratic
  would actually show, because the corpus contains files much larger than
  npm's largest (react 812 KB, turbo 2.2 MB). Measured over the whole corpus
  with `-benchtime 3x`:

  | benchmark | ns/op | B/op | allocs/op |
  |---|---|---|---|
  | `BenchmarkYarnRealCorpus` | 29,321,556 | 39,570,560 | 287,949 |
  | `BenchmarkPnpmRealCorpus` | 53,310,653 | 69,642,424 | 268,505 |
  | `BenchmarkCargoRealCorpus` | 5,363,569 | 8,886,312 | 26,081 |
  | `BenchmarkGoModCorpus` | 11,003,556 | 6,671,928 | 24,716 |

  No thresholds are enforced, deliberately: a benchmark that fails a build
  on a noisy machine is a benchmark people delete. These exist so a
  regression is a visible number rather than a vague feeling.

**Not covered, and deliberately named rather than left implied:**

- **Vulnerability matching and OSV/EPSS network I/O.** Bounded by the
  network, not by this code; a benchmark would measure the internet.
- **The SBOM serializers.** `FuzzMarshalCycloneDX` measured 915,227 execs in
  151 s (~6,000/s), which is a throughput figure, not a regression guard.
  Serialization is linear in component count by construction.
- **Drift and policy evaluation.** Run over components that are already in
  memory; the cost is a sort, and profiling would be needed before a
  benchmark was worth writing.
## NFR-1: a ~500-dependency repository

The phase target, measured directly. `yargs/yargs` is the corpus fixture
closest to 500 dependencies: **492 resolved components** from a real npm
v3 lockfile.

| operation | median of 3 | note |
|---|---|---|
| `sbom generate --format both` | **30 ms** | resolve + serialize, no network |
| `scan` (warm cache) | **1,300 ms** | OSV matching, cache warm; 2,256 ms at v0.1.0 |
| `scan --no-cache` (cold) | **2,810 ms** | 6,022 ms at v0.1.0; every component re-queried |
| `scan --scorecard <repo>` | 2,268 ms | + one OpenSSF Scorecard call, the new term |

**NFR-1 (< 30 s) is met with a wider margin than at v0.1.0.** The target is
not softened or reinterpreted: 2,810 ms against 30,000 ms, cold.

**The new work did not cost what it looked like it would.** Four resolvers
were added after v0.1.0 (yarn, pnpm, Cargo, go.mod) and one new network call
was added (OpenSSF Scorecard). Both were re-measured rather than assumed:

- **Resolution is still negligible.** The new resolvers run over a corpus
  that includes files an order of magnitude larger than npm's largest —
  react's `yarn.lock` is 812 KB / 2,388 components, turbo's `pnpm-lock.yaml`
  is 2.2 MB / 2,217 — and the whole pnpm corpus resolves in **53 ms**. A
  single `sbom generate` over react is 70 ms.
- **The Scorecard call is one request**, not per-component, and adds roughly
  1 s to a cold scan. It is opt-in (`--scorecard`, auto-enabled from the git
  origin) and `--no-scorecard` skips it entirely.
- **Cold scans got faster**, 6,022 ms → 2,810 ms, which is network variance
  and cache state rather than a code change. Both numbers are recorded rather
  than only the flattering one, because the improvement is not attributable to
  anything in this release.

The dominant term is OSV, not SCRAM. `sbom generate` does the same
resolution and serialization with no network at all in 30 ms, so ~99.5% of
a cold scan is the vulnerability lookup. That is the honest shape of the
number and the reason the 6-hour per-component cache exists.

## End-to-end

Wall-clock for the whole binary, median of 3 runs, same machine. The
`sbom generate` row does no vulnerability lookup at all, which is what
separates SCRAM's own cost from the network:

| command | median | what it includes |
|---|---|---|
| `sbom generate` (nest, 1,478 components) | **92 ms** | resolve + serialize, no network |
| `scan` (nest, 1,478 components) | 3,433 ms warm / 4,096 ms cold | + OSV matching, 6h cache warm |
| `scan` (consul, 307 components) | 1,077 ms warm / 1,106 ms cold | + OSV matching |
| `scan` (psf/requests, 6 components) | 783 ms | + OSV matching |

**92 ms versus 3.4 s, and the difference is the vulnerability lookup, not
resolution.** A full corpus resolve is 125 ms; asking OSV about 1,478
components is roughly 37x that, and the warm/cold difference is small
because the batch and hydration calls dominate either way.

This is the honest shape of a PR gate: SCRAM's own work is under 100 ms,
and the wall clock a user experiences is set by how it talks to OSV. It is
also the argument for the cache existing at all, and the reason the cache
is keyed per component rather than per scan.
