# D40 — Benchmarks, and the number that was not a leak

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D40

**Title:** Benchmarks, and the number that was not a leak

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

Section 5. Nine benchmarks in `internal/resolve/bench_test.go`, run against
the real corpus rather than synthetic input, with `BENCHMARKS.md` recording
the baseline together with the machine, Go version and corpus size, because
a benchmark number without those is not a measurement.

**No pass/fail thresholds, deliberately.** A benchmark wired as a CI gate
fails on a noisy machine, and a benchmark people delete is worth less than
none. `TestBenchmarksRunAgainstRealFiles` fails if the corpus disappears,
since a benchmark measuring nothing looks exactly like a fast one.

### The 54 MB question

`NpmRealCorpus` allocates 54 MB per iteration, and the largest single
fixture allocates 9.7 MB for a 1.66 MB lockfile — 5.8x the input, 78,497
allocations. That is the number worth interrogating, because "allocates 5x
its input" is what a leak looks like before it is.

It is not a leak. Two things account for it, both inherent to the input:

1. `os.ReadFile` plus `json.Unmarshal` into a full `packageLock` struct
   materialises the entire tree — 1,676 entries become several MB of Go maps,
   strings and nested `lockDep` values.
2. The `[]model.Component` result is built alongside the decoded tree, so
   both are live at once.

A streaming `json.Decoder` would cut peak memory, at the cost of handling a
document shape npm does not guarantee. **The current shape is what caught
D22** — an array-valued `license` that made `json.Unmarshal` fail on the
*entire* file and cost a 1,676-package project its whole scan. That is a
deliberate trade and D22 is its price, so it belongs in the record rather
than in a TODO.

`GoSumLine` at 23.63 ns/op with **zero allocations** is the honest
contrast: a line-oriented format with no tree gets a zero-alloc path, and
the tree-shaped ones do not.

### What actually determines whether SCRAM is usable in a PR gate

| command | median | includes |
|---|---|---|
| `sbom generate` (nest, 1,478 components) | **92 ms** | resolve + serialize, no network |
| `scan` (nest, 1,478 components) | 3,433 ms warm | + OSV matching |
| `scan` (consul, 307 components) | 1,077 ms warm | + OSV matching |

SCRAM's own work is under 100 ms; the wall clock a user experiences is set
by asking OSV about 1,478 components, roughly 37x the resolve cost. The
warm/cold difference is small (3,433 vs 4,096 ms) because batch and
hydration calls dominate either way, which is the argument for the 6-hour
per-component cache and the reason it is keyed per component rather than per
scan.

### Two benchmark bugs, in the benchmarks themselves

`BenchmarkDeclaredDependenciesTOML` failed on the first run with `declared
0, want 2`, and the second attempt with `declared 3, want 2`. The code was
right both times: my first fixture put `dependencies` after a table header,
so TOML parsed it inside `[project.optional-dependencies]`, and the second
assertion still said 2 when there were 3. A benchmark that fails on its own
fixture is indistinguishable from one that found a real defect, so it is
worth recording that the fix was to the fixture, not the assertion, both
times.

The other is more interesting. I wrote a benchmark calling
`flexString.spdxExpression()` and the compiler said no such method — the
array-to-SPDX join I remembered is inline in `UnmarshalJSON`, not a method.
A benchmark for the D22 hot path that benchmarks a function that does not
exist would have been deleted rather than fixed, taking the coverage with
it. The benchmark now drives `UnmarshalJSON` directly, which is the path
that actually runs 1,676 times for the largest fixture.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
