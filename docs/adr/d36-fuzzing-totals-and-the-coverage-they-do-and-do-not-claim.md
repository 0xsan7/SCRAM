# D36 — Fuzzing totals, and the coverage they do and do not claim

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D36

**Title:** Fuzzing totals, and the coverage they do and do not claim

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

Sixteen targets, 150 seconds each:

| target | executions | interesting inputs found |
|---|---|---|
| FuzzNormalizeHash | 11,609,253 | 190 |
| FuzzSpdxID | 8,739,214 | 2 |
| FuzzParseIntegrity | 7,025,250 | 144 |
| FuzzNameFromKey | 5,454,852 | 7 |
| FuzzEmptyComponentList | 3,334,313 | 146 |
| FuzzPEP508 | 2,939,486 | 256 |
| FuzzSplitGoModule | 2,722,000+ | ~30 |
| FuzzMarshalSPDX | 1,290,570 | 82 |
| FuzzGoSum | 646,135 | 91 |
| FuzzRequirementsTxt | 786,445 | 191 |
| FuzzPyprojectToml | 545,491 | 75 |
| FuzzNameFromKey / IsPythonConstraintKey | 545,485 / 2 | 7 / 2 |
| FuzzNpmV1Warning | 198,252 | 173 |
| FuzzNpmLockfile | 194,017 | 37 |
| FuzzPoetryLock | 140,402 | 102 |
| FuzzMarshalCycloneDX | 915,227 | 30 |

**Zero crashes, zero hangs, zero malformed-SBOM reports.** Two real bugs
found, both silent-zero shaped.

Two honest caveats, because the numbers above look better than the coverage
they represent:

- **Executions are not coverage.** The pure string helpers run millions of
  times per session; the JSON and TOML parsers run hundreds of thousands.
  A high execution count on a target with narrow branch coverage is worth
  much less than the raw figure suggests, and the table above does not
  measure coverage.
- **The multi-argument SBOM targets keep their hand-written seeds.** Go's
  corpus encoding for multiple arguments is a typed stream, so a promoted
  file cannot be split into six strings. Those two targets therefore replay
  the hand-written seeds, and only `FuzzSpdxID`, `FuzzNormalizeHash` and
  `FuzzEmptyComponentList` replay promoted files directly. The 190 inputs
  `FuzzNormalizeHash` found are tested; the 30 `FuzzMarshalCycloneDX` found
  are not yet. That is a real gap and it is stated here rather than implied
  away by the total.

---

### Note on the promoted corpus

### Fuzzing that leaves something behind

231 of the fuzzer's "interesting" inputs — the ones that reached coverage the
seed corpus did not — are committed under `testdata/fuzz/`, 116 KB, capped at
64 KB per input with the largest 40 kept per target. They replay as ordinary
`go test` cases, so a shape the fuzzer discovered is still tested when
nobody is fuzzing. Fuzzing that finds a bug and leaves only a cache entry
under `~/Library/Caches` has not been done, only performed.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
