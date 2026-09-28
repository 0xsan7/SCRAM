# D29 — Resolver precedence was init() order, and nothing in the type said so

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D29

**Title:** Resolver precedence was init() order, and nothing in the type said so

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

The pyproject commit (D28) generalised the registry from `map[string]Resolver`
to `map[string][]Resolver` with filename dispatch. Every ecosystem routes
through that path now, Go and npm included, even though the bugs were all
PyPI-side -- so the question worth asking is whether the generalisation
quietly cost anything elsewhere.

**No regression in behaviour.** The 80-fixture corpus was run through the
pre-change commit (`7f6aaf2`) in a separate worktree and compared
per-fixture, because matching totals can hide a compensating pair of errors:

| ecosystem | files | before | after |
|---|---|---|---|
| go | 63 | 11,613 | 11,613 |
| npm | 10 | 10,840 | 10,840 |
| pypi | 7 | 323 | 323 |

**Zero per-file differences across all 80.** Plus 44 pyproject.toml files
(32 resolved, 12 correctly zero, 0 mismatches). 124 files, no change.

**But the precedence rule was incidental, and that is a real defect.**

`GetFor` scanned the resolver slice BACKWARDS and returned the first match.
That works only because Go runs `init()` in file presentation order, so
`pypi.go` registers before `pyproject.go`. Go's specification does not
guarantee that ordering, and nothing in `Register` or the registry type said
which resolver was supposed to win. Renaming `pyproject.go` to
`zz_pyproject.go` would have silently swapped which resolver handled which
file, and every test would still have passed.

Precedence is now explicit. A resolver may implement `Prioritised`:

- `PriorityLockfile` (20) — reads a lockfile, reports exact versions
- `PriorityManifest` (10) — reads a manifest, can only report a range

`GetFor` picks the highest-priority resolver that claims the file, falling
back to the highest-priority resolver overall so the previous
`ErrUnsupported` behaviour is unchanged. A resolver that implements neither
interface defaults to `PriorityLockfile`, so Go and npm behave exactly as
before without needing changes.

The rule that matters is stated in one place: **within an ecosystem, a lockfile
resolver outranks a manifest resolver**, because a lockfile records what was
installed and a manifest records what was asked for. If Go later grows a
`vendor/modules.txt` alongside `go.mod`, or npm grows a `bun.lockb`, they
inherit that rule rather than rediscovering it.

### Two tests that were passing for the wrong reason

`TestPrioritiesAreDeclaredForEveryMultiResolverEcosystem` immediately failed:
`pypiResolver` had no `Priority` method, because the patch that was supposed
to add it had not matched. It would have shipped as a lockfile resolver
winning by default and by luck.

`TestScanFailsWhenResolverReturnsNothingForADeclaringFile` failed for the
mirror-image reason. Its `brokenResolver` implemented `FileMatcher` but not
`Prioritised`, so it tied with the real resolver and lost on registration
order -- the real resolver ran, and the test asserted the guard while
exercising nothing. This is the third time in this project that a test
stopped testing anything after the code beneath it changed shape (the first
was the `ResolveFile` path bug, the second the same test's missing
`Handles`). Each was found by a test failing for an unexpected reason, not by
inspecting the test. The guard assertion I added last commit is what surfaced
it; without it the test would have gone green.

A fourth, of a different kind: the dispatch tests register synthetic
resolvers under ecosystem names `test` and `test2`. Restoring only
`registry[eco]` in `t.Cleanup` left those new keys behind, and a later
`Supported()` assertion in an unrelated test then saw five ecosystems instead
of three. The tests share one package-level registry, so a test that leaves it
dirty breaks a test that has nothing to do with it. `withRegistry` now
snapshots and restores the whole map.

**Standing rule, extended:** a test helper that installs a replacement must
assert the replacement is in effect, and must restore shared state completely.
Both cost one line and both have now caught a real defect.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
