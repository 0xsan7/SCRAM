# D26 — The silent-zero invariant, and a guard that disabled itself

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D26

**Title:** The silent-zero invariant, and a guard that disabled itself

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

D01, D22, and D23 were three instances of one shape: a resolver returned an
empty slice, and nothing downstream could tell that apart from a repository
that genuinely has no dependencies. The scan printed `CLEAN` and exited 0.
For a security scanner that is the worst available outcome — a false
all-clear is trusted, and nobody debugs a green build.

Fixed in three layers, because each catches a case the others miss:

1. **`resolve.ResolveFile`** refuses to return `(empty, nil)` for a file that
   declares dependencies. It re-reads the file to count declarations
   *independently of any resolver*, so a resolver bug cannot make the counter
   agree with it. This is now the only sanctioned entry point; there is no way
   to reach `Resolver.Resolve` from the scan path.
2. **`scan.Run`** propagates `ErrSilentZero` as a hard error rather than
   warning and continuing.
3. **`cli.warnIfNothingResolved`** covers the gap the first two leave: a
   lockfile that was detected but could not be parsed at all. `scan.Run`
   deliberately warns rather than aborting (one bad file should not sink a
   monorepo scan), which means a command could still exit 0 having read
   nothing. That now exits 2 — an operational failure, distinct from exit 1's
   policy verdict — and `sbom generate` no longer emits a 0-component SBOM
   that looks like a legitimate artifact.

### Two bugs found while building the guard

**The guard silently disabled itself.** `ResolveFile` re-reads the file, but
`Resolve` takes its path relative to `root`. Passing a bare filename made the
counter read a nonexistent path, count zero, and stand down. The test that was
supposed to prove the guard worked passed a bare filename for exactly this
reason, and the guard appeared to be missing when it was merely asleep. Fixed
by resolving the path before re-reading.

**The guard then failed on the wrong warning.** It selected parse failures
with `strings.Contains(w, "failed")`, which also matched `"EPSS enrichment
failed, exploitability scored as 0"` — an unrelated advisory that must never
fail a scan. Warnings now carry an explicit `resolving` prefix contract
instead of being matched by substring. A loose match in a warning classifier
turns a useful signal into noise, which is how a guard gets ignored.

### What the guard caught, and what it did not

Reverting each fix and re-running the property test is how the guard was
validated. D23 was caught by name, with the declared count:

    SILENT ZERO: pypi/real/prefecthq/prefect/requirements.txt:
      pypi lockfile declares 22 dependencies but the resolver returned 0

D22 was **not** caught, and that is correct: it surfaced as a hard
`json.Unmarshal` error rather than a silent zero, because the npm resolver
propagates parse failures. The guard covers the silent case, not the loud one.

**Rule:** a guard must be validated by breaking the thing it guards, not by
writing a test that passes against correct code. Two of the three bugs above
were found only because a test was written to fail against deliberately
broken input.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
