# D44 — the invariant could not see a bug that made every go.mod scan clean

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D44

**Title:** the invariant could not see a bug that made every go.mod scan clean

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** Two bugs shipped with correct PURLs, plausible component names,
real versions and green CI.

`9f4ae85` — the pnpm 6.0 lockfile. The key schema changed at **6.0**, not at
9.0, and 6.0 is a hybrid: slash-prefixed but `@`-delimited. Read as a 5.x
file, the name came out as `lodash@4.17.21` with an empty version, so the
component was dropped. A real pnpm 7 repository resolved to **361 components
instead of 1523**, a 76% undercount, with no error raised.

`af8e58f` — the go.mod fallback. It set `Component.Name` to the bare last
path segment while `internal/vuln/osv.go` queries OSV by `Name` and OSV keys
its Go ecosystem on the **module path**. So `github.com/gin-gonic/gin` was
looked up as `gin`, matched nothing in any registry, and the scan reported
**CLEAN**. Against real repositories: `aquasecurity/trivy` 0 → 9 findings,
`rook/rook` 0 → 6, `docker/docker` 0 → 4.

**The common cause.** Neither was a resolution failure in the sense the
silent-zero invariant was built to detect. Resolution *succeeded*: it
produced components with well-formed PURLs drawn from the real file. The
defect was in what those components were **keyed on** when sent to the
registry, and in whether they survived to be sent at all.

**The invariant's actual scope.** It answers one question: *did resolution
produce components for a file that declares dependencies?* A component with
a good name, a real version and a correct PURL is exactly what it calls
healthy. It never observes the matching step, so a scanner that resolved
correctly and then looked every package up under a key no registry indexes
passes it completely. This is a permanent limitation of the framework, not a
missing test case — recorded in TESTING.md so it is not rediscovered as if it
were news.

**Decision.** Two things follow, both standing:

1. **TESTING.md** states the limitation as a named property of the invariant,
   with the two bug classes named, so the next person to add a resolver knows
   what the invariant will and will not catch for them.

2. **CONTRIBUTING.md** adds a requirement no existing check satisfied: any
   resolver or vulnerability matcher, **new or existing**, must pass a
   *known-vulnerable roundtrip* — take a real package from the real corpus
   with a known, currently-valid advisory and assert the matcher returns it.
   A correct-looking PURL is not evidence the lookup key is correct.

The roundtrip runs offline against recorded responses from the real OSV
(`scripts/record_osv_fixtures.py`), so it is enforced in CI without depending
on the network. It asserts the key through the **production** lookup path: the
stub server returns advisories only for the key OSV actually uses, so a wrong
key produces the same empty result the bug produced, and is now a test failure
rather than a clean scan. A live variant runs under `SCRAM_LIVE_OSV=1`.

**Verification.** Breaking `goModuleName` to truncate the module path to its
last segment fails the Go case with the diagnostic naming the exact defect,
and fails the live two-path comparison too. Two mutants covering this are in
`scripts/mutation_audit.py`, so a future "simplification" of that function
cannot quietly reintroduce it. Total: **39/39 killed**.

**The uncomfortable part.** Both bugs were found by hand, late, by reading
someone else's research notes — not by the framework. A test suite that
reports green while a scanner silently reports vulnerable projects as clean
is worse than no suite, because it is trusted. The roundtrip requirement
exists to close that gap; it is the minimum bar, not a sufficient one.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
