# Testing

How this project is tested, and — more importantly — what the tests do **not**
cover. The second part is the part that has bitten us.

Run everything:

```bash
go test ./...
go test -race ./...
python3 scripts/mutation_audit.py
go run ./cmd/corpus-check
```

---

## The silent-zero invariant, and its hard limit

The invariant (`internal/resolve/invariant_test.go`) walks every lockfile in
`testdata/fixtures/`, resolves it, and fails if a file that declares
dependencies yields zero components. Its job is to catch a parser that reads
a real file and produces nothing — the quiet failure that looks exactly like a
clean project. Across 202 lockfiles it has caught real bugs, and it is
worthwhile.

**It verifies that resolution produced components. It does not verify that
vulnerability matching found what a real, known-vulnerable package should
find.** That is a permanent limitation of the framework, not a gap someone
will patch later. Record it here so it is treated as a known property rather
than rediscovered as if it were new.

### Why the limit exists

A component that the resolver produced is *supposed* to look like this:

- a plausible `Name`
- a real, specific `Version` taken from the file
- a well-formed `Purl` that agrees with both

Those are exactly the properties the invariant checks. So a component
produced with a **wrong lookup key** satisfies every one of them. The
invariant's verdict is "healthy", and it is right about what it asked.

Two shipped bugs lived entirely in that blind spot.

| Bug | Resolver output | Lookup result | Reported |
|---|---|---|---|
| pnpm 6.0 (`9f4ae85`) | 361 of 1523 components; names like `lodash@4.17.21`, version `""` | components dropped before matching | 76% of the tree never checked |
| go.mod fallback (`af8e58f`) | correct name, version, **correct PURL** | `github.com/gin-gonic/gin` sent to OSV as `gin`; matches nothing | **CLEAN**, 0 findings |

The second is the dangerous one, because *nothing* about the output looked
wrong. `aquasecurity/trivy` reported 0 findings; the same dependencies
resolved through `go.sum` reported 9. The inventory, the badge and the score
were all fine. Only the security answer — the entire reason the tool exists —
was silently wrong.

### The two failure shapes to check for

1. **Component silently dropped.** A key parsed into a name that carries its
   own version, or with an empty version, produces a component no registry
   will ever match. Resolution "succeeds". Compare component counts between
   lockfile generations of the same project: a large unexplained drop is the
   signature.
2. **Correct component, wrong key.** The name is wrong for the registry even
   though it looks right locally. What OSV keys on is per-ecosystem:

   | OSV ecosystem | Keyed on |
   |---|---|
   | `Go` | the **full module path** — `github.com/gin-gonic/gin` |
   | `npm` | the package name **including its `@scope`** |
   | `PyPI` | the distribution name as published — `PyYAML` |
   | `crates.io` | the crate name |

   A Go module path split into namespace and name is a PURL detail, not a
   lookup detail. Stripping the path down to `gin` produces a *valid-looking*
   component that indexes against nothing.

### What closes the gap

The **known-vulnerable roundtrip**: take a real package from the real corpus
that has a known, currently-open advisory, and assert the matcher actually
returns it. See the requirement in
[CONTRIBUTING.md](CONTRIBUTING.md#known-vulnerable-roundtrip-required).

```bash
go test ./internal/resolve/ -run TestKnownVulnerableRoundtripOffline -v
SCRAM_LIVE_OSV=1 go test ./internal/resolve/ -run TestTheTwoGoPaths -v
```

Both run through the **production** lookup path. The stub server returns
advisories only for the key OSV actually uses, so a wrong key produces the
same empty result the bug produced and fails the test. A test that built its
own query would have passed the whole time — which is why the production path
is not optional here.

---

## Fixtures

Real lockfiles, not synthetic ones. A trimmed file is fine; a hand-written
one is not, because synthetic fixtures omit exactly the fields that break
parsers — a Berry key that quotes once instead of per descriptor, a Cargo V1
file with no `version =` line at all, a pnpm 6.0 key that is
slash-prefixed *and* `@`-delimited.

Fetch more with `scripts/fetch_corpus.py`. The "genuinely empty" fixtures
(numbered in the invariant's output) are real lockfiles for projects that
truly have no dependencies; they are expected to resolve to zero and the
invariant knows the difference.

Recorded OSV responses live in `testdata/osv/` and are regenerated with
`scripts/record_osv_fixtures.py`, which fails loudly if a recorded package
has been patched — an empty recording would let a broken key pass.

## Mutations

`scripts/mutation_audit.py` reverts one fix at a time and requires the test
suite to notice. A test that does not fail when its fix is reverted is not
testing the fix, and the audit reports survivors rather than letting a green
run imply coverage. 39 mutants, all killed.

When you add a fix, add the mutant. If a mutant survives, the honest options
are to write the missing test or to delete the mutation — not to relax the
assertion.

## Fuzzing

Fuzz targets use the committed corpus as seeds, so every real lockfile is
replayed before any random input is generated. A crash in a cached seed is a
regression, not a new bug: check whether the input still fails before
reporting it.

## Live checks

Anything that needs the real network is opt-in and skipped by default rather
than deleted, so it stays discoverable:

| Check | Gate |
|---|---|
| OSV roundtrip, live | `SCRAM_LIVE_OSV=1` |
| OpenSSF Scorecard | `SCRAM_LIVE_SCORECARD=1` |

## Reporting a verification claim

"Verified" means a command was run and its output read. A green suite is
evidence about the things the suite checks, and — per the section above — not
about the things it does not. When a check cannot cover a claim, say so
rather than implying the suite did.
