# D41 — a linter-driven rename silently disabled the fail-closed path

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D41

**Title:** a linter-driven rename silently disabled the fail-closed path

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** `golangci-lint` flagged `shadow: declaration of "err" shadows
declaration at line 88` in `internal/scan/scan.go`. The shadow was inside a
per-project loop, and the outer `err` was nil at that point.

**What I did.** Renamed the inner variable to `resolveErr` with a scripted
regex. The regex handled `err != nil`, `err is ErrSilentZero`, and
`return nil, err`, but not `errors.Is(err, resolve.ErrSilentZero)` — the
argument to a call rather than a bare comparison.

**The damage.** The silent-zero branch became:

```go
if errors.Is(err, resolve.ErrSilentZero) {   // err is the OUTER, nil err
    return nil, resolveErr
}
```

`errors.Is(nil, ErrSilentZero)` is always false, so the branch was
unreachable. A resolver that read a declaring file and returned nothing
would have produced a warning, zero components, and **CLEAN with exit 0** --
the exact D01/D22/D23 failure this project was built to eliminate, restored
by a lint cleanup.

**Why it did not survive.** It did not survive anything. `go test` ran in
the same command as the rename, and
`TestScanFailsWhenResolverReturnsNothingForADeclaringFile` failed with
"scan succeeded against a resolver that read nothing". The invariant test
did its job on the first execution, which is the argument for having written
it.

**The rule.** A rename applied by regex across a fail-closed branch is a
behavioural change until the invariant test says otherwise, and `go build`
is not evidence. Structural edits inside a fail-closed path get read back.

**Also in this change.** `internal/sbom/sbom_test.go` had assertions
written `x != x` where `x == x` was meant, so each could only fail if the
function was already correct. staticcheck flagged the identical-operands
form. `spdxNamespace` had no non-vacuous assertion at all. Two mutations --
`spdxNamespace` ignoring its input, and `serialNumber` made
time-dependent -- are now both killed by the corrected test.

Six genuinely dead symbols were also removed (`exitCodeFor`,
`baselineUpdate`, `colorCyan`, `gitHubTaxonomy`, `urlOrEmpty`,
`dedupeDetailsTimeout`). Dead code in a fail-closed path is not harmless:
it reads like a guard that is not running.

**Verified.** `python3 scripts/mutation_audit.py --jobs 4` -> 16 killed, 0
survived. `golangci-lint run` against the committed `.golangci.yml` ->
clean, on the pinned v1.64.5.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
