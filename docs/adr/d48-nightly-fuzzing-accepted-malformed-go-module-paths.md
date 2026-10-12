# D48 — nightly fuzzing accepted malformed Go module paths

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D48

**Title:** nightly fuzzing accepted malformed Go module paths

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** On resuming for v0.2.0, push CI on `078a48f` was green, but
nightly fuzzing had failed repeatedly in `FuzzGoMod`. The runner log reported
`name="A./\x93" version="v0" purl="pkg:golang/A./%93@v0"`: the fallback
accepted invalid UTF-8 as a module path. Replaying `require A./\x93 v0`
locally reproduced the exact invariant failure before the fix.

**Decision.** Validate Go module path characters before building the component.
Only ASCII letters, digits, and `-._~/` are allowed. The existing host and
segment checks remain; the real trivy fixture guards against rejecting valid
module paths. Regression cases cover invalid bytes in the host and final
segment, non-ASCII characters, and PURL delimiters. The original failing input
is a permanent seed in `FuzzGoMod`. A mutation removes the character check
without changing compilation and must be rejected by the resolver tests.

The fuzz workflow also uploaded the wrong directories: Go wrote its failing
input under `internal/resolve/testdata/fuzz/FuzzGoMod/`, but the upload step
looked for files named `*crash*` under the root corpus. It now includes the
package-local fuzz directories, so future failures preserve their inputs.

**Release reporting.** The signature identity in the release footer must use
the current tag, not a hardcoded v0.1.0 candidate. The release command now
prepends `docs/BREAKING-2.0.0.md` to the actual published notes; checking a
separate locally generated changelog did not ensure the publication included
that warning.

**Verification.** The original seed failed before the fix and passed after it.
`go test ./...` and `go vet ./...` passed. A 45-second `FuzzGoMod` run
completed 1,127,031 executions without failure. The D48 mutation was killed
by the resolver tests.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
