# D34 — One vacuous test, and a harness that could not tell green from broken

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D34

**Title:** One vacuous test, and a harness that could not tell green from broken

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

The mutation audit re-breaks each logged fix and checks the suite notices.
Mechanised as `scripts/mutation_audit.py`, because 194 tests is too many to
mutate by hand without skipping some, and skipping is how this class of bug
survives.

**Final result: 16 mutants declared, 16 killed, 0 survived.**

### The one genuine vacuous test

`TestEscalationByCount` claimed to cover count-based escalation. Its body
built ten **clean** components and asserted that an all-clean repo stays
clean. It never reached `counts[BucketHigh] >= 10`, so changing that
threshold to 99 left the suite green — a guard that cannot fail, named after
the behaviour it did not test.

The replacement needed a component that lands in High, which took some
probing to construct: a single-vulnerability component maxes out at 39 no
matter how many findings it carries (only the *maximum* CVSS counts), so
severity and exploitability must both be pushed and freshness supplied by a
major-version distance. CVSS 9.5 + EPSS 0.95 + version gap scores 72. The
threshold is now pinned from **both** sides — ten highs escalate to Critical,
nine do not — so changing it in either direction fails.

The original all-clean assertion was kept as
`TestEscalationAllCleanStaysClean`, correctly named, rather than discarded
along with the misnamed test.

### The harness lied, and that was the bigger finding

The first run reported four survivors. Three were false. The harness copied
the single mutated file into an empty temp directory and ran `go test` there
— no `go.mod`, no package, no other source file. Every run failed to build,
and the harness read "this package did not fail" as SURVIVED.

Three fixes were reported untested when the suite catches all three. Each was
confirmed by hand first, which is what made the discrepancy visible:

| mutant | harness said | actually |
|---|---|---|
| DEDUPE-alias | SURVIVED | 5 tests fail |
| DRIFT-added | SURVIVED | `TestDiffAddedComponent` fails |
| POLICY-threshold | SURVIVED | 2 subtests fail |
| SCORE-bucket-escalation | SURVIVED | genuinely vacuous |

The harness now copies a full tree, distinguishes a **build failure** from a
**test failure** (a mutant that does not compile proves nothing about whether
a test guards the behaviour, and is reported INVALID rather than counted
either way), and copies the **working tree** rather than `git clone` — a clone
tests HEAD, which silently excluded the score fix committed seconds earlier
and briefly reported it as still surviving.

**This is the fourth time in this project a verification tool reported a
conclusion it had not established** (after D25, D31, D33). Each time the
tool was the thing that was wrong, and each time the tell was the same: a
plausible number in a summary line rather than an error. A harness that
cannot distinguish "tests passed" from "tests never ran" is exactly the
failure mode the whole project is built to avoid, appearing in the tooling
that exists to detect it.

### Anchors that were wrong rather than mutants that survived

Six of the sixteen declared mutants were BROKEN on first run — anchors I had
written from memory of the code rather than by reading it
(`if declared > 0 && ...`, `req, err := parseRequirement(line)`, a
`cvss.go` that does not exist). The harness reports those as BROKEN rather
than as passes, because a mutant whose anchor moved tests nothing. Three more
turned out to be syntax-destroying rather than behaviour-changing, and are
now INVALID. Neither category is allowed to look like a result: a mutation
audit that quietly skips the mutants it could not apply would report a clean
bill of health for coverage it never measured.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
