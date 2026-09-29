# D45 — three guards passed while missing the defect they were written for

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D45

**Title:** three guards passed while missing the defect they were written for

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** D44 recorded a class of bug the invariant cannot see. The natural
response is to write guards for that class. Three of them were written, and
all three shipped wrong — in the same way, and all three were found the same
way: by putting the real defect back and watching the guard stay green.

**`TestKnownVulnerableRoundtripOffline`.** Written to catch the go.mod OSV
lookup key (`af8e58f`). It built its Go component through the production
`go.mod` resolver, so it read as though it covered the whole lookup path. It
did not: the bug was in `goModuleName`, a helper shared with the `go.sum`
path, and the test also exercised a `go.sum` component. Reverting the shared
rule left the test passing, because the assertion that mattered was being
satisfied by the other caller. The fix was to unify both call sites through
one named rule and break *the rule* rather than a call site. The lesson is
not "write a better test" — it is that a guard placed one level above the bug
can be correct about the thing it names and still miss it.

**`internal/badge/badge_test.go`.** The badge renders a presented score, so a
fixture was built by hand with `RepoScore: 95`. On a 65-point scale 95 is
impossible, and the test asserted `95/65 critical` — a value the shipped
clamp exists to prevent. It passed because nothing connected the fixture's
plausibility to the assertion's meaning. Hand-built fixtures need a stated
invariant, not just a literal expected string.

**`scripts/check_action_metadata.py`.** Added to stop `action.yml` claiming
`/100` after the presented scale moved to 65. It searched for the literal
`/100` and therefore missed the `repo-score` output's description, which said
`0-100`. That check ran green over the exact defect it was added for. It now
matches all three spellings that have appeared in that file, each verified by
reintroducing it.

**Decision.** A new guard must be proven against **every real-world spelling
and variant** of the defect it claims to catch, not one instance. Before a
guard is trusted it must have been observed rejecting the actual defect, and
that rejection must have been read to confirm it failed for the right reason
— a compile error is not a catch. [TESTING.md](../TESTING.md) states the rule
with the three instances tabulated.

**The uncomfortable part.** All three guards were written *because* of a real
bug, in direct response to it, and all three would have been reported as
"the bug is now covered". A guard that has never rejected anything is an
unevaluated claim, and the only way to tell the difference is to break the
thing on purpose. That costs a cycle per guard, which is cheap next to
shipping a scanner that reports vulnerable projects as clean — but it is not
automatic, and nothing in the build enforced it.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
