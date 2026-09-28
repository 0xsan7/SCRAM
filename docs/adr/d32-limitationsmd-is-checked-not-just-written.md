# D32 — LIMITATIONS.md is checked, not just written

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D32

**Title:** LIMITATIONS.md is checked, not just written

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

Every claim in LIMITATIONS.md was verified against the code before being
committed, and one was wrong on the first draft.

The draft said a Go module with `go.mod` and no `go.sum` "is not detected as
a Go project... This is a detection gap, not a parse failure: nothing warns."
Running it showed the opposite: `no dependency lockfiles found, so nothing was
scanned; this is not a clean result`, a warning naming every filename
searched, and **exit 1**. The behaviour was right and the documentation
understated it, which is its own failure mode -- an honest-sounding gap
disclosure that makes the tool look weaker than it is, and invites a
workaround that is not needed.

The corrected entry says plainly that this is a coverage gap which fails
closed, and notes that `go.mod` does declare dependencies, so reading it is a
deliberate choice to read only the resolved file rather than an oversight.

This is the G-section rule ("a badge showing green for a check that doesn't
run") applied to prose: a limitation that overstates a gap is as much an
unverified claim as a coverage number nobody counted.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
