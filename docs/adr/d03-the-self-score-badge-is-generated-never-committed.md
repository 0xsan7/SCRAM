# D03 — The self-score badge is generated, never committed

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D03

**Title:** The self-score badge is generated, never committed

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

The README badge is produced by the same CI scan that runs the dogfood job, via
`scram badge` reading `scram scan --format json`. It is published as a CI
artifact, not written into the README.

A committed badge is the stale-claim problem the feature exists to prevent: it
would still read `32/100` a year after the score moved, and nobody would
notice because a badge looks live. Regenerating it every run is the entire
point.

`scram badge` rejects any document that is not a scan rather than rendering
`0/100`. A public badge fed the wrong input must fail loudly, not display a
fabricated score.

Wiring the artifact to an actual endpoint (GitHub Pages or a gist) is a
deployment decision belonging to the repo owner and is deliberately left
unwired rather than guessed at.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
