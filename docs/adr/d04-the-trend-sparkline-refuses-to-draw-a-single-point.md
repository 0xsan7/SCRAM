# D04 — The trend sparkline refuses to draw a single point

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D04

**Title:** The trend sparkline refuses to draw a single point

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

A one-sample history renders no row at all. Scaling one point to full width
produces a bar that looks like a dramatic trend it cannot support, and a
fabricated trend is worse than an absent one.

A flat series renders flat at the bottom of the ramp rather than being
stretched across the full height, for the same reason.

JSON and SARIF receive no trend: those are fixed machine schemas (FR-208) and a
decorative glyph in stdout that gets piped to `jq` is indefensible. Verified the
JSON output still parses after the change.

History lives in a local append-only file. No account, no telemetry, nothing
leaves the machine — the only way a "run it yourself" scanner can also be one
you leave switched on in CI is if being watched costs the user nothing.

A corrupt or wrong-version history file is an error, not a silent reset: an
empty trend looks exactly like a repo that has never been scanned. Writing
history is atomic (temp file plus rename) and failing to write it never fails
the scan; it is an aid, not a result.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
