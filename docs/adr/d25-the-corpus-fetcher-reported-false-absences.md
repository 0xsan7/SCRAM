# D25 — The corpus fetcher reported false absences

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D25

**Title:** The corpus fetcher reported false absences

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

While building the corpus, the fetcher reported `0/77` for Go on four separate
runs, and `0/45` / `0/54` for npm and PyPI — while the same code, called
directly on the same repos, returned hits every time.

Two separate defects, both of the same kind as D24: a tool reporting a
confident answer it had not actually established.

1. **A transient upstream failure was reported as "this repo has no
   lockfile."** Absent and unreachable are different facts. Fetches now retry,
   and only a definitive 404 counts as an absence.
2. **Repos whose file was already on disk were counted as absent.** The summary
   printed `0/45` for a corpus that was 100% present on disk, because cached
   files skipped the accounting entirely. The summary now reports fetched and
   cached separately and reconciles against files on disk.

**Rule:** a tool that reports "nothing found" must be able to distinguish
"I looked and there was nothing" from "I could not look". A negative result
needs the same evidence as a positive one, and a summary that can disagree
with the filesystem is worse than no summary.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
