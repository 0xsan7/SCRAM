# D02 — Why and blame claim only what they can actually know

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D02

**Title:** Why and blame claim only what they can actually know

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

`scram why` prints a dependency path; `scram blame` reads lockfiles as they
existed at each commit. Both make claims about structure, so both separate
"here is the answer" from "I cannot know this".

- Parentage is recovered from npm install paths only. `requirements.txt` is a
  flat list and `go.sum` stores checksums, so for PyPI and Go the output says
  unknown and points at `pipdeptree` / `go mod why`. Inventing a plausible
  path would be worse than admitting ignorance — the whole point of a
  supply-chain tool is not to make things up.
- Blame caps history at 2000 commits and reports the truncation, so a shallow
  clone cannot look like a clean history.
- A lockfile with a dependency cycle terminates rather than hanging the CLI.
  Hand-edited lockfiles can contain one and a scanner must not wedge on it.
- Commits that rewrote a lockfile without changing a package's resolved
  version are omitted from that package's history. Lockfile churn reported as
  risk history is exactly the noise that teaches people to ignore the output.

Both features are exercised against real fixtures and, for blame, against real
throwaway git repositories with known commit sequences. A blame feature that
reports the wrong commit looks authoritative, so mocking git would have proved
nothing.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
