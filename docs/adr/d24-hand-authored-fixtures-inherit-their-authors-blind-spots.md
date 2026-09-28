# D24 — Hand-authored fixtures inherit their author's blind spots

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D24

**Title:** Hand-authored fixtures inherit their author's blind spots

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Pattern, applying the existing "a guard that cannot fail is worse than no
guard" rule to test *data* rather than test *logic*.**

Every npm fixture in this repo was written by the same person who wrote the npm
resolver. When that resolver mis-modelled a lockfile shape, no fixture could
catch it, because the fixture and the resolver shared one author's
assumptions about what an npm lockfile looks like. A green suite and a broken
product were consistent with each other.

The corpus under `testdata/fixtures/<eco>/real/` now comes from upstream
projects, fetched reproducibly by `scripts/fetch_corpus.py`. It is 80 lockfiles
(63 Go, 10 npm, 7 PyPI) covering 22,776 components, and it found D22 and D23
within minutes.

**Rule:** no ecosystem resolver's test suite is trusted until it has been run
against at least one lockfile nobody on this project wrote. For a new
resolver that means: fetch real fixtures first, then write unit tests to cover
shapes the corpus does not contain.

### What the corpus could not get, and why

Honest limits, so nobody re-attempts these:

- **npm lockfileVersion 1 (npm 6) is not in the corpus.** Modern upstream
  projects have migrated. The v1 nested-`dependencies` path is therefore still
  only covered by hand-written fixtures, which is exactly the blind spot D24
  describes. This is a known gap, not a covered case.
- **Many popular repos commit no npm lockfile at all.** n8n uses pnpm;
  express and angular.js are libraries with nothing to lock. A larger repo list
  will not fix this.
- **Most Python projects have moved to `pyproject.toml`.** click, starlette and
  fastapi commit no requirements file whatsoever. SCRAM has no PEP 621
  resolver, so a large and growing share of the Python ecosystem is invisible
  to it. That is a product gap, not a test gap, and closing it means writing
  the resolver rather than growing the corpus.
- The GitHub API is rate-limited to 60 req/hour unauthenticated, which is why
  the fetcher uses `raw.githubusercontent.com` and probes subpaths instead of
  walking repository trees.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
