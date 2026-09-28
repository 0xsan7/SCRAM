# D31 — D25 confirmed fixed, with a regression test that catches it

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D31

**Title:** D25 confirmed fixed, with a regression test that catches it

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

D25 was "the fetcher reported 0/77 on a corpus where all 73 files were on
disk": a tool asserting a conclusion it had not established, the same class as
D01/D22/D23 but in the tooling.

**The clean run.** Two consecutive runs against identical targets:

    run A: npm: 10/45 repos have a lockfile (0 fetched, 10 already present)
    run B: npm: 10/45 repos have a lockfile (0 fetched, 10 already present)

Identical totals, identical split. The first version of the accounting
excluded already-present files from `have`, so a complete corpus printed as
0/N -- indistinguishable from a corpus that had downloaded nothing.

**The regression test** is `scripts/test_fetch_corpus.py`, 7 tests, and it is
verified by reintroducing the bug: restoring the
`if os.path.exists(dest): continue` branch without the `cached[repo] = ...`
assignment produces

    npm: 1/2 repos have a lockfile (1 fetched, 0 already present); 1 have none

and the suite goes red on two tests. Restored, all 7 pass. That is the D-series
standard applied to the tooling rather than the product, and it is the only
reason to believe the fix rather than the log line.

Three of the fetcher tests failed on first run -- all three my test's fault,
not the fetcher's, and worth recording because two were subtly wrong:

- Seeded `real/a/` when `fetch_eco` writes `real/a/b/`, so the cache path
  never matched and "cached" was never exercised.
- Asserted `assertNotIn("already present")`, which **passes against the
  correct output "0 already present"** -- the substring lives inside the
  string it was checking for. It would have green-lit the exact bug it was
  written to catch. Now `assertNotRegex(out, r"[1-9]\d* already present")`.
- Asserted on a fully-qualified URL when `get()` is called with a
  repo-relative path and builds the base itself.

A test that cannot fail is worse than no test, and the second one above is a
clean example: it was green, it was wrong, and it was green *for the reason
it was trying to detect*.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
