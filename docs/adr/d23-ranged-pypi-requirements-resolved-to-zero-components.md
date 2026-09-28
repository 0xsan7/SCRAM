# D23 — Ranged PyPI requirements resolved to ZERO components

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D23

**Title:** Ranged PyPI requirements resolved to ZERO components

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Found by:** the same corpus run, on `prefecthq/prefect/requirements.txt`.

The requirements parser matched a single regex:

    ^([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)

That matches `==` and nothing else. Every `>=`, `~=`, `<`, and bare-name line
fell through it and was discarded. prefect's file is 22 ranged dependencies and
no exact pins, so SCRAM resolved ZERO of them and reported the repo clean.

The fix parses the name permissively, then extracts a version by preferring an
exact `==` pin and falling back to a range's lower bound, which is the version
pip would actually install.

The fix introduced a second bug, caught by an existing test: the old regex had
been *accidentally* filtering out VCS requirements, so `git+https://...` now
parsed as a package named `git`. Those are now rejected explicitly.

**The pre-existing test asserted the buggy behaviour.** `TestPyPIRequirements`
required exactly 4 components and commented that `urllib3>=2.0.0` "carries no
pinned version". That comment was the bug, written down as an expectation. The
test was updated, because the expectation was wrong — but note that a test
suite which pinned the defect would have blocked the fix.

**Rule:** a test that asserts a lossy behaviour is not protecting the product,
it is protecting the bug. When a fix changes an assertion, read the assertion's
comment first: if it rationalises the loss ("carries no version", "not
pinned"), that is the smell, not the test.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
