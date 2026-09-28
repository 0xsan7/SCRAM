# D28 — A fourth instance of the silent-zero class, in the guard itself

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D28

**Title:** A fourth instance of the silent-zero class, in the guard itself

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

Running the section-1 invariant against the new pyproject.toml corpus found
two more bugs, and both are the same class as D01/D22/D23. The first is the
answer to the question "does a new resolver introduce a new silent-zero path":
yes, and in an unexpected place.

**The counter, not the resolver.** `declaredDependencies` (the function that
decides whether a file declares dependencies) fell through to its text branch
for `.toml` and counted every non-comment line. So click's
`name = "click"`, `version = "8.6.0.dev"`, and `[build-system]` were tallied
as dependencies. The guard then demanded **275 components from a file that
legitimately declares none** and hard-failed 12 completely correct results.

A false positive in the guard is as harmful as a false negative: it turns a
working scan into an error, and the fix for that is to disable the tool. The
counter now parses TOML properly and reads only the sections that declare
dependencies.

**Two resolvers, one ecosystem slot.** Registering `pyprojectResolver` with
`Register` REPLACED `pypiResolver` in a `map[string]Resolver`, because both
report `Ecosystem() == "pypi"`. Adding pyproject support silently disabled
poetry.lock, Pipfile.lock and every requirements variant — the fix broke more
than it fixed, and the corpus caught it within one test run.

The registry is now `map[string][]Resolver` with a `FileMatcher` interface,
and dispatch is by filename via `GetFor(eco, path)`. This is a design limit
worth stating plainly: the registry could not express "two formats, one
ecosystem", and nothing in the type said so.

The scan test that installs a broken resolver had to change too: without a
`Handles` method it was skipped by the new dispatch, the real resolver ran,
and the test **passed for the wrong reason**. It now asserts the swap took
effect, because a test that silently stops testing anything is worse than no
test at all.

---

### The guard, validated by breaking it

Per the section-1 standard, each fix was reverted and the property re-run:

- Disabling the PEP 621 array branch →
  `SILENT ZERO: agronholm/anyio: declares 3 dependencies, resolved 0`, plus
  aiohttp and the rest of the 32 positive cases.
- Removing the `python` constraint check →
  `resolved "python": the interpreter constraint is not a package`, on rich
  and textual.

**Corpus result: 44 files, 32 with declared dependencies all resolved, 12
with none correctly yielding zero, 0 mismatches, 0 parse errors.**

The 12 true negatives are load-bearing. A suite that only ever sees
"resolved something" cannot catch a counter that invents dependencies, so
`TestPyprojectCorpusAgreesWithItsOwnContents` fails if the corpus ever
degenerates into one-sided coverage, and `TestPyprojectCorpusHasKnownTrueNegatives`
pins click, h11 and urllib3 specifically.

End-to-end, a lock-less project declaring `requests>=2.19.1`, `jinja2>=2.10`
and `pyyaml>=5.1` now resolves 3 components and reports 14 real
vulnerabilities, including PyYAML's three 9.8 CVEs. Before D27 it reported
nothing at all.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
