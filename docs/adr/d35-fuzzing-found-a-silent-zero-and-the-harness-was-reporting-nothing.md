# D35 — Fuzzing found a silent zero, and the harness was reporting nothing

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D35

**Title:** Fuzzing found a silent zero, and the harness was reporting nothing

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

Fuzz targets for every parser SCRAM runs on untrusted input: the four
lockfile/manifest formats and both SBOM serializers, plus the pure helpers
where the interesting logic actually lives (SRI parsing, npm install-path
names, PEP 508 requirement splitting, go.sum path splitting, SPDXID
derivation).

Every resolve target asserts two things, and the second is the one that
matters: **no panic, and no silent zero**. A fuzz input that declares
dependencies must either resolve at least one component or return an
explicit error. An empty list with no error is D01/D22/D23, and the fuzzer
is the cheapest way to find a new shape that triggers it.

Seeds come from the real corpus, not from strings invented in the test file.
D24 applies to fuzzing too: a seed corpus written by the same person who
wrote the parser inherits that person's blind spots.

### The bug: a requirement with no name at all

`parsePEP508("!!!")` returned `ok=true` with an **empty component name**.

`strings.IndexAny(s, "=<>!~;")` finds `!` at index 0, so the split produced
`componentFromNameSpec("", "!")` — a component whose name is empty, and
therefore whose PURL is empty. Downstream that is a component that matches no
package, is looked up under no identifier, and reports nothing. It is the
silent-zero shape again, one layer below the resolver: a scan would report
three components when the file declared one, and the extra one was a ghost.

The fuzzer found this in its first run, from a seed written to be obviously
harmless.

### The harness, again

The first fuzz run reported `elapsed: 12s, execs: 47` and then `0/sec` for
the rest of the window — it appeared to run for 180 seconds per target while
exploring 47 inputs. `t.TempDir()` was being called once per execution, and
the filesystem cost dominated completely.

`f.TempDir()` is created once per run instead. Same target, same 45 seconds:

    before   execs: 47
    after    execs: 3362

A 70x difference, from a line that looked like ordinary test hygiene. This is
the fifth time a verification tool in this project has reported a result it
did not earn (D25, D31, D33, and twice in D34), and the pattern is now
unmistakable: **the tell is always a plausible number with no units and no
baseline.** A fuzz run that completes on time and prints `ok` is exactly as
suspicious as one that prints a wrong count.

### The second bug: a padded TOML key became a package named "python"

`FuzzIsPythonConstraintKey` found that `isPythonConstraintKey(" pYthon")`
returned false. The check lowercased the key but never trimmed it, and TOML
permits whitespace around a bare key, so a real `pyproject.toml` written as

    [tool.poetry.dependencies]
     python = ">=3.9"

produced a component named `python` -- a distribution that does not exist on
PyPI, matches no OSV record, and contributes nothing. Same failure as D27,
one layer of normalisation short of catching it.

This is the argument for fuzzing that the seed corpus could not make on its
own: the D27 corpus tests cover `python` bare, because every real project
writes it that way. Nothing in a corpus of real repositories produces a
padded key, so only a fuzzer would.

Two permanent regression tests, both verified by reverting the fix: the
helper-level table (including `pYthon-requests` and `pythonnet`, which must
NOT be treated as constraints) and an end-to-end test that parses a
whitespace-padded key through TOML and asserts no phantom component appears.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
