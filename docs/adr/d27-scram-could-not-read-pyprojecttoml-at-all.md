# D27 — SCRAM could not read pyproject.toml at all

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D27

**Title:** SCRAM could not read pyproject.toml at all

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**The gap.** Most modern Python projects have migrated to pyproject.toml
(PEP 621) and ship no lockfile and no requirements.txt. In a 48-repo survey
of the libraries a Python developer actually installs, 44 had a
pyproject.toml, 2 had a poetry.lock, and only a handful had a
requirements.txt. SCRAM read none of the pyproject.toml files, so all of
those projects scanned as having **no Python dependencies at all** — the
silent-zero shape of D01/D22/D23, in a whole ecosystem.

This is D24's lesson applied one step further: D24 said the fixtures inherit
the author's blind spots, and the blind spot here was an entire file format
the author had not thought to support.

**What was added.** `internal/resolve/pyproject.go`, handling both styles
found in the corpus:

- PEP 621 `[project] dependencies = [...]`, and the PEP 735
  `[project.dependencies]` table form
- Poetry's `[tool.poetry.dependencies]`, which is a TABLE
  (`pygments = "^2.13.0"`) rather than an array, including the inline-table
  form `{ version = ">=7.5.1,<9", optional = true }`

Lockfile precedence is unchanged and still correct: `poetry.lock` is a detect
candidate before `pyproject.toml`, verified end to end — a project with both
resolves the lock's exact `2.19.1` and ignores the manifest's three ranges.

### The trap the real corpus contained

`Textualize/rich` declares this in its Poetry table:

    [tool.poetry.dependencies]
    python = ">=3.9.0"
    pygments = "^2.13.0"

`python` is the interpreter constraint, not a package. A parser that treats
every key as a dependency invents a package called `python` that does not
exist on PyPI and then queries the OSV API for it forever. There is an
explicit `isPythonConstraintKey` check, and the corpus test asserts no
component is ever named `python`.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
