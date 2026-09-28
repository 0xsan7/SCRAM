# D33 — D25's false negative had a second instance, in a different code path

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D33

**Title:** D25's false negative had a second instance, in a different code path

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

D31 fixed the fetcher's accounting and added a regression test for it. Then
the full sweep was run for the first time end to end, and reported:

    pyproject: 0/55 repos have a lockfile (0 fetched, 0 already present)
    55 have none

**44 pyproject.toml fixtures were on disk at that moment.** Same failure class
as D25, same shape -- a tool asserting a conclusion it had not established --
in a completely separate branch of the same file.

**Cause.** `fetch_eco` builds destinations as
`<corpus>/<sub>/real/<repo>/<file>`. The pyproject corpus lives at
`<corpus>/pypi/real/pp/<repo>/pyproject.toml`, and no single `sub` value can
express a directory that is not directly under the ecosystem directory, so
the call built `fixtures/pp/real/...` (and before that, with the wrong
argument order, `fixtures/pypi/real/pp/real/...`). The cache check therefore
never matched, and every run reported an absence.

**Why it was invisible.** The output was a plausible number in a line nobody
was reading, not an error. The npm, pypi and go paths all worked, because
their subdirectory happened to match the function's assumption. D25's fix
gave those three a regression test and left this one untested -- the same gap
one layer down.

`fetch_eco` now takes an explicit `root` override for destinations that are
not `<corpus>/<sub>/real/`. The report is now `44/55 (0 fetched, 44 already
present)`, and the 11 remaining are genuine: celery, attrs, tox and friends
have no root-level `pyproject.toml`.

**Found by reading the fetcher's own report against the filesystem**, not by
running its tests, which were green. The general rule this keeps earning:
a summary line is a claim, and a claim about the world should be checked
against the world.

### The same test-hygiene bug, in Python this time

Three of the new tests assigned `fc.probe_one = ...` and cleaned up with
`del fc.probe_one`, which destroys the real function for every test that runs
later -- four tests errored in classes that had nothing to do with the edit.
`patched()` now saves and restores the original. This is the third time this
project has had a test leak state into its neighbours: the Go registry
(`withRegistry`), the scan resolver swap (`Handles` + `Priority`), and now the
fetcher monkey-patch. The pattern is worth naming: **a test that cleans up by
deleting rather than restoring has silently changed a shared fixture.**

### Verified by reintroducing the bug

Ignoring the `root` override again produces `palliets/click: ERROR probe_one
ran despite a valid cached file` and two failures. Restored, 10/10 pass.
`test_default_layout_is_unchanged` correctly stayed green throughout -- the
default path was never broken, and a test that went red for an unrelated
reason would have been noise.

Also fixed while in here: `fetch_npm_v1` called `get()` with a repo-relative
path, but `get()` takes a fully-qualified URL and raised
`ValueError: unknown url type` on every v1 target. The six v1 fixtures were
fetched by hand before that function existed, so the bug was never
exercised. It is now covered by `test_tag_urls_carry_the_v_prefix`.

---

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
