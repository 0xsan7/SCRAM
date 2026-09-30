# D46 — the differential harness was silently comparing id strings

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D46

**Title:** the differential harness was silently comparing id strings

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** A pre-tag differential for v0.2.0 reported, on `lodash@4.17.11`,
that SCRAM found **5** advisories and grype found **7**. Taken literally that
is a matcher gap, and it deserves a real investigation before a release.

**It was not a gap, and that was only half the finding.**

### 1. The 5-vs-7 is an alias artefact

Querying OSV directly for that exact package returns **7 records for 5
advisories**:

```
GHSA-35jh-r3h4-6jhm  aliases: CVE-2021-23337, CVE-2026-4800, GHSA-r5fr-rjxr-66jc
GHSA-r5fr-rjxr-66jc  aliases: CVE-2021-23337, CVE-2026-4800, GHSA-35jh-r3h4-6jhm
GHSA-f23m-r3pf-42rh  aliases: CVE-2025-13465, CVE-2026-2950, GHSA-xxjr-mmjv-4gpg
GHSA-xxjr-mmjv-4gpg  aliases: CVE-2025-13465, CVE-2026-2950, GHSA-f23m-r3pf-42rh
```

`GHSA-r5fr-rjxr-66jc` and `GHSA-xxjr-mmjv-4gpg` are reciprocally aliased to
two of the five SCRAM reported. Union-find over the alias graph gives 5
classes on both sides and identical sets. Confirmed across npm, yarn, pnpm
5.4, pnpm 9.0 and cargo — all now **5 vs 5, exact set match**.

### 2. The harness had not been comparing aliases at all

`canonical()` existed for exactly this. It did nothing, because:

```python
try:
    ... urlopen(...) ...
    group = {vid} | set(d.get("aliases") or [])
except Exception:
    group = {vid}
```

On a machine whose `urllib` has no CA bundle every request raised
`SSL CERTIFICATE_VERIFY_FAILED`, the bare `except` swallowed it, and the
function returned `{vid}` for every id. Canonicalization degenerated into the
identity function — raw string comparison.

So the harness was **on the verge of filing a release-blocking bug report
against a scanner that was correct**, and the earlier PyPI results it had
reported as "same set: True" were string equality, which is a weaker claim
than they looked. The identical SSL problem had already been hit and fixed in
`scripts/record_osv_fixtures.py` weeks earlier; the same footgun in an older
script went unnoticed until a disagreement forced the question.

### 3. Three more bugs, found only after the first was fixed

Each was invisible while the alias lookup was silently dead.

- **The transitive closure was a no-op.** It unioned only ids already in the
  input, so A → B → C with only A and C present — the exact case closure
  exists for — merged nothing. Deleting the loop changed no observed result,
  which is exactly why `TestAliasClassesMergeTransitively` was written: it
  pins the behaviour with a synthetic two-hop chain. `find()` had to become
  self-initialising, because intermediate nodes are not in `parent`.
- **The class representative was chosen from input ids only.** With the union
  correct, four PYSEC ids still showed as "SCRAM only" against grype's
  GHSAs: the class contained just the names each tool happened to use, so the
  two tools picked different representatives for one advisory. Fixed, and a
  first attempt that "solved" it by merging all ids into every class was
  caught by the transitive test, which caught it because it was already
  there.
- **The attribution check indexed a raw-id map with a canonical key.** `if
  s[i] != g[i]` for `i in sorted(S)` raised `KeyError` the moment any class
  collapsed to its CVE — aborting the run after the first case. It had never
  fired because every canonical name *was* a raw id while the lookup was
  broken.

Also: OSV hosts no record under every id it lists as an alias, so
`SNYK-PYTHON-JINJA2-1012994` returns 404. That is a **definitive answer, not a
failure** — treating it as fatal meant any package whose advisory graph
touched a Snyk id refused to compare at all.

### Decision

1. **Never degrade a comparison silently.** `canonical()` raises when the
   alias lookup fails; `--allow-offline` is the explicit opt-in for raw-id
   comparison and says so in the output.
2. **Union alias classes transitively**, and pick the representative from the
   whole closure, so the answer does not depend on which tool reported what.
3. **Cache on disk, write atomically, flush on exit**, and use three workers
   with exponential backoff. Eight workers got connections reset by OSV; this
   walks a free public API and must not hammer it.
4. **`TestAliasLookupFailureIsNotSilent` drives the real
   `_fetch_alias_group`.** Its first version stubbed `aliases_for`, so it
   could not see the swallow inside the function that does the fetching —
   reintroducing the original bug passed. A guard that only exercises one
   spelling of the defect, found in the guard written to stop exactly that.
   All six mutants now die.

### 4. What the comparison found once it worked

Every remaining difference is **SCRAM reporting advisories grype's database
does not carry** — the mirror image of the lodash case, and the opposite of a
SCRAM defect. Each was confirmed by querying OSV directly for the exact
package and version, not by trusting the differential:

| fixture | SCRAM | grype | SCRAM-only ids, all OSV-confirmed |
|---|---|---|---|
| cryptography 3.2 | 16 | 12 | CVE-2020-25659, CVE-2024-26130, CVE-2026-69248, CVE-2026-69249 |
| flask 1.0 + werkzeug 0.15 | 13 | 11 | CVE-2022-29361, CVE-2023-46136 |
| django 2.0.2 | 22 | 21 | CVE-2026-15830 |
| Pillow 5.0.0 | 54 | 49 | CVE-2021-23437, CVE-2021-25292, CVE-2021-28678, CVE-2022-45199, PYSEC-2023-175 |
| idna 2.7 + certifi 2018.11.29 | 5 | 4 | CVE-2024-39689 (on certifi, as PYSEC-2024-230) |

Isolated on werkzeug 0.15 alone: OSV returns 20 advisories, SCRAM 11, grype
9 — grype missing 11 that OSV and SCRAM both find. On cryptography the
difference runs the other way before canonicalization, and grype had been
failing outright (`vulnerability data incomplete`) because SCRAM refused to
gate a scan on unreachable data.

`DISAGREEMENTS FOUND` is the correct exit for this harness. Where the tools
disagree, they should be told, not made to agree.

**The rule, one layer up.** A comparison step that fails open reports
agreement it never established, and disagreement it invented. Both happened
here, from one `except Exception: return {vid}`.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
