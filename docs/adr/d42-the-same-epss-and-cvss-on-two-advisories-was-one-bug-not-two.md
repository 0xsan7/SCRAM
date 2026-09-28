# D42 — the same EPSS and CVSS on two advisories was one bug, not two

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D42

**Title:** the same EPSS and CVSS on two advisories was one bug, not two

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**The report.** Two lodash advisories showed an identical EPSS of 21.33%
and a CVSS of 8.1. Identical numbers on two records looked like a
lookup bug.

**What the data actually said.** EPSS was correct. Every value matched
FIRST.org exactly:

| advisory | CVE | SCRAM EPSS | FIRST.org |
|---|---|---|---|
| GHSA-jf85-cpcp-j695 | CVE-2019-10744 | 0.05006 | 0.050060000 |
| GHSA-35jh-r3h4-6jhm | CVE-2021-23337 | 0.21333 | 0.213330000 |
| GHSA-p6mc-m468-83gw | CVE-2020-8203 | 0.05213 | 0.052130000 |
| GHSA-29mw-wpgm-hmr9 | CVE-2020-28500 | 0.07336 | 0.073360000 |

Of course they matched: `GHSA-35jh` and `GHSA-r5fr` are two records for
the *same* CVE, so they carry the same EPSS. That is the alias dedupe
working, not failing. A repeated number across two advisories is the
expected shape of two identifiers for one vulnerability, and reading it
as a bug sent the investigation at the wrong subsystem.

**The real bug was in CVSS.** Those two records carry *different*
vectors, because GitHub rescored the issue when its scope model changed:

```
GHSA-35jh-r3h4-6jhm  AC:L/PR:H  ->  7.2     OSV's canonical record
GHSA-r5fr-rjxr-66jc  AC:H/PR:N  ->  8.1     the older record
```

`Dedupe` merged the group and took `if v.CVSSv3 > best.CVSSv3`, so
GHSA-35jh was reported at 8.1 with GHSA-r5fr's vector. That is a
severity belonging to a different record, presented as though it were
the matched advisory's own. A reader comparing against the GitHub
advisory sees a discrepancy with no way to tell which number is the
mistake.

**The fix.** A score is not a measure of completeness, so it is never
adopted from a sibling. The selected record keeps its own score; a
vector is only recovered from a sibling that has the vector for the
*same* score, which completes a record rather than replacing one.

**Why this mattered more than the number.** The project's premise is
that it does not report a severity it did not verify. This one was
internally consistent -- 8.1 and the 8.1 vector agreed with each other
-- and still wrong, because both numbers came from a record that was not
the one matched. Self-consistency is not provenance.

**Verified.** All five lodash findings now have a score that matches an
independent CVSS 3.1 implementation run over the vector that ships with
them: 9.1, 7.4, 7.2, 6.5, 5.3, every one matching. Re-introducing
`if v.CVSSv3 > best.CVSSv3` turns
`TestDedupeDoesNotInflateCVSSFromASiblingRecord` red with
`CVSSv3 = 8.1, want at most 7.2`.

**Also added.** `TestDedupeKeepsScoreAndVectorFromTheSameRecord` (a
merged pair must trace back to one input record) and
`TestDedupeEPSSDoesNotTreatZeroAsBetter` (an absent score must not
outrank a real one). The first version of the fix reordered the
comparison instead of removing it and the test stayed red, which is what
proved the test was load-bearing rather than descriptive.

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
