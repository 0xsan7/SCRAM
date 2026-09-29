# ⚠ BREAKING: `schema_version` is now 2.0.0, and `repo_score` means something different

**If you consume SCRAM's JSON, read this before upgrading. Your code will not
fail — it will be quietly wrong.**

`summary.repo_score` changed meaning and kept its name. It is now a
**presented score out of 65**. It used to be a **raw total out of 100**.

A consumer written against `schema_version: 1.0.0` parses the new document
successfully, because the field names are unchanged. It then renders
`25/100` for what is now `25/65` — **wrong by 35%**, with nothing in the
document to contradict it. That is why this is a *major* version bump rather
than a minor one: the failure mode is silence.

## What to change

```diff
- fmt.Printf("score %d/100\n", summary.repo_score)
+ fmt.Printf("score %d/%d\n", summary.repo_score, summary.repo_score_max)
```

Read `summary.repo_score_max`. Do not hardcode either 65 or 100. If your
consumer compares scores across versions of SCRAM, note that **a score from
1.x and a score from 2.x are on different scales** and are not comparable —
this is the one case where a trend line built from old history needs to be
discarded rather than continued.

## What did not change

- The **ordering** is identical. A consumer that only sorts, ranks, or picks
  the maximum is unaffected; the severity ordering underneath is the same.
- `scram badge` reads a scan document, so it picked the change up
  automatically and now emits `25/65`.
- SARIF is unaffected: it never carried a repository score, and its
  `securitySeverity` is GitHub's own 0–10 CVSS field.
- The **formula is untouched**. Severity (40), exploitability (25),
  maintenance (20) and freshness (15) are computed exactly as before, in the
  same units with the same weights. `--explain` prints all four plus the
  0–100 subtotal they sum to, so the arithmetic stays checkable. Only the
  total the score is *reported* against changed.

## Bucket boundaries moved with the scale

| Bucket | 2.x (of 65) | was (of 100) |
|---|---|---|
| Critical | 58–65 | 90–100 |
| High | 45–57 | 70–89 |
| Medium | 26–44 | 40–69 |
| Low | 1–25 | 1–39 |
| Clean | 0 | 0 |

The rescale is monotonic but **not** bucket-preserving. Checked across all 101
possible inputs, exactly two change bucket, both upward: a raw total of 69
becomes *high* (it was *medium*), and 89 becomes *critical* (it was *high*).
No input is demoted. If you alert on bucket transitions, expect those two.

## Why 65 and not 100

`scripts/measure_score_terms.sh` runs every ecosystem and prints which terms
carry data. Severity is the only term that scores without an opt-in flag.
Exploitability needs EPSS, which is a per-CVE fetch that returns nothing when
FIRST is unreachable, and freshness needs latest-version data this project
does not collect — so it is structurally zero everywhere.

Dividing by 100 advertised 35 points the tool usually cannot earn, and a
moderately-scored repository read as "39/100" when 39 was all the evidence
there was. See [ROADMAP.md](https://github.com/0xsan7/SCRAM/blob/main/ROADMAP.md)
for what a 100-point scale would require.
