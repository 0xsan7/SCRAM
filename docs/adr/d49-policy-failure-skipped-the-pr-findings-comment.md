# D49 — policy failure skipped the PR findings comment

<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the
     source, not this file. The prose is copied verbatim; only the
     structure is added. -->

**Number:** D49

**Title:** policy failure skipped the PR findings comment

**Format:** [MADR](https://adr.github.io/madr/) 3.0.1

**Context and decision**

**Context.** The real v0.2.0-rc1 PR check introduced `minimist@0.0.8`.
SCRAM correctly returned policy exit 1 for critical advisory
`GHSA-xvch-5gv4-984h` and wrote valid schema 2.0.0 JSON. GitHub then skipped
the composite Action's comment step because its condition implicitly
required all previous steps to succeed. The unchanged PR did post its
`21/65` score, so that positive case could not expose the missing failure
report.

**Decision.** The comment step runs with `always()` when the scan has
produced a score. It still requires the PR event and `comment-on-pr` input.
The score-output guard prevents a download, baseline, or scanner crash
from being mistaken for a valid policy result. The scan step continues to
fail the job; posting its report must not turn a rejected PR green.

**Verification.** The corrected Action was checked using its exact SHA
and the verified rc1 binary, then repeated against stable v0.2.0. Both
five-platform push matrices passed. Unchanged PRs passed and rendered
`21/65`; new-finding PRs remained red and rendered `25/65`, two new
advisories, one new high and one new critical finding. Comment IDs were
retained across reruns. Immutable run links are in
[the release validation record](https://github.com/0xsan7/SCRAM/blob/71b2e122481c1062e5839700b12517a108f34812/docs/releases/v0.2.0.md).

---

Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. Regenerate with `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py`.
