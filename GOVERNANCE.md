# Governance

## Who decides

One maintainer. This is stated plainly because a governance document that
implies a committee nobody sits on is worse than none.

## How decisions are made

In `DECISIONS.md`, with the reasoning and the evidence, numbered and
indexed. The index is generated (`scripts/gen_decision_index.py`) and
checked in CI, so a decision cannot be added without appearing in the
index.

Two norms have held up well:

- **Measure, then claim.** Every number in a document is produced by a
  command a reader can run. Where a target is not met, the real number is
  published instead of the target being reinterpreted.
- **Break the guard, then fix it.** A safety check is not considered
  present until it has been made to fail. `scripts/mutation_audit.py`
  enforces this for the historical fixes.

## How to influence a decision

Open an issue with the command output that motivates it. Decisions here
have changed on exactly that kind of evidence: the resolver registry, the
CVSS merge rule, and the silent-zero invariant were all revised after
someone produced a failing run.

## Becoming a maintainer

There is no process, because there is nobody to hand over to. If that
changes it will be written here first.

## What a maintainer may not do

- Publish a release or cut a tag alone. A human reads the report and
  decides.
- Change repository settings, visibility, or secrets.
- Rewrite published history.

These were the constraints this project was built under and they are
recorded so a future maintainer knows they were deliberate.
