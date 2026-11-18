# Report viewer: first build brief

Status: data fixtures and implementation brief only. No browser UI or hosting
has been built or enabled by this change.

## Job and audience

A maintainer or portfolio reviewer opens a scan report and answers: did the
policy pass, what findings changed, and what evidence is missing? The primary
action is to inspect a bundled example or a local JSON file. Files stay in
the browser; the first version makes no scan, advisory or telemetry requests.

## Scope

- One static screen: file/example selection, policy outcome and warnings,
  current inventory, then new/resolved finding details when drift is present.
- Keep warnings and failure reasons above score summaries. A passing policy
  does not mean no findings; zero findings do not mean a complete assessment.
- Search components by name/PURL, distinguish direct/transitive dependencies,
  and show the score denominator from the report. Do not invent a production
  dependency flag or treat a suggested fixed version as an applied upgrade.
- Use a readable table/list on desktop and stacked component rows on mobile.
  Native file input, labeled controls, visible focus and text status labels
  are required. Visual styling remains a later review decision.
- Proposed future hostname: `scram.0xsan7.in`. No DNS, deployment, accounts,
  repository cloning, uploads or live scanning are part of this brief.

## Input contract and limits

Consume the document produced by `scram scan --format json`: top-level
`schema_version`, `scan`, optional `drift`, `passed`, optional `fail_reasons`.
The nested scan has its own schema version, components, summary and optional
warnings. Start with schema `2.0.0`; reject other major versions explicitly.
Validate types, required fields and reasonable size/count limits before
rendering. Initial proposed limits: 5 MiB and 10,000 components, with a clear
error when exceeded. These are UI limits, not scanner limits.

The report has no scan timestamp, CLI version, explicit inventory-only flag,
or top-level degraded flag. Do not manufacture those fields, infer freshness
from the current time, or infer completeness from `passed`/a zero score.
Show warnings verbatim as text and use "Policy passed" rather than "Safe".
An imported report without mode/provenance remains an unverified imported
report. A zero EPSS value cannot establish whether enrichment ran.

Treat report strings as untrusted text. Do not render supplied HTML. Future
advisory links must be valid HTTP(S) URLs; opening a report must never fetch
them automatically. Malformed JSON, unsupported schema, missing summary,
inconsistent counts, absent drift, no findings, policy failure and warnings
need distinct states. Never reinterpret a parse failure as an empty scan.

## Synthetic examples

All files in `fixtures/` are synthetic UI demonstrations, not vulnerability
observations or real scan results. `DEMO-HIGH-001` and `viewer-example` are
invented demo identifiers; they must have no external advisory/package links.
Keep a visible synthetic-example label whenever they are loaded.

| File | Expected behavior |
|---|---|
| `passed-with-existing-finding.json` | Policy passes with a pre-existing high finding; show that finding and zero new findings |
| `blocked-new-finding.json` | Same package/version gains a new high finding; show a failed gate and its reason even though the dependency version did not change |
| `incomplete-no-findings.json` | Zero known findings with unavailable data; show warning and failed policy, never a clean success |

Scores, drift and decisions are generated using SCRAM's production model,
score engine, drift engine, policy evaluator and JSON writer. They are
verified by `TestViewerFixturesMatchReportWriter`; no network is needed.

```sh
go test ./internal/report -run TestViewerFixturesMatchReportWriter -v
# Only after reviewing an intentional contract/data change:
UPDATE_VIEWER_FIXTURES=1 go test ./internal/report -run TestViewerFixturesMatchReportWriter
```

First UI acceptance: a visitor can explain all three example outcomes,
switching files clears prior data/errors, missing drift is not a zero-change
claim, and keyboard/mobile use exposes the same information. A live public
scan service is a separate future design and security decision.
