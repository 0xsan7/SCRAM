# Scanner and viewer release readiness

Updated 2026-11-21. This is a review checklist, not a release announcement.
The published stable release is [v0.2.0](https://github.com/0xsan7/SCRAM/releases/tag/v0.2.0).
It predates the [post-release correctness fixes](audits/2026-10-12.md), the
embedded `scram view` command and the browser report viewer.

## Integration scope

The product integration brings together the post-release scanner fixes, embedded
viewer, November regression suite, report metadata and single-report SARIF export.
The [November audit](audits/2026-11-21.md) records the tested starting point
at `651e0cb`. The original CSS backdrop replaces the trial photograph in the
static package and binary. Cloudflare production and signed release publication
have independent promotion steps. See [hosting configuration](report-viewer-hosting.md).

## Earlier local evidence

Run on 2026-11-20, macOS arm64, Go 1.23.4, against the source SHA above:

```sh
go test -race -coverprofile=/tmp/scram-preview.cover -covermode=atomic ./...
go vet ./...
node --test web/*.test.mjs
```

All packages passed with race detection, vet passed, and all 10 Node test
groups passed. Statement coverage: overall 71.4%, CLI 44.9%, scan 60.1%,
vulnerability client 84.2%, viewer server 87.1%. Coverage identifies paths
to exercise; it is not evidence that every meaningful scenario is tested.

The glass correction was also exercised in Brave at desktop and mobile
sizes: visible blur 0–40 px and saturation 50–200%, opacity, edge light,
tint, presets, reset and keyboard controls. This establishes that browser's
observed behavior, not Safari/Firefox or full accessibility coverage.

The GitHub Actions API returned zero workflow runs for `c6c50fe` when
checked on 2026-11-20. Opening the candidate PR starts the applicable jobs;
record their exact candidate SHA and conclusions before calling them passed.
Cloudflare's viewer build is narrower than the full GitHub CI matrix.

## Gates before publication

| Gate | Status | Evidence required to close |
| --- | --- | --- |
| One integrated candidate | In review | Review the complete diff against main, including scanner fixes, report semantics, embedded assets and viewer. |
| Hosted CI | Pending | Candidate passes Linux/macOS/Windows Go matrix, viewer checks, lint, corpus, official SBOM schemas and full-history secret checks; record fuzz/mutation results where triggered. |
| Installed user journey | Open | From a fresh released-candidate binary: scan a real repository, create JSON, open `scram view report.json`, inspect and export; exercise exit codes and stop the local server. |
| Browser journeys | Chromium covered in the November audit. Safari and Firefox open. | Valid/invalid file import, drag/drop, oversize files, report switching, filters, pagination, inspector and copy/download behavior across the supported browsers. |
| Completeness and resilience | Open | Exercise missing/partial OSV data, pagination, cache expiry/corruption, cancellation, Python ranges and skipped VCS/unpinned requirements; surface incomplete coverage explicitly. |
| Report provenance | Partial | Scan start, CLI version and scan mode are carried through JSON, the viewer and export. Source age and checked/skipped counts remain open. |
| Accessibility and performance | Open | Keyboard, screen reader, zoom, reduced transparency/forced colors, narrow layouts, and latency/memory near documented report limits. |
| Public assets | Trial photograph replaced | The release source uses an original CSS backdrop. Check the built package and retain the bundled font notices. |
| Published artifacts and Action | Open | Verify exact binaries, embedded assets, checksums/signatures, SBOMs, upgrade behavior and Action push/unchanged-PR/new-finding-PR behavior on the candidate release. |

## Scope after this release

Reachability, more ecosystems, freshness data and SLSA build attestations
remain separately scoped roadmap work. Offline cache-backed matching and
persistent EPSS caching are still unimplemented; do not advertise them as
working because online scans use a cache. Keep the documented `/65` score
semantics until a reviewed measurement change is implemented and tested.
