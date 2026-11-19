# Scanner and viewer release readiness

Updated 2026-11-20. This is a review checklist, not a release announcement.
The published stable release is [v0.2.0](https://github.com/0xsan7/SCRAM/releases/tag/v0.2.0).
It predates the [post-release correctness fixes](audits/2026-10-12.md), the
embedded `scram view` command and the browser report viewer.

## Candidate and deployment boundaries

- Source under local test: `c6c50fe6d96b21c0794fcd9ba1ca9e28148e1d45`.
- `codex/scram-glass-preview` contains the scanner/viewer work, 18 commits
  beyond `main` at `4bee3c63477e7b2a98b9e7118d0c279cb386908b`.
- `codex/scram-release-readiness` carries this candidate forward for review.
- Cloudflare production uses `codex/scram-usability`; a merge to `main`
  does not automatically update that production branch setting. See
  [hosting configuration](report-viewer-hosting.md).
- Keep existing branches and published tags. Review merging, release
  publication and production promotion as separate actions.

## Local evidence

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
| Browser journeys | Open | Valid/invalid file import, drag/drop, oversize files, report switching, filters, pagination, inspector and copy/download behavior across the supported browsers. The last automated import attempt was blocked by extension file-access permissions. |
| Completeness and resilience | Open | Exercise missing/partial OSV data, pagination, cache expiry/corruption, cancellation, Python ranges and skipped VCS/unpinned requirements; surface incomplete coverage explicitly. |
| Report provenance | Open | Structured scan time, generating version, source availability/freshness and checked/unmatched counts, with producer/consumer compatibility tests. |
| Accessibility and performance | Open | Keyboard, screen reader, zoom, reduced transparency/forced colors, narrow layouts, and latency/memory near documented report limits. |
| Public assets | Open | Identify a license for the reference photograph or replace it with an owned/clearly licensed asset. Its [source record](../web/assets/GLASS-ROOM-SOURCE.md) does not establish a license. |
| Published artifacts and Action | Open | Verify exact binaries, embedded assets, checksums/signatures, SBOMs, upgrade behavior and Action push/unchanged-PR/new-finding-PR behavior on the candidate release. |

## Scope after this release

Reachability, more ecosystems, freshness data and SLSA build attestations
remain separately scoped roadmap work. Offline cache-backed matching and
persistent EPSS caching are still unimplemented; do not advertise them as
working because online scans use a cache. Keep the documented `/65` score
semantics until a reviewed measurement change is implemented and tested.
