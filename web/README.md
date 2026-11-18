# SCRAM report viewer

Static, browser-local report inspection. No frontend dependencies, accounts,
upload service or live scans. The dark interface follows the approved
portfolio direction and uses its self-hosted fonts.

## Check and preview

Requires Node.js 24 and Python 3 for the local preview command:

```sh
node --test web/*.test.mjs
node scripts/build-viewer.mjs
python3 -m http.server 4175 --bind 127.0.0.1 --directory dist/viewer
```

Open `http://127.0.0.1:4175`. The build is location-independent and includes
the production-generated synthetic reports; test files are not packaged.
`dist/viewer/` is generated output and stays ignored. These commands do not
publish, change DNS or create GitHub Pages settings.

## Behavior and limits

- Load a bundled synthetic scenario or choose a local JSON file. The only
  fetches in application code load the explicitly chosen same-origin example.
  File contents are read locally, and changing reports clears prior state.
- Policy outcome, failure reasons and warnings appear before inventory.
  A pass with existing findings is not labeled safe; missing drift is unknown.
- Search names, PURLs, ecosystems and finding IDs; filter inventory; inspect
  component findings/raw score terms; review new/resolved findings even when
  the dependency version is unchanged. Lists are paginated.
- Schema 2.x, 5 MiB, 10,000 components, 50,000 findings and 500 warnings/failure
  reasons. Missing fields, inconsistent counts/score arithmetic and unsupported
  schemas fail explicitly. These are viewer limits, not scanner limits.
- Report strings are rendered with `textContent`; advisory links accept only
  explicit HTTP(S) URLs without embedded credentials and require a click.
  Bundled synthetic identifiers never link to advisory/package pages.
- No scan time, CLI version, enrichment coverage or complete inventory can be
  inferred when the current report schema does not supply that evidence.

See `examples/report-viewer/README.md` for input semantics and
`docs/report-viewer-design.md` for the interface direction. Font source and
license notices are retained in `assets/`.

## Hosting review

The packaged directory can be served as static files. The proposed subdomain
is `scram.0xsan7.in`; nothing here enables automatic public deployment. Keep
the root portfolio unchanged and review the artifact, domain and hosting
configuration before enabling publication. A host should serve correct module
MIME types and may strengthen the supplied CSP with response headers such as
`frame-ancestors 'none'` and `X-Content-Type-Options: nosniff`.
