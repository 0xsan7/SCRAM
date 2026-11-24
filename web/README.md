# SCRAM website and report viewer

The landing page explains SCRAM, links to an example report, and walks visitors
through installing the CLI, generating JSON and opening it privately. The
reader is a separate static page. Imported files are processed in the browser.

## Check and preview

With a SCRAM binary built from this branch, start the embedded viewer:

```sh
scram view
scram view report.json
```

Open the printed local URL. An optional file opens in the reader automatically. With no file, SCRAM serves the landing page. Ctrl+C stops the server. The viewer needs
no Node or Python runtime. This command is new in this branch and is not yet
part of the existing v0.2.0 release. From this checkout, use `go run ./cmd/scram view`.

For frontend development or a static hosting artifact, use Node.js 24 and
Python 3:

```sh
node --test web/*.test.mjs
node scripts/build-viewer.mjs
python3 -m http.server 4175 --bind 127.0.0.1 --directory dist/viewer
```

Open `http://127.0.0.1:4175`. The build is location-independent and includes
the production-generated synthetic reports; test files are not packaged.
`dist/viewer/` is generated output and stays ignored. These commands do not
publish, change DNS or create GitHub Pages settings.

### Regression tests

Run `node --test web/*.test.mjs scripts/viewer-cli.test.mjs` with Go and Node
installed. The CLI test builds SCRAM from the checkout and scans a temporary
lockfile under passing and failing license policies. It checks the exit code,
imports the actual JSON with the viewer, and verifies a known package digest
in both emitted SBOMs. Vulnerability matching is skipped for this fixture.

For the browser journey, build the binary with `go build -o scram ./cmd/scram`.
With Playwright Core and a compatible Chromium browser installed, run
`node --test scripts/viewer-browser.test.mjs`. Set `SCRAM_BIN` to select a
different binary, `SCRAM_BROWSER` to select a browser executable, or
`PLAYWRIGHT_MODULE` to select a locally installed Playwright Core module by
absolute path or file URL. The test opens a temporary report on loopback and
exercises import errors, drag and drop, pagination, filtered export, download,
mobile focus and switching reports at widths of 390 and 1440 pixels.

## Behavior and limits

- Load one of four synthetic scenarios, choose a local JSON file or drop one
  onto the file picker. File-picker/drop contents stay in the browser. The
  embedded CLI can serve an explicitly selected report from memory on loopback;
  the browser reads it from a same-origin endpoint under a random session path.
  Changing reports clears prior state. No arbitrary remote report URL is fetched.
- Policy outcome, failure reasons and warnings appear before inventory.
  A pass with existing findings is not labeled safe; missing drift is unknown.
- Search names, PURLs, ecosystems and finding IDs; filter inventory; inspect
  component findings/raw score terms; review new/resolved findings even when
  the dependency version is unchanged. Lists are paginated.
- Combine relationship, ecosystem and advisory-severity filters; sort by CVSS,
  name or original report order. Export a filtered inventory summary that keeps
  the full policy reasons/warnings: review it onscreen, copy it or request a text
  download. Browser download restrictions do not block the copyable summary.
- A native expandable guide provides the report-generation command. Larger
  report text, labeled controls and mobile inspector focus preserve keyboard
  access. The full-review example exercises six dependencies across four
  ecosystems; all identifiers and findings in it are invented.
- Schema 2.x, 5 MiB, 10,000 components, 50,000 findings and 500 warnings/failure
  reasons. Missing fields, inconsistent counts/score arithmetic and unsupported
  schemas fail explicitly. These are viewer limits, not scanner limits.
- Report strings are rendered with `textContent`; advisory links accept only
  explicit HTTP(S) URLs without embedded credentials and require a click.
  Bundled synthetic identifiers never link to advisory/package pages.
- New reports include the scan start time (UTC), generating CLI version and
  collection mode. The viewer and export label missing fields for older reports.
  Advisory mode describes the requested scan. Consult warnings for partial data.

See `examples/report-viewer/README.md` for input semantics and
`docs/report-viewer-design.md` for the interface direction. Font source and
license notices are retained in `assets/`.

## Hosting review

The production viewer is published at `https://scram.0xsan7.in/` through
Cloudflare Pages from `codex/scram-usability`. Other branches receive preview
deployments; the glass trial does not change production or the root portfolio.
A host should serve correct module
MIME types and may strengthen the supplied CSP with response headers such as
`frame-ancestors 'none'` and `X-Content-Type-Options: nosniff`.

The embedded server binds to `127.0.0.1` on a random port, accepts GET/HEAD
only, checks the Host/Origin, disables caching and frames, and embeds only viewer
assets plus synthetic examples. It never exposes the working directory or an
upload endpoint. The random URL is for local use, not a public share link.

## Public and loopback routes

The public build contains the homepage, report reader, a 404 page and static
assets, including four synthetic JSON reports. It has no public scan, report or
upload API. Cloudflare Pages uses the packaged `_headers` rules for a
same-origin content security policy, framing restrictions and no-referrer
navigation. The top-level 404 page prevents unknown paths from silently
falling back to the homepage. [Cloudflare Pages routing](https://developers.cloudflare.com/pages/configuration/serving-pages/) · [Custom headers](https://developers.cloudflare.com/pages/configuration/headers/)

The embedded server accepts GET and HEAD on loopback under a random session
prefix. It serves `report.json` inside that session only if the user opened a
specific file with `scram view report.json`. It rejects directory listings.
See [hosting configuration](../docs/report-viewer-hosting.md) for production and preview branches.
