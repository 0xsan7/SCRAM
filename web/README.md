# SCRAM report viewer

Static, browser-local report inspection. No frontend dependencies, accounts,
upload service or live scans. The dark interface follows the approved
portfolio direction and uses its self-hosted fonts.

## Check and preview

With a SCRAM binary built from this branch, start the embedded viewer:

```sh
scram view
scram view report.json
```

Open the printed local URL. The optional file is loaded automatically; without
one, explore the synthetic examples. Ctrl+C stops the server. The viewer needs
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
- No scan time, CLI version, enrichment coverage or complete inventory can be
  inferred when the current report schema does not supply that evidence.

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

## Glass styling trial

The `codex/scram-glass-preview` branch applies the supplied dashboard's glass
material to this existing viewer, as requested. It adds no React, Tailwind,
GSAP or frontend dependencies. The reference's room photograph is bundled
locally, so appearance makes no third-party image requests. Its source is
recorded in `assets/GLASS-ROOM-SOURCE.md`. The production branch remains
`codex/scram-usability` until the trial is reviewed.

Use **Adjust glass** to choose Clear, Frosted or Solid, or adjust blur, opacity,
saturation, edge light and tint. Settings last only for the current page session;
they are never read from reports or saved to local storage. Solid mode removes
blur/transparency, and browser accessibility preferences can enforce solid
surfaces. Escape closes the appearance disclosure and restores trigger focus.
The module bounds all material values and accepts only six-digit hex tints.
`glass.css` and `glass.mjs` are packaged both in the static output and Go binary.

The reference's 30% default opacity lets the sharp room image show through;
blur (0–40 px) and saturation (50–200%) filter that scenery, while report text
stays sharp. A live sample uses the same material. Opacity spans 8–100%; at
100%, the opaque surface hides the backdrop, so blur and saturation cannot
show through. Solid intentionally removes blur as an accessibility fallback.

This is a visual adaptation of the user's supplied component, not a copy of its
finance demo or its React implementation. Report policy, inventory, warnings,
filters, imports and export retain the existing behavior. The trial direction
is recorded in `docs/report-viewer-glass-preview.md`.

See `docs/report-viewer-hosting.md` for the public demo configuration.
