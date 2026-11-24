// Package viewerassets holds the report viewer shipped in the SCRAM binary.
package viewerassets

import "embed"

// Files contains only browser assets, never source tests or local reports.
//
//go:embed index.html viewer.html styles.css landing.css footer.css footer.mjs site.mjs app.mjs report.mjs assets/favicon.svg assets/footer-glyphs.svg assets/fonts assets/landscape-*.webp
var Files embed.FS
