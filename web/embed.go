// Package viewerassets holds the report viewer shipped in the SCRAM binary.
package viewerassets

import "embed"

// Files contains only browser assets, never source tests or local reports.
//
//go:embed index.html viewer.html styles.css site.mjs app.mjs report.mjs assets/favicon.svg assets/fonts
var Files embed.FS
