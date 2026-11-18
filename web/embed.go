// Package viewerassets holds the report viewer shipped in the SCRAM binary.
package viewerassets

import "embed"

// Files contains only browser assets, never source tests or local reports.
//
//go:embed index.html styles.css app.mjs report.mjs assets
var Files embed.FS
