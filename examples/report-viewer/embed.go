// Package viewerexamples supplies explicitly synthetic, production-checked reports.
package viewerexamples

import "embed"

//go:embed fixtures/*.json
var Files embed.FS
