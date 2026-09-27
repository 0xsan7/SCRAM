// Package sbom serializes a component list into CycloneDX 1.5 and SPDX 2.3
// JSON documents (FR-103, FR-104). Both are generated from the same component
// list so the two artifacts can never disagree about what's in the repo.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0xsan7/scram/internal/model"
)

// Timestamp returns an RFC3339 UTC time suitable for either spec's
// serialNumber/created fields. Overridable in tests for deterministic output.
var Timestamp = func() time.Time { return time.Now().UTC() }

// Tool identification embedded in every document, so consumers can tell which
// SCRAM version produced it.
const (
	ToolName      = "scram"
	ToolVendor    = "0xsan7"
	ToolVersion   = "0.1.0"
	CycloneDXSpec = "1.5"
	SPDXVersion   = "SPDX-2.3"
)

// Format names the supported SBOM encodings.
type Format string

const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
)

// Write serializes components in the requested format to dir. The filename is
// derived from repoName so multiple repos in a monorepo don't overwrite each
// other. Returns the path written.
func Write(dir string, repoName string, format Format, components []model.Component) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var (
		data []byte
		err  error
		base string
	)
	switch format {
	case FormatCycloneDX:
		data, err = marshalCycloneDX(repoName, components)
		base = "sbom.cdx.json"
	case FormatSPDX:
		data, err = marshalSPDX(repoName, components)
		base = "sbom.spdx.json"
	default:
		return "", fmt.Errorf("unknown SBOM format %q (want cyclonedx or spdx)", format)
	}
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, base)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// contentHash derives a stable SHA-256 over the component's identity. This is
// not a hash of the package bytes — SCRAM does not download packages, it
// reads lockfiles — so it is a *component identity* hash, which is what lets
// the same dependency in two repos dedupe downstream.
func contentHash(c model.Component) string {
	sum := sha256.Sum256([]byte(c.Purl + "|" + c.Ecosystem))
	return hex.EncodeToString(sum[:])
}

// serialNumber builds the CycloneDX serialNumber: "urn:uuid:<uuid>". Derived
// deterministically from the repo name so repeated runs on an unchanged repo
// produce an identical document, which is what makes golden-file tests and
// PR diffs meaningful.
func serialNumber(repoName string) string {
	sum := sha256.Sum256([]byte("scram-serial:" + repoName))
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// SPDX document namespace must be a unique URI per document. Same determinism
// rationale as serialNumber.
func spdxNamespace(repoName string) string {
	sum := sha256.Sum256([]byte("scram-spdx:" + repoName))
	return "https://spdx.org/spdxdocs/scram-" + hex.EncodeToString(sum[:16])
}
