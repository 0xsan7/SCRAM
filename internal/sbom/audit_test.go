package sbom

import (
	"encoding/json"
	"github.com/0xsan7/scram/internal/model"
	"strings"
	"testing"
)

func TestAuditSBOMDoesNotInventPackageChecksums(t *testing.T) {
	comps := []model.Component{{Purl: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm"}}
	cdx, err := marshalCycloneDX("app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var c cdxDoc
	if err := json.Unmarshal(cdx, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Components[0].Hashes) != 0 {
		t.Fatalf("identity was presented as a package content hash: %+v", c.Components[0].Hashes)
	}
	spdx, err := marshalSPDX("app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var s spdxDoc
	if err := json.Unmarshal(spdx, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Packages[0].Checksums) != 0 {
		t.Fatalf("invented SPDX package checksum: %+v", s.Packages[0].Checksums)
	}
}

func TestAuditSBOMPreservesRealDigest(t *testing.T) {
	digest := strings.Repeat("ab", 64)
	comps := []model.Component{{Purl: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm", Hashes: map[string]string{"SHA-512": digest}}}
	data, err := marshalSPDX("app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	hashes := doc.Packages[0].Checksums
	if len(hashes) != 1 || hashes[0].Algorithm != "SHA512" || hashes[0].ChecksumValue != digest {
		t.Fatalf("real digest replaced with identity: %+v", hashes)
	}
}

func TestAuditCycloneDXLinksAllAffectedComponents(t *testing.T) {
	comps := []model.Component{{Purl: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm", Vulnerabilities: []model.Vuln{{ID: "CVE-SHARED"}}}, {Purl: "pkg:npm/b@1", Name: "b", Version: "1", Ecosystem: "npm", Vulnerabilities: []model.Vuln{{ID: "CVE-SHARED"}}}}
	data, err := marshalCycloneDX("app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var doc cdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulns) != 1 || len(doc.Vulns[0].Affects) != 2 {
		t.Fatalf("advisory lacks affected component references: %+v", doc.Vulns)
	}
}
