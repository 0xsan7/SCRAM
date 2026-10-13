package policy

import (
	"github.com/0xsan7/scram/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditNewnessIsScopedToComponent(t *testing.T) {
	cfg := Default()
	scan := model.Scan{Components: []model.Component{
		{Purl: "pkg:npm/old@1", Bucket: "low", Vulnerabilities: []model.Vuln{{ID: "CVE-SHARED", CVSSv3: 9.8}}},
		{Purl: "pkg:npm/new@1", Bucket: "low", Vulnerabilities: []model.Vuln{{ID: "CVE-SHARED", CVSSv3: 4.0}}},
	}}
	d := &model.DiffResult{Summary: model.Summary{NewVulnIDs: []string{"CVE-SHARED"}}, Drifts: []model.Drift{
		{Purl: "pkg:npm/old@1", Change: model.ChangeUnchanged},
		{Purl: "pkg:npm/new@1", Change: model.ChangeAdded, NewVulnerabilities: []string{"CVE-SHARED"}},
	}}
	if got := Evaluate(cfg, scan, d, false); !got.Pass {
		t.Fatalf("existing critical finding was gated because another component shared its ID: %v", got.Reasons)
	}
}

func TestAuditRejectsMisspelledPolicyFields(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ConfigName), []byte("fail_on_existingg: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("misspelled security setting was silently ignored")
	}
}

func TestAuditRejectsUnsupportedConfigVersion(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ConfigName), []byte("version: 999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("unsupported config version was accepted")
	}
}

func TestAuditNormalizesSBOMFormatValues(t *testing.T) {
	cfg := Default()
	cfg.SBOM.Formats = []string{" SPDX "}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.SBOM.Formats[0] != "spdx" {
		t.Fatalf("validated but left unnormalized: %q", cfg.SBOM.Formats[0])
	}
}

func TestAuditRejectsUnimplementedSources(t *testing.T) {
	for _, sources := range []Sources{{GHSA: true}, {OSV: true, NVD: true}} {
		cfg := Default()
		cfg.Sources = sources
		if err := cfg.normalize(); err == nil {
			t.Fatalf("unimplemented sources accepted: %+v", sources)
		}
	}
}
