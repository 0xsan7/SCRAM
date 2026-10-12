package drift

import (
	"github.com/0xsan7/scram/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditMultiVersionRemovalIsNotLost(t *testing.T) {
	a := model.Component{Purl: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm", Vulnerabilities: []model.Vuln{{ID: "CVE-OLD"}}}
	b := model.Component{Purl: "pkg:npm/a@2", Name: "a", Version: "2", Ecosystem: "npm"}
	d := Diff(model.Scan{Components: []model.Component{a, b}}, model.Scan{Components: []model.Component{b}})
	if len(d.Drifts) != 2 {
		t.Fatalf("drifts=%+v, want removed a@1 and unchanged a@2", d.Drifts)
	}
}

func TestAuditNewDisclosureCountsWithoutVersionChange(t *testing.T) {
	a := model.Component{Purl: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm"}
	b := a
	b.Vulnerabilities = []model.Vuln{{ID: "CVE-NEW", CVSSv3: 9.8}}
	d := Diff(model.Scan{Components: []model.Component{a}}, model.Scan{Components: []model.Component{b}})
	if d.Summary.NewCritical != 1 || d.Summary.NewHigh != 1 {
		t.Fatalf("new disclosure counted incorrectly: %+v", d.Summary)
	}
}

func TestAuditRejectReportAsBaseline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(p, []byte(`{"schema_version":"2.0.0","scan":{"components":[]},"passed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBaseline(p); err == nil {
		t.Fatal("wrapped report silently accepted as empty baseline")
	}
}

func TestAuditAliasRepresentativeChangeIsNotNew(t *testing.T) {
	a := model.Component{Purl: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm", Vulnerabilities: []model.Vuln{{ID: "GHSA-old", Aliases: []string{"CVE-SAME"}}}}
	b := a
	b.Vulnerabilities = []model.Vuln{{ID: "CVE-SAME", CVSSv3: 9.8}}
	d := Diff(model.Scan{Components: []model.Component{a}}, model.Scan{Components: []model.Component{b}})
	if len(d.Summary.NewVulnIDs) != 0 || len(d.Drifts[0].ResolvedVulnerabilities) != 0 {
		t.Fatalf("alias-only change introduced/resolved a finding: %+v", d)
	}
}
