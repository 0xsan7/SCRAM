package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xsan7/scram/internal/drift"
	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/policy"
	"github.com/0xsan7/scram/internal/score"
)

// Viewer examples are explicitly synthetic. Generate their scores, drift and
// decisions with production code so the future UI consumes the real contract.
func viewerScan(hasFinding bool) model.Scan {
	findings := []model.Vuln{}
	if hasFinding {
		findings = append(findings, model.Vuln{
			ID: "DEMO-HIGH-001", Source: "synthetic", CVSSv3: 8.1,
			Summary: "Synthetic high-severity finding for the report viewer",
		})
	}
	components := []model.Component{{
		Purl: "pkg:npm/viewer-example@1.0.0", Name: "viewer-example", Version: "1.0.0",
		Ecosystem: model.EcoNPM, Direct: true, License: "MIT", Vulnerabilities: findings,
	}}
	return model.Scan{
		SchemaVersion: model.SchemaVersion, Repo: "synthetic-viewer-demo",
		Components: components, Summary: score.New().Score(components),
	}
}

func TestViewerFixturesMatchReportWriter(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		baseFinding bool
		headFinding bool
		degraded    bool
		wantPass    bool
	}{
		{"passed-with-existing-finding", true, true, false, true},
		{"blocked-new-finding", false, true, false, false},
		{"incomplete-no-findings", false, false, true, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			head := viewerScan(scenario.headFinding)
			base := viewerScan(scenario.baseFinding)
			diff := drift.Diff(base, head)
			if scenario.degraded {
				head.Warnings = []string{"Synthetic demo: vulnerability data was unavailable; this is not a clean result."}
			}
			decision := policy.Evaluate(policy.Default(), head, &diff, scenario.degraded)
			if decision.Pass != scenario.wantPass {
				t.Fatalf("policy pass=%v, want %v; reasons=%v", decision.Pass, scenario.wantPass, decision.Reasons)
			}
			var output bytes.Buffer
			if err := Write(&output, head, &diff, FormatJSON, decision); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("..", "..", "examples", "report-viewer", "fixtures", scenario.name+".json")
			if os.Getenv("UPDATE_VIEWER_FIXTURES") == "1" {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, output.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			fixture, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fixture, output.Bytes()) {
				t.Fatal("viewer fixture differs from the report writer; review the change, then regenerate with UPDATE_VIEWER_FIXTURES=1")
			}
		})
	}
}
