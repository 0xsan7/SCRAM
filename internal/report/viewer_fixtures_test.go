package report

import (
	"bytes"
	"fmt"
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

func TestFullReviewFixtureMatchesReportWriter(t *testing.T) {
	components := []model.Component{}
	for i, item := range []struct {
		name, ecosystem, purl string
		cvss                  float64
		direct                bool
	}{
		{"demo-web-client", model.EcoNPM, "pkg:npm/demo-web-client@2.0.0", 9.6, true},
		{"demo-task-worker", model.EcoPyPI, "pkg:pypi/demo-task-worker@2.0.0", 8.1, false},
		{"demo-request-router", model.EcoGo, "pkg:golang/demo-request-router@2.0.0", 5.3, true},
		{"demo-log-adapter", model.EcoNPM, "pkg:npm/demo-log-adapter@2.0.0", 2.4, false},
		{"demo-config-reader", model.EcoCargo, "pkg:cargo/demo-config-reader@2.0.0", 0, true},
		{"demo-metrics-agent", model.EcoGo, "pkg:golang/demo-metrics-agent@2.0.0", 0, false},
	} {
		component := model.Component{Name: item.name, Purl: item.purl, Version: "2.0.0", Ecosystem: item.ecosystem, Direct: item.direct, License: "MIT", Vulnerabilities: []model.Vuln{}}
		if item.cvss > 0 {
			component.Vulnerabilities = append(component.Vulnerabilities, model.Vuln{ID: fmt.Sprintf("DEMO-REVIEW-%03d", i+1), Source: "synthetic", CVSSv3: item.cvss, Summary: "Invented finding for exploring the report viewer; not a real vulnerability.", FixedVersion: "2.1.0"})
		}
		components = append(components, component)
	}
	head := model.Scan{SchemaVersion: model.SchemaVersion, Repo: "synthetic-multi-ecosystem-demo", Components: components, Summary: score.New().Score(components)}
	baseComponents := append([]model.Component(nil), components...)
	baseComponents[0].Vulnerabilities = []model.Vuln{}
	base := model.Scan{SchemaVersion: model.SchemaVersion, Repo: head.Repo, Components: baseComponents, Summary: score.New().Score(baseComponents)}
	diff := drift.Diff(base, head)
	decision := policy.Evaluate(policy.Default(), head, &diff, false)
	if decision.Pass {
		t.Fatal("new critical synthetic finding should fail policy")
	}
	var output bytes.Buffer
	if err := Write(&output, head, &diff, FormatJSON, decision); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "examples", "report-viewer", "fixtures", "full-review.json")
	if os.Getenv("UPDATE_VIEWER_FIXTURES") == "1" {
		if err := os.WriteFile(path, output.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fixture, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixture, output.Bytes()) {
		t.Fatal("full review fixture differs from production writer")
	}
}
