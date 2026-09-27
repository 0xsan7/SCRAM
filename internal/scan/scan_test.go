package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/drift"
	"github.com/0xsan7/scram/internal/model"
)

// npmRepo writes a small npm project and returns its root.
func npmRepo(t *testing.T, lodashVersion string) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"fixture","dependencies":{"lodash":"`+lodashVersion+`"}}`)
	write("package-lock.json", `{
		"name": "fixture",
		"lockfileVersion": 3,
		"requires": true,
		"packages": {
			"": {"name":"fixture","dependencies":{"lodash":"`+lodashVersion+`"}},
			"node_modules/lodash": {"version":"`+lodashVersion+`","license":"MIT"}
		}
	}`)
	return root
}

// TestScanEndToEndOffline runs the full pipeline — detect, resolve, score,
// policy — with no network. Vulnerability matching is skipped because it is
// the only stage that needs upstream access, and what is being verified here
// is the plumbing.
func TestScanEndToEndOffline(t *testing.T) {
	root := npmRepo(t, "4.17.21")
	out := t.TempDir()

	res, err := Run(context.Background(), Options{
		Path:        root,
		SBOMFormats: []string{"cyclonedx", "spdx"},
		OutDir:      out,
		SkipVuln:    true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.Scan.Summary.TotalComponents != 1 {
		t.Errorf("components: got %d, want 1", res.Scan.Summary.TotalComponents)
	}
	if res.Scan.Components[0].Purl != "pkg:npm/lodash@4.17.21" {
		t.Errorf("purl: got %q", res.Scan.Components[0].Purl)
	}
	if !res.Scan.Components[0].Direct {
		t.Error("lodash is a direct dependency")
	}
	// Both SBOMs should have been written.
	if len(res.SBOMPaths) != 2 {
		t.Fatalf("SBOM paths: got %v, want 2 entries", res.SBOMPaths)
	}
	for _, p := range res.SBOMPaths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("SBOM %s not written: %v", p, err)
		}
	}
	// A clean repo with no vulns must pass.
	if !res.Decision.Pass {
		t.Errorf("expected a pass, got reasons: %v", res.Decision.Reasons)
	}
}

// TestScanEmptyRepoFails covers the trust rule: finding nothing is not the
// same as finding nothing wrong.
func TestScanEmptyRepoFails(t *testing.T) {
	res, err := Run(context.Background(), Options{
		Path:     t.TempDir(),
		SkipVuln: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Decision.Pass {
		t.Error("a scan that found no lockfiles must not pass; it verified nothing")
	}
	found := false
	for _, r := range res.Decision.Reasons {
		if strings.Contains(r, "no dependency lockfiles") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a no-lockfiles reason, got %v", res.Decision.Reasons)
	}
}

// TestScanWithBaselineDetectsDrift is the §17 Phase 5 acceptance test at the
// engine level: a version change that introduces risk must show up as drift.
func TestScanWithBaselineDetectsDrift(t *testing.T) {
	// Capture a baseline at the patched version.
	root := npmRepo(t, "4.17.21")
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")

	base, err := Run(context.Background(), Options{
		Path:     root,
		SkipVuln: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBaseline(baselinePath, base.Scan); err != nil {
		t.Fatal(err)
	}

	// Downgrade lodash and rescan against the baseline. With vuln matching
	// skipped there are no CVEs, so the assertion is that the version change
	// itself is detected as drift.
	root2 := npmRepo(t, "4.17.11")
	// The baseline path lives in a different temp dir, so copy it next to the
	// second repo.
	local := filepath.Join(root2, "baseline.json")
	copyFile(t, baselinePath, local)

	head, err := Run(context.Background(), Options{
		Path:         root2,
		SkipVuln:     true,
		BaselinePath: local,
	})
	if err != nil {
		t.Fatal(err)
	}
	if head.Diff == nil {
		t.Fatal("expected a diff result")
	}
	if len(head.Diff.Drifts) != 1 {
		t.Fatalf("got %d drift entries, want 1: %+v", len(head.Diff.Drifts), head.Diff.Drifts)
	}
	d := head.Diff.Drifts[0]
	if d.Change != model.ChangeVersionChanged {
		t.Errorf("change: got %q, want %q", d.Change, model.ChangeVersionChanged)
	}
	if d.PreviousVersion != "4.17.21" || d.NewVersion != "4.17.11" {
		t.Errorf("versions: got %s -> %s", d.PreviousVersion, d.NewVersion)
	}
}

func TestScanEcosystemFilter(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "package-lock.json"),
		[]byte(`{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/a":{"version":"1.0.0"}}}`), 0o644)
	os.WriteFile(filepath.Join(root, "go.sum"),
		[]byte("github.com/x/y v1.0.0 h1:abc=\ngithub.com/x/y v1.0.0/go.mod h1:def=\n"), 0o644)
	os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module x\n\ngo 1.22\n\nrequire github.com/x/y v1.0.0\n"), 0o644)

	all, err := Run(context.Background(), Options{Path: root, SkipVuln: true})
	if err != nil {
		t.Fatal(err)
	}
	if all.Scan.Summary.TotalComponents != 2 {
		t.Errorf("unfiltered: got %d components, want 2", all.Scan.Summary.TotalComponents)
	}

	only, err := Run(context.Background(), Options{
		Path: root, SkipVuln: true, Ecosystems: []string{"go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if only.Scan.Summary.TotalComponents != 1 {
		t.Errorf("filtered to go: got %d components, want 1", only.Scan.Summary.TotalComponents)
	}
	if only.Scan.Components[0].Ecosystem != model.EcoGo {
		t.Errorf("ecosystem: got %q, want go", only.Scan.Components[0].Ecosystem)
	}
}

func TestScanWritesConfigurableBaseline(t *testing.T) {
	root := npmRepo(t, "4.17.21")
	res, err := Run(context.Background(), Options{Path: root, SkipVuln: true})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "b.json")
	if err := writeBaseline(path, res.Scan); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bl model.Baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		t.Fatalf("baseline is not valid JSON: %v", err)
	}
	if bl.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema version: got %q", bl.SchemaVersion)
	}
}

// writeBaseline captures a scan as a baseline, wrapping drift.WriteBaseline
// so the intent reads clearly at the call sites.
func writeBaseline(path string, s model.Scan) error {
	return drift.WriteBaseline(path, s)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
