package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/report"
	"github.com/0xsan7/scram/internal/vuln"
)

func auditCLIRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "package-lock.json"), `{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0","license":"MIT"}}}`)
	return root
}

func TestAuditExplicitConfigControlsDecision(t *testing.T) {
	root := auditCLIRepo(t)
	config := filepath.Join(t.TempDir(), "custom.yml")
	writeCLIFile(t, config, "version: 1\nlicenses:\n  deny: [MIT]\n")
	_, err := runCLI(t, "scan", root, "--sbom-only", "--no-scorecard", "--no-trend", "--config", config)
	if !errors.Is(err, ErrPolicyFailed) {
		t.Fatalf("explicit config must deny MIT: %v", err)
	}
}

func TestAuditExplicitMissingConfigFails(t *testing.T) {
	root := auditCLIRepo(t)
	_, err := runCLI(t, "scan", root, "--sbom-only", "--no-scorecard", "--no-trend", "--config", filepath.Join(root, "missing.yml"))
	if err == nil {
		t.Fatal("explicitly missing policy was silently ignored")
	}
}

func TestAuditFailOnOverrideControlsDecision(t *testing.T) {
	root := auditCLIRepo(t)
	writeCLIFile(t, filepath.Join(root, ".scram.yml"), "version: 1\nfail_on: critical\nfail_on_existing: true\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/querybatch" {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-AUDIT"}]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"CVE-AUDIT","severity":[{"type":"CVSS_V3","score":"7.5"}]}`))
	}))
	defer server.Close()
	old := vuln.OSVBaseURL
	vuln.OSVBaseURL = server.URL
	defer func() { vuln.OSVBaseURL = old }()
	_, err := runCLI(t, "scan", root, "--no-cache", "--no-scorecard", "--no-trend", "--fail-on", "high")
	if !errors.Is(err, ErrPolicyFailed) {
		t.Fatalf("--fail-on high must override critical and fail: %v", err)
	}
}

func TestAuditJSONCarriesActualDecision(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "pass", true: "fail"}[deny], func(t *testing.T) {
			root := auditCLIRepo(t)
			if deny {
				writeCLIFile(t, filepath.Join(root, ".scram.yml"), "licenses:\n  deny: [MIT]\n")
			}
			out, err := runCLI(t, "scan", root, "--sbom-only", "--format", "json", "--no-scorecard", "--no-trend")
			if deny && !errors.Is(err, ErrPolicyFailed) {
				t.Fatal(err)
			}
			if !deny && err != nil {
				t.Fatal(err)
			}
			var doc report.JSONDocument
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Passed == deny {
				t.Fatalf("passed=%v, deny=%v", doc.Passed, deny)
			}
			if deny && len(doc.FailReasons) == 0 {
				t.Fatal("failing JSON omitted the decision reasons")
			}
		})
	}
}

func TestAuditSBOMWriteFailureIsAnError(t *testing.T) {
	root := auditCLIRepo(t)
	out := filepath.Join(root, "not-a-directory")
	writeCLIFile(t, out, "file")
	_, err := runCLI(t, "sbom", "generate", root, "--out", out)
	if err == nil {
		t.Fatal("requested SBOM failed to write but command succeeded")
	}
}

func TestAuditInvalidSBOMFormatFails(t *testing.T) {
	root := auditCLIRepo(t)
	_, err := runCLI(t, "sbom", "generate", root, "--format", "typo", "--out", t.TempDir())
	if err == nil {
		t.Fatal("unknown SBOM format silently generated zero files")
	}
}

func TestAuditReportPreservesDecision(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "report.json")
	writeCLIFile(t, input, `{"schema_version":"2.0.0","scan":{"components":[]},"passed":true}`)
	out, err := runCLI(t, "report", "--from", input, "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var doc report.JSONDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Passed {
		t.Fatal("report conversion changed pass into fail")
	}
}

func TestAuditSBOMMetadataUsesCLIVersion(t *testing.T) {
	root := auditCLIRepo(t)
	out := t.TempDir()
	old := Version
	Version = "v9.9.9-audit"
	defer func() { Version = old }()
	if _, err := runCLI(t, "sbom", "generate", root, "--format", "both", "--out", out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sbom.cdx.json", "sbom.spdx.json"} {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), Version) {
			t.Fatalf("%s did not identify generating binary %s", name, Version)
		}
	}
}

func TestAuditBaselineRefusesIncompleteVulnerabilityData(t *testing.T) {
	root := auditCLIRepo(t)
	out := filepath.Join(t.TempDir(), "baseline.json")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "outage", 503) }))
	defer s.Close()
	old := vuln.OSVBaseURL
	vuln.OSVBaseURL = s.URL
	defer func() { vuln.OSVBaseURL = old }()
	_, err := runCLI(t, "baseline", "update", root, "--no-cache", "--out", out)
	if err == nil {
		t.Fatal("incomplete vulnerability data was saved as a successful baseline")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("untrustworthy baseline was written: %v", err)
	}
}

func TestAuditPartialInventoryCannotPass(t *testing.T) {
	root := auditCLIRepo(t)
	writeCLIFile(t, filepath.Join(root, "requirements.txt"), "click==8.0.0\n")
	writeCLIFile(t, filepath.Join(root, "package-lock.json"), "{malformed")
	_, err := runCLI(t, "scan", root, "--sbom-only", "--no-scorecard", "--no-trend")
	if !errors.Is(err, ErrPolicyFailed) {
		t.Fatalf("partial inventory was reported as a passing scan: %v", err)
	}
	_, err = runCLI(t, "sbom", "generate", root, "--out", t.TempDir())
	if err == nil {
		t.Fatal("partial SBOM silently succeeded")
	}
}

func TestAuditDefaultBaselineBelongsToScannedRepo(t *testing.T) {
	root := auditCLIRepo(t)
	writeCLIFile(t, filepath.Join(root, ".scram", "baseline.json"), `{"schema_version":"2.0.0","components":[{"purl":"pkg:npm/a@0.9.0","name":"a","version":"0.9.0","ecosystem":"npm"}]}`)
	out, err := runCLI(t, "scan", root, "--sbom-only", "--format", "json", "--no-scorecard", "--no-trend")
	if err != nil {
		t.Fatal(err)
	}
	var doc report.JSONDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Drift == nil || len(doc.Drift.Drifts) != 1 || doc.Drift.Drifts[0].PreviousVersion != "0.9.0" {
		t.Fatalf("scan ignored its repo's baseline: %+v", doc.Drift)
	}
}

func TestAuditExplicitMissingBaselineFails(t *testing.T) {
	root := auditCLIRepo(t)
	_, err := runCLI(t, "scan", root, "--sbom-only", "--no-scorecard", "--no-trend", "--baseline", filepath.Join(root, "missing-baseline.json"))
	if err == nil {
		t.Fatal("explicitly requested baseline was silently ignored")
	}
}
