package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActionAdvisoryModePreservesVerdict(t *testing.T) {
	scan, _ := reviewScripts(t)
	for _, tc := range []struct {
		name, enforce, verdict, scannerExit string
		status                              int
		exposesVerdict                      bool
	}{
		{"blocking", "true", "false", "1", 1, true},
		{"advisory", "false", "false", "1", 0, true},
		{"passed", "false", "true", "0", 0, true},
		{"scanner failure", "false", "false", "2", 2, false},
		{"bad report", "false", "null", "1", 2, false},
		{"mismatched verdict", "false", "true", "1", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := "#!/usr/bin/env bash\nprintf '{\"passed\":%s}\\n' \"$VERDICT\"\nexit \"$SCANNER_EXIT\"\n"
			if err := os.WriteFile(filepath.Join(dir, "scram"), []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "outputs")
			if err := os.WriteFile(output, nil, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", scan)
			cmd.Env = append(os.Environ(), "RUNNER_TEMP="+dir, "GITHUB_OUTPUT="+output, "OUT_DIR="+dir,
				"CONFIG_PATH=", "FAIL_ON=high", "SBOM_FORMATS=cyclonedx", "ENABLE_EPSS=false", "BASE_JSON=",
				"ENFORCE="+tc.enforce, "VERDICT="+tc.verdict, "SCANNER_EXIT="+tc.scannerExit)
			log, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.status {
				t.Fatalf("expected exit %d, got %v: %s", tc.status, err, log)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			want := "policy-passed=" + tc.verdict + "\n"
			if strings.Contains(string(data), want) != tc.exposesVerdict ||
				strings.Contains(string(data), "report-path=") != tc.exposesVerdict {
				t.Fatalf("unexpected action outputs %q", data)
			}
		})
	}
}

func TestActionCommentUsesComponentDriftAndCoverage(t *testing.T) {
	_, comment := reviewScripts(t)
	// Render the actual comment body locally, stopping before GitHub API calls.
	body, _, ok := strings.Cut(comment, "# FR-604:")
	if !ok {
		t.Fatal("comment rendering boundary not found")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	const report = `{"passed":false,"scan":{"summary":{"repo_score":12,"repo_bucket":"low","total_components":2,"counts_by_bucket":{}},"osv_coverage":{"checked":1,"partial":1,"unchecked":0},"warnings":["incomplete"],"components":[{"purl":"pkg:npm/existing@1","vulnerabilities":[{"id":"TEST-ID"}]}]},"drift":{"summary":{"new_vuln_ids":["TEST-ID"],"new_high_count":1,"new_critical_count":0},"drifts":[{"purl":"pkg:npm/new@1","new_vulnerabilities":["TEST-ID"]},{"purl":"pkg:npm/existing@1","new_vulnerabilities":[]}]}}`
	if err := os.WriteFile(path, []byte(report), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", body)
	cmd.Env = append(os.Environ(), "RUNNER_TEMP="+dir, "SCAN_JSON="+path, "COMMENT_MARKER=<!-- scram-report -->", "ENFORCE=false")
	if log, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("comment render failed: %v %s", err, log)
	}
	data, err := os.ReadFile(filepath.Join(dir, "comment.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| Policy | Failed |", "| Enforcement | Advisory |", "1 checked, 1 partial, 0 unchecked", "pkg:npm/new@1"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %q in comment:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), "pkg:npm/existing@1") {
		t.Fatal("existing advisory listed as new on an unchanged component")
	}
}

func reviewScripts(t *testing.T) (scan, comment string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Action shell replay requires Unix paths")
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s required for Action shell replay", tool)
		}
	}
	data, err := os.ReadFile("../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct{ ID, Name, Run string }
		}
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	for _, step := range action.Runs.Steps {
		switch {
		case step.ID == "scram":
			scan = strings.ReplaceAll(step.Run, "${{ runner.os == 'Windows' && '.exe' || '' }}", "")
		case step.Name == "Comment on PR":
			comment = step.Run
		}
	}
	if scan == "" || comment == "" {
		t.Fatal("scan or comment missing from Action")
	}
	return scan, comment
}
