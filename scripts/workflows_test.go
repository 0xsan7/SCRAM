package scripts

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// The self-check used to require schedule/dispatch events in a workflow
// that declared neither. Read the real workflows so that regression fails.
func TestVulnerabilityCheckHasScheduledAndManualTriggers(t *testing.T) {
	paths, err := filepath.Glob("../.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			On   map[string]yaml.Node `yaml:"on"`
			Jobs map[string]struct {
				If string `yaml:"if"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		job, ok := workflow.Jobs["govulncheck"]
		if !ok {
			continue
		}
		found++
		if schedule, ok := workflow.On["schedule"]; !ok || len(schedule.Content) == 0 {
			t.Errorf("%s: govulncheck has no schedule trigger", path)
		}
		if _, ok := workflow.On["workflow_dispatch"]; !ok {
			t.Errorf("%s: govulncheck has no manual trigger", path)
		}
		if job.If != "" {
			t.Errorf("%s: govulncheck must run for every event its dedicated workflow declares", path)
		}
	}
	if found != 1 {
		t.Errorf("found %d govulncheck jobs; want one dedicated self-check", found)
	}
}
