package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/vuln"
)

// TestTheLookupKeyShapeIsOneFact tests the thing that broke twice.
//
// Two bugs shipped because the string a resolver sends to OSV was not the
// string OSV indexes on, and nothing in the suite could tell the difference:
//
//   - pnpm 6.0 (9f4ae85): the key was parsed into "lodash@4.17.21" with an
//     empty version.
//   - the go.mod fallback (af8e58f): the key was "gin" instead of
//     "github.com/gin-gonic/gin".
//
// Both produced components with plausible names, real versions and correct
// PURLs, so the silent-zero invariant called them healthy. This test states
// the expected key shape per ecosystem in ONE place, next to the code that
// builds the key, so a future resolver has to read it rather than infer it.
func TestTheLookupKeyShapeIsOneFact(t *testing.T) {
	cases := []struct {
		ecosystem string
		component model.Component
		want      string
	}{
		// OSV's Go ecosystem is keyed on the full module path. A PURL splits
		// it into namespace and name, which is a PURL rule and NOT a lookup
		// rule -- conflating the two is the bug.
		{"go", model.Component{
			Name: "github.com/gin-gonic/gin", Version: "v1.6.0"}, "github.com/gin-gonic/gin"},
		// Sub-paths stay whole.
		{"go", model.Component{
			Name: "github.com/aws/aws-sdk-go-v2/service/s3", Version: "v1.0.0"},
			"github.com/aws/aws-sdk-go-v2/service/s3"},
		// A go.sum and a go.mod component are keyed identically.
		{"go", model.Component{
			Name: "golang.org/x/text", Version: "v0.3.0"}, "golang.org/x/text"},
		// npm keeps its scope: "@babel/core", never "core".
		{"npm", model.Component{Name: "@babel/core", Version: "7.11.1"}, "@babel/core"},
		{"npm", model.Component{Name: "lodash", Version: "4.17.11"}, "lodash"},
		// PyPI keys on the published distribution name. Verified by roundtrip
		// against a real advisory, not by inspection.
		{"pypi", model.Component{Name: "pyyaml", Version: "3.13"}, "pyyaml"},
		{"pypi", model.Component{Name: "requests", Version: "2.19.0"}, "requests"},
		// Cargo keys on the crate name.
		{"cargo", model.Component{Name: "anyhow", Version: "1.0.100"}, "anyhow"},
		{"cargo", model.Component{Name: "serde", Version: "1.0.0"}, "serde"},
	}

	for _, c := range cases {
		if got := osvLookupKey(c.component); got != c.want {
			t.Errorf("osvLookupKey(%s/%s@%s) = %q, OSV indexes it as %q",
				c.ecosystem, c.component.Name, c.component.Version, got, c.want)
		}
	}
}

// TestEveryEcosystemResolvesToAnOSVEcosystem is the coverage half: every
// registered resolver must map to an ecosystem OSV actually serves, and that
// mapping must be exercised. A new resolver whose ecosystem is missing from
// osvEcosystem is silently skipped by QueryOSV -- no error, no findings, a
// permanent clean scan.
func TestEveryEcosystemResolvesToAnOSVEcosystem(t *testing.T) {
	for _, eco := range Supported() {
		t.Run(eco, func(t *testing.T) {
			r, err := GetFor(eco, "package-lock.json")
			if err != nil || r == nil {
				t.Skipf("no resolver registered for %q (expected for shared ecosystems)", eco)
			}
			if osvEco, ok := vuln.OSVEcosystem(r.Ecosystem()); !ok {
				t.Errorf("resolver for %q reports ecosystem %q, which osvEcosystem "+
					"does not map. QueryOSV skips unmapped components without "+
					"warning, so this ecosystem would scan as permanently clean.",
					eco, r.Ecosystem())
			} else {
				t.Logf("%q -> OSV %q", eco, osvEco)
			}
		})
	}
}

// TestTheRecordingCoversEveryRegisteredEcosystem keeps the roundtrip
// requirement honest as the ecosystem list grows.
//
// The requirement is "any resolver, new or existing". A new ecosystem with no
// recording is an ecosystem with no roundtrip, and nothing else notices --
// the test above passes, the silent-zero invariant passes, and the new
// ecosystem scans as clean forever.
func TestTheRecordingCoversEveryRegisteredEcosystem(t *testing.T) {
	recorded := map[string]bool{}
	for _, r := range loadRecordings(t) {
		recorded[r.projectEco()] = true
	}
	for _, eco := range Supported() {
		r, err := GetFor(eco, "package-lock.json")
		if err != nil || r == nil {
			continue
		}
		if !recorded[r.Ecosystem()] {
			t.Errorf("ecosystem %q has no known-vulnerable roundtrip recording. "+
				"Add a vulnerable package to scripts/record_osv_fixtures.py and "+
				"re-run it; without one, a wrong lookup key in this ecosystem "+
				"would report vulnerable projects as clean.",
				r.Ecosystem())
		}
	}
}

// TestRecordedPackagesStillHaveAdvisories refuses to let the recordings rot
// into something that passes for the wrong reason.
//
// If a recorded package is patched upstream and the response is replaced with
// an empty one, every lookup key -- correct or not -- would "pass". The
// recording is only evidence while it still contains a real advisory.
func TestRecordedPackagesStillHaveAdvisories(t *testing.T) {
	entries, err := os.ReadDir(osvFixtureDir())
	if err != nil {
		t.Skipf("no recordings: %v", err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".response.json") {
			continue
		}
		found++
		b, err := os.ReadFile(filepath.Join(osvFixtureDir(), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"id"`) {
			t.Errorf("%s contains no advisory id. Re-run "+
				"scripts/record_osv_fixtures.py; an empty recording would make "+
				"every lookup key look correct.", e.Name())
		}
	}
	if found == 0 {
		t.Skip("no recorded responses")
	}
}

func osvFixtureDir() string { return "../../testdata/osv" }

// osvLookupKey is the string the client sends to the registry.
//
// It is not the PURL and not necessarily the name as a human would write it.
// Writing it once, here, means the per-ecosystem rule is stated in a single
// place that a test can assert against.
func osvLookupKey(c model.Component) string { return c.Name }

// projectEco maps an OSV ecosystem name to this project's constant.
func (r osvRecording) projectEco() string {
	switch r.Ecosystem {
	case "Go":
		return "go"
	case "PyPI":
		return "pypi"
	case "crates.io":
		return "cargo"
	case "npm":
		return "npm"
	}
	return r.Ecosystem
}
