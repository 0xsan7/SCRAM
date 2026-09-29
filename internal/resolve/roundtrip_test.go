package resolve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/vuln"
)

// osvRecording is one recorded OSV query plus its real response.
//
// The responses are REAL: fetched from https://api.osv.dev on 2026-09-30 for
// packages that genuinely have open advisories. No advisory ID here is
// invented, and none is hand-written. Replaying them is what lets the
// known-vulnerable roundtrip run in CI without depending on the network.
type osvRecording struct {
	Ecosystem string   `json:"eco"`
	Name      string   `json:"name"`
	Version   string   `json:"ver"`
	Count     int      `json:"count"`
	IDs       []string `json:"ids"`
	File      string   `json:"file"`
}

// fileBase is the recording's own filename stem, used to find its response.
func (r osvRecording) fileBase() string {
	if r.File != "" {
		return r.File
	}
	switch r.Ecosystem {
	case "Go":
		return "go"
	case "PyPI":
		return "pypi"
	case "crates.io":
		return "cargo"
	}
	return r.Ecosystem
}

// TestKnownVulnerableRoundtripOffline is the standing requirement from
// CONTRIBUTING.md, applied to every ecosystem OSV indexes.
//
// THE REQUIREMENT. Any resolver or vulnerability matcher, new or existing, must
// be validated with a known-vulnerable roundtrip: take a real package from the
// real corpus that has a known, currently-valid advisory, and assert the
// matcher actually returns it.
//
// WHY A CORRECT-LOOKING PURL IS NOT ENOUGH. Two shipped bugs had perfect
// PURLs, plausible names, real versions, and green CI:
//
//   - pnpm 6.0 (9f4ae85). The key schema changed at 6.0, not 9.0, and 6.0 is
//     slash-PREFIXED but @-delimited. Read as a 5.x file, the name came out as
//     "lodash@4.17.21" with an empty version and the component was dropped:
//     361 components instead of 1523, with no error raised.
//
//   - The go.mod fallback (af8e58f). Name was set to the bare last path
//     segment while the OSV client queries by Name and OSV keys its Go
//     ecosystem on the module PATH. "github.com/gin-gonic/gin" was looked up
//     as "gin", matched nothing anywhere, and the scan reported CLEAN with a
//     correct PURL.
//
// The silent-zero invariant caught neither and could not: it verifies that
// RESOLUTION produced components, not that MATCHING found what a
// known-vulnerable package should yield. A component with a good name, a real
// version and a correct PURL is precisely what that invariant calls healthy.
// Both bugs lived in the layer the invariant does not observe.
//
// This test asserts what the invariant cannot. It runs the PRODUCTION lookup
// path, and the stub server returns advisories only for the key the real
// registry uses -- so a wrong key produces the same empty result the bug
// produced, and is now caught.
func TestKnownVulnerableRoundtripOffline(t *testing.T) {
	recs := loadRecordings(t)
	if len(recs) == 0 {
		t.Skip("no OSV recordings; run scripts/record_osv_fixtures.py")
	}

	for _, r := range recs {
		t.Run(r.Ecosystem, func(t *testing.T) {
			if r.Count == 0 {
				t.Fatalf("the recorded response for %s/%s@%s has no advisories; "+
					"re-record it against a package that is still vulnerable",
					r.Ecosystem, r.Name, r.Version)
			}

			comp := componentForRecording(t, r)

			var sawQuery probeQuery
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				// The batch endpoint is what the client calls first; the
				// stub answers the exact query it was sent, so a wrong
				// lookup key cannot be papered over by a permissive fake.
				if strings.Contains(req.URL.Path, "querybatch") {
					var body probeBatchRequest
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					if len(body.Queries) == 0 {
						http.Error(w, "empty batch", http.StatusBadRequest)
						return
					}
					sawQuery = body.Queries[0]
					if sawQuery.Package.Name != r.Name || sawQuery.Package.Ecosystem != r.Ecosystem {
						// What the real registry does with an unknown key:
						// it answers correctly, with nothing.
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{
							"results": []map[string]any{{"vulns": []any{}}},
						})
						return
					}
					writeRecordedBatch(w, t, r)
					return
				}
				// Hydration of the ids returned above: the real
				// recorded records, not a stub.
				writeRecordedVulns(w, t, r)
			}))
			defer srv.Close()

			restore := vuln.OSVBaseURL
			vuln.OSVBaseURL = srv.URL
			defer func() { vuln.OSVBaseURL = restore }()

			c := vuln.NewClient(nil)
			c.UseEPSS = false
			comps := []model.Component{comp}
			if err := c.QueryOSV(context.Background(), comps); err != nil {
				t.Fatalf("QueryOSV: %v", err)
			}

			if sawQuery.Package.Name == "" {
				t.Fatal("the client never sent a query")
			}
			if sawQuery.Package.Name != r.Name {
				t.Fatalf("lookup key is wrong: the matcher queried %q/%q but OSV's %s "+
					"ecosystem is keyed on %s. Every advisory for this package is "+
					"invisible, so a vulnerable project scans as clean.",
					sawQuery.Package.Ecosystem, sawQuery.Package.Name,
					r.Ecosystem, osvKeyShape(r.Ecosystem))
			}
			if sawQuery.Package.Ecosystem != r.Ecosystem {
				t.Fatalf("ecosystem mismatch: sent %q, OSV expects %q",
					sawQuery.Package.Ecosystem, r.Ecosystem)
			}

			got := comps[0].Vulnerabilities
			if len(got) == 0 {
				t.Fatalf("ZERO advisories for %s/%s@%s, which has %d open advisories. "+
					"The lookup key is wrong, so a vulnerable package reads as clean.",
					r.Ecosystem, r.Name, r.Version, r.Count)
			}
			found := map[string]bool{}
			for _, v := range got {
				found[v.ID] = true
			}
			for _, want := range r.IDs {
				if !found[want] {
					t.Errorf("advisory %s missing for %s/%s@%s; got %d of %d",
						want, r.Ecosystem, r.Name, r.Version, len(got), r.Count)
				}
			}
			t.Logf("%s/%s@%s -> %d advisories recorded, %d returned",
				r.Ecosystem, r.Name, r.Version, r.Count, len(got))
		})
	}
}

// componentForRecording produces the component a real resolver emits for a
// known-vulnerable package.
//
// For Go the component is built by the PRODUCTION go.mod resolver, because
// choosing the lookup key is the resolver's job and that is the thing that was
// broken. For the others the project's ecosystem name is the registry name
// verbatim -- but the test still asserts it through the real query path, so
// "PyPI uses the bare distribution name" is verified rather than assumed.
func componentForRecording(t *testing.T, r osvRecording) model.Component {
	t.Helper()

	if r.Ecosystem == "Go" {
		dir := t.TempDir()
		// A go.mod require directive carries a leading "v" on the version.
		// The recording stores the OSV-facing version without it, because
		// that is what OSV keys on; the resolver's input is the go.mod form.
		ver := r.Version
		if !strings.HasPrefix(ver, "v") {
			ver = "v" + ver
		}
		mod := "module example.com/probe\n\ngo 1.21\n\nrequire " + r.Name + " " + ver + "\n"
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := GetFor("go", "go.mod")
		if err != nil {
			t.Fatal(err)
		}
		comps, err := ResolveFile(res, dir, "go.mod")
		if err != nil {
			t.Fatal(err)
		}
		if len(comps) != 1 {
			t.Fatalf("expected 1 component from the go.mod resolver, got %d", len(comps))
		}
		return comps[0]
	}

	eco := map[string]string{"npm": "npm", "PyPI": "pypi", "crates.io": "cargo"}[r.Ecosystem]
	if eco == "" {
		t.Fatalf("no project ecosystem for OSV ecosystem %q", r.Ecosystem)
	}
	ns, name := splitProbeName(eco, r.Name)
	return model.Component{
		Name:      r.Name,
		Version:   r.Version,
		Ecosystem: eco,
		Purl:      "pkg:" + eco + "/" + ns + name + "@" + r.Version,
	}
}

func splitProbeName(eco, name string) (string, string) {
	if eco == "npm" && strings.HasPrefix(name, "@") {
		i := strings.Index(name, "/")
		if i > 0 {
			return name[:i] + "%2F", name[i+1:]
		}
	}
	return "", name
}

// osvKeyShape documents, per OSV ecosystem, what the registry actually keys
// on. A lookup key has to agree with this or it matches nothing.
func osvKeyShape(eco string) string {
	switch eco {
	case "Go":
		return "the full module path, e.g. github.com/gin-gonic/gin"
	case "npm":
		return "the package name including its @scope"
	case "PyPI":
		return "the distribution name as published, e.g. PyYAML"
	case "crates.io":
		return "the crate name"
	}
	return "the package name"
}

func loadRecordings(t *testing.T) []osvRecording {
	t.Helper()
	dir := "../../testdata/osv"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []osvRecording
	for _, e := range entries {
		if e.IsDir() || e.Name() == "index.json" {
			continue
		}
		// <eco>.json is the index; <eco>.response.json holds the real
		// recorded response and is read separately.
		if !strings.HasSuffix(e.Name(), ".json") ||
			strings.HasSuffix(e.Name(), ".response.json") {
			continue
		}
		// The recorded RESPONSE lives in a sibling file so the test can
		// replay real advisory content rather than a hand-built stub.
		rec := osvRecording{}
		idx, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(idx, &rec); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if rec.Name == "" {
			t.Fatalf("%s is not a recording", e.Name())
		}
		out = append(out, rec)
	}
	return out
}

// writeRecordedBatch answers the batch endpoint from the REAL recorded
// response, so the advisory ids the client receives are ids OSV actually
// returned for this package.
func writeRecordedBatch(w http.ResponseWriter, t *testing.T, r osvRecording) {
	t.Helper()
	body := loadRecordedResponse(t, r)
	vulns, _ := body["vulns"].([]any)
	ids := make([]map[string]any, 0, len(vulns))
	for _, v := range vulns {
		if m, ok := v.(map[string]any); ok {
			ids = append(ids, map[string]any{"id": m["id"]})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"results": []map[string]any{{"vulns": ids}},
	})
}

// writeRecordedVulns answers the hydration endpoint with the real records.
func writeRecordedVulns(w http.ResponseWriter, t *testing.T, r osvRecording) {
	t.Helper()
	body := loadRecordedResponse(t, r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func loadRecordedResponse(t *testing.T, r osvRecording) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata/osv", r.fileBase()+".response.json"))
	if err != nil {
		t.Fatalf("read recorded response: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("recorded response: %v", err)
	}
	return body
}

// Mirror types for the batch request the OSV client sends. The client's own
// types are unexported, and re-declaring them here keeps the assertion
// honest: if the client changes the wire shape, decoding fails loudly rather
// than the stub quietly matching nothing.
type probeBatchRequest struct {
	Queries []probeQuery `json:"queries"`
}

type probeQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}
