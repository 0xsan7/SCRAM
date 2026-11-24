package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/vuln"
)

func TestWhyUsesTargetEvidenceInMixedRepository(t *testing.T) {
	dir := t.TempDir()
	writeCLIFile(t, filepath.Join(dir, "package.json"), `{"dependencies":{"parent":"1.0.0"}}`)
	writeCLIFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/parent":{"version":"1.0.0"},"node_modules/parent/node_modules/child":{"version":"2.0.0"}}}`)
	writeCLIFile(t, filepath.Join(dir, "go.mod"), "module example.com/project\n")
	writeCLIFile(t, filepath.Join(dir, "go.sum"), "example.com/isolated v1.0.0 h1:eHl6\n")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Error(err)
		}
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Queries []json.RawMessage }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"results": make([]struct{}, len(req.Queries))}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	old := vuln.OSVBaseURL
	vuln.OSVBaseURL = server.URL
	t.Cleanup(func() { vuln.OSVBaseURL = old })
	for _, tc := range []struct {
		name              string
		direct, pathKnown bool
		text              string
	}{
		{"example.com/isolated", false, false, "How it got here: unknown"},
		{"child", false, true, "pkg:npm/parent@1.0.0"},
		{"parent", true, false, "direct dependency, declared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runCLI(t, "why", tc.name, "--no-cache", "--json")
			if err != nil {
				t.Fatal(err)
			}
			var doc whyDocument
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Direct != tc.direct || doc.PathKnown != tc.pathKnown {
				t.Errorf("unexpected JSON: %s", out)
			}
			out, err = runCLI(t, "why", tc.name, "--no-cache")
			if err != nil || !strings.Contains(out, tc.text) {
				t.Errorf("expected %q, got %s (%v)", tc.text, out, err)
			}
		})
	}
}
