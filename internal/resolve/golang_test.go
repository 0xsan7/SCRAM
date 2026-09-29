package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPlausibleGoModule pins the rule that decides whether a require
// directive names a module at all.
//
// The rule is stated in plausibleGoModule. What is worth recording here is
// the first, wrong version of it, which passed every hand-written case and
// still broke a real project: it required the FINAL path segment to
// contain a dot, because "example.com/pkg" looks like a module path. Real
// paths are host/path/..., so the dot is in the host:
//
//	github.com/Azure/azure-sdk-for-go/sdk/azcore
//	          ^ dot here
//
// The rule rejected 467 of aquasecurity/trivy's 472 requirements, and the
// go.mod fallback reported 5 components for a project with several hundred
// dependencies. Every case below with a dotted final segment would have
// passed against the broken rule; the ones that catch it are the ones whose
// last segment has no dot.
func TestPlausibleGoModule(t *testing.T) {
	accepted := []string{
		// The shape that broke the original rule: dotted host, undotted
		// final segment. This is the majority of real Go module paths.
		"github.com/Azure/azure-sdk-for-go/sdk/azcore",
		"github.com/BurntSushi/toml",
		"github.com/Masterminds/sprig/v3",
		"github.com/go-chi/chi/v5",
		// Dotted host with a dotted final segment too.
		"github.com/anchore/oss-docs",
		"golang.org/x/net",
		"k8s.io/api",
		"gopkg.in/yaml.v3",
	}
	for _, m := range accepted {
		if !plausibleGoModule(m) {
			t.Errorf("plausibleGoModule(%q) = false; this is a real module path", m)
		}
	}

	rejected := []struct {
		why string
		m   string
	}{
		{"a version, not a host", "0.0"},
		{"a version, not a host", "1.2"},
		{"leading dot", ".com"},
		{"bare host with no name", "github.com"},
		{"empty trailing segment", "github.com/"},
		{"empty leading segment", "/a/b"},
		{"empty middle segment", "github.com//b"},
		{"empty", ""},
	}
	for _, c := range rejected {
		if plausibleGoModule(c.m) {
			t.Errorf("plausibleGoModule(%q) = true; %s", c.m, c.why)
		}
	}
}

// TestGoModFallbackIsNotASilentZero is the end-to-end version, on a real
// go.mod from a real project, with no go.sum present.
//
// "No go.sum" used to mean "no dependencies" and produce a clean scan of a
// project that has several hundred. That is the silent false clean this
// project treats as unrecoverable, so the case is pinned on a fixture large
// enough that a regression cannot hide: 400 components from trivy, and the
// count is asserted, not assumed.
func TestGoModFallbackIsNotASilentZero(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures",
		"gomod", "real", "aquasecurity", "trivy", "go.mod"))
	if err != nil {
		t.Skipf("trivy go.mod fixture absent: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	// Guard the test itself: if a go.sum were written, the resolver would
	// read that instead and this would be testing the wrong branch.
	if _, err := os.Stat(filepath.Join(dir, "go.sum")); err == nil {
		t.Fatal("test setup is wrong: a go.sum is present")
	}

	comps, err := goResolver{}.Resolve(dir, "go.mod")
	if err != nil {
		t.Fatalf("go.mod fallback returned an error: %v", err)
	}
	if len(comps) < 400 {
		t.Fatalf("go.mod fallback recovered %d components from trivy's go.mod; "+
			"it declares several hundred, so this is a parser regression", len(comps))
	}
	// Component.Name is the last path segment, as it is everywhere else in
	// the tool, so the plausibility check has to be applied to the full
	// module path. Rebuild it from the namespace and the name rather than
	// pretending Name holds the whole thing.
	for _, c := range comps {
		full := strings.TrimPrefix(
			strings.TrimPrefix(c.Purl, "pkg:golang/"), "@")
		full = strings.SplitN(full, "@", 2)[0]
		if !plausibleGoModule(full) {
			t.Errorf("fallback emitted a component with an implausible module path: %q", full)
		}
		if c.Version == "" {
			t.Errorf("fallback emitted %q with no version", c.Name)
		}
	}
}

// TestGoModFallbackSkipsCommentsAndDirectives is the negative half: a go.mod
// full of non-requirement lines must not turn those lines into
// dependencies. `go 1.24`, `toolchain`, `replace` and `exclude` are
// directives, not dependencies, and a scanner that reports them is
// reporting a project that depends on its own Go version.
func TestGoModFallbackSkipsCommentsAndDirectives(t *testing.T) {
	src := `module github.com/example/project

// require github.com/not/a/dependency v1.0.0

go 1.24

toolchain go1.24.0

require (
	github.com/real/one v1.2.3
	github.com/real/two v0.4.5 // indirect
	github.com/real/three v2.0.0
)

exclude github.com/bad/pkg v1.0.0

replace github.com/real/one => ../local
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	comps, err := goResolver{}.Resolve(dir, "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 {
		var names []string
		for _, c := range comps {
			names = append(names, c.Name)
		}
		t.Fatalf("got %d components %v, want 3 (the three requires)", len(comps), names)
	}
	want := map[string]bool{
		"pkg:golang/github.com/real/one@v1.2.3":   true,
		"pkg:golang/github.com/real/two@v0.4.5":   true,
		"pkg:golang/github.com/real/three@v2.0.0": true,
	}
	for _, c := range comps {
		if !want[c.Purl] {
			t.Errorf("unexpected component %s; a directive or comment was read as a dependency", c.Purl)
		}
	}
}
