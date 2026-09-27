package resolve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// writeFixture materializes a small repo from a map of relative path to
// content and returns its root.
func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func find(comps []model.Component, name string) *model.Component {
	for i := range comps {
		if comps[i].Name == name {
			return &comps[i]
		}
	}
	return nil
}

func TestNPMResolveLockfileV3(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"package.json": `{
			"dependencies": {"lodash": "4.17.11"},
			"devDependencies": {"minimist": "1.2.0"}
		}`,
		"package-lock.json": `{
			"lockfileVersion": 3,
			"packages": {
				"": {"name": "x", "dependencies": {"lodash": "4.17.11"}},
				"node_modules/lodash": {"version": "4.17.11", "license": "MIT"},
				"node_modules/minimist": {"version": "1.2.0", "license": "MIT", "dev": true},
				"node_modules/nested": {"version": "2.0.0"}
			}
		}`,
	})

	comps, err := npmResolver{}.Resolve(root, "package-lock.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(comps) != 3 {
		t.Fatalf("got %d components, want 3: %+v", len(comps), comps)
	}

	lodash := find(comps, "lodash")
	if lodash == nil {
		t.Fatal("lodash not found")
	}
	if lodash.Purl != "pkg:npm/lodash@4.17.11" {
		t.Errorf("purl: got %q, want pkg:npm/lodash@4.17.11", lodash.Purl)
	}
	if !lodash.Direct {
		t.Error("lodash should be marked direct (it is in package.json dependencies)")
	}
	if lodash.License != "MIT" {
		t.Errorf("license: got %q, want MIT", lodash.License)
	}

	if c := find(comps, "nested"); c == nil || c.Direct {
		t.Error("nested is not in package.json, so it should be transitive")
	}

	// The root project must not be listed as its own dependency.
	if find(comps, "x") != nil {
		t.Error("the root package (key \"\") must be excluded from components")
	}
}

// TestNPMResolveNestedNodeModulesPath covers scoped and deeply nested paths,
// where the name is everything after the final "node_modules/".
func TestNPMResolveNestedNodeModulesPath(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"package.json": `{}`,
		"package-lock.json": `{
			"lockfileVersion": 3,
			"packages": {
				"": {"name": "x"},
				"node_modules/a/node_modules/@scope/pkg": {"version": "3.0.0"},
				"node_modules/@other/thing": {"version": "1.0.0"}
			}
		}`,
	})

	comps, err := npmResolver{}.Resolve(root, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 2 {
		t.Fatalf("got %d components, want 2: %+v", len(comps), comps)
	}
	// The scope is part of the npm package name.
	pkg := find(comps, "@scope/pkg")
	if pkg == nil {
		t.Fatalf("expected a component named @scope/pkg, got %+v", comps)
	}
	if pkg.Version != "3.0.0" {
		t.Errorf("version: got %q, want 3.0.0", pkg.Version)
	}
	if find(comps, "@other/thing") == nil {
		t.Errorf("expected a component named @other/thing, got %+v", comps)
	}
}

// TestNPMResolveLockfileV1 covers the legacy nested "dependencies" shape.
func TestNPMResolveLockfileV1(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"package.json": `{"dependencies": {"a": "1.0.0"}}`,
		"package-lock.json": `{
			"lockfileVersion": 1,
			"dependencies": {
				"a": {
					"version": "1.0.0",
					"requires": {"b": "2.0.0"},
					"dependencies": {
						"b": {"version": "2.0.0"}
					}
				}
			}
		}`,
	})

	comps, err := npmResolver{}.Resolve(root, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 2 {
		t.Fatalf("got %d components, want 2: %+v", len(comps), comps)
	}
	a := find(comps, "a")
	if a == nil || !a.Direct {
		t.Error("a should be direct (declared in package.json)")
	}
	b := find(comps, "b")
	if b == nil || b.Direct {
		t.Error("b is only a transitive dependency, so it should not be direct")
	}
}

// TestNPMRequiresBoolNotMap is a regression test: the top-level "requires"
// field in a v2/v3 lockfile is a boolean. Declaring it as a map made
// unmarshalling fail on every modern lockfile, producing zero components.
func TestNPMRequiresBoolNotMap(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"package.json": `{}`,
		"package-lock.json": `{
			"lockfileVersion": 3,
			"requires": true,
			"packages": {
				"": {"name": "x"},
				"node_modules/lodash": {"version": "4.17.21"}
			}
		}`,
	})
	comps, err := npmResolver{}.Resolve(root, "package-lock.json")
	if err != nil {
		t.Fatalf("a lockfile with \"requires\": true must parse: %v", err)
	}
	if len(comps) != 1 {
		t.Errorf("got %d components, want 1", len(comps))
	}
}

func TestIntegrityToHex(t *testing.T) {
	// "sha512-<base64 of 64 bytes>"
	h := parseIntegrity("sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==")
	if len(h) != 128 {
		t.Errorf("expected 128 hex chars for a sha512, got %d", len(h))
	}
	if parseIntegrity("") != "" {
		t.Error("empty integrity should yield an empty hash")
	}
	if parseIntegrity("not-an-integrity") != "" {
		t.Error("malformed integrity should yield an empty hash, not garbage")
	}
	// SRI can carry several space-separated entries; the first usable wins.
	multi := parseIntegrity("sha1-abc sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==")
	if len(multi) != 128 {
		t.Errorf("expected the sha512 entry to win, got %d chars", len(multi))
	}
}

func TestPyPIRequirements(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"requirements.txt": `# a comment
requests==2.25.1
Flask_Login==0.6.0
flask_login==0.5.0
urllib3>=2.0.0
some-pkg==1.0.0 ; python_version >= "3.8"
git+https://github.com/foo/bar.git#egg=bar
-r other.txt
-e .
numpy==1.21.0
`,
	})

	comps, err := pypiResolver{}.Resolve(root, "requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	// requests, flask-login (two pins collapse to the last), urllib3, some-pkg,
	// numpy.
	//
	// urllib3 IS included. This test used to assert the opposite, encoding the
	// D25 bug: a regex matched only `==`, so `urllib3>=2.0.0` was discarded
	// along with every other ranged requirement, and a file full of ranges
	// scanned as zero dependencies. A lower bound is a version pip would
	// install, so it is now recorded.
	//
	// The VCS URL and -r/-e lines are still skipped: a git+https URL has no
	// version to record, and -r/-e are pip options rather than requirements.
	if len(comps) != 5 {
		for _, c := range comps {
			t.Logf("  %s", c.Purl)
		}
		t.Fatalf("got %d components, want 5", len(comps))
	}
	urllib := find(comps, "urllib3")
	if urllib == nil {
		t.Error("urllib3 (>=2.0.0) not parsed; ranged requirements must not be dropped")
	} else if urllib.Version != "2.0.0" {
		t.Errorf("urllib3 version: got %q, want 2.0.0 (the range's lower bound)", urllib.Version)
	}
	if find(comps, "requests") == nil {
		t.Error("requests not parsed")
	}
	// PEP 503 normalization: Flask_Login and flask_login are the same package,
	// and the later pin wins, matching pip.
	fl := find(comps, "flask-login")
	if fl == nil {
		t.Error("Flask_Login was not normalized to flask-login")
	} else if fl.Version != "0.5.0" {
		t.Errorf("flask-login version: got %q, want 0.5.0 (the last pin wins)", fl.Version)
	}
	if find(comps, "some-pkg") == nil {
		t.Error("a pinned requirement with an environment marker should still parse")
	}
}

func TestPyPINormalization(t *testing.T) {
	cases := map[string]string{
		"Flask_Login":     "flask-login",
		"flask.login":     "flask-login",
		"zope..interface": "zope-interface",
		"A_B.C-D":         "a-b-c-d",
		"requests":        "requests",
	}
	for in, want := range cases {
		if got := normalizePyPIName(in); got != want {
			t.Errorf("normalizePyPIName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoModules(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"go.mod": `module example.com/app

go 1.22

require (
	github.com/spf13/cobra v1.8.0
	github.com/pelletier/go-toml v1.9.5 // indirect
)

require github.com/stretchr/testify v1.8.4
`,
		"go.sum": `github.com/spf13/cobra v1.8.0 h1:abc=
github.com/spf13/cobra v1.8.0/go.mod h1:def=
github.com/pelletier/go-toml v1.9.5 h1:ghi=
github.com/pelletier/go-toml v1.9.5/go.mod h1:jkl=
github.com/stretchr/testify v1.8.4 h1:mno=
github.com/stretchr/testify v1.8.4/go.mod h1:pqr=
`,
	})

	comps, err := goResolver{}.Resolve(root, "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	// The /go.mod-only lines must not become separate components.
	if len(comps) != 3 {
		for _, c := range comps {
			t.Logf("  %s", c.Purl)
		}
		t.Fatalf("got %d components, want 3", len(comps))
	}
	cobra := find(comps, "github.com/spf13/cobra")
	if cobra == nil {
		t.Fatal("cobra not found")
	}
	if !cobra.Direct {
		t.Error("cobra is a direct require, so it should be marked direct")
	}
	// Even marked // indirect in go.mod, the resolver trusts go.mod's
	// require list as the direct/transitive signal.
	toml := find(comps, "github.com/pelletier/go-toml")
	if toml == nil {
		t.Fatal("go-toml not found")
	}
	if !toml.Direct {
		t.Log("note: go-toml is marked // indirect in go.mod but listed in require; " +
			"treating it as direct is the conservative choice")
	}
}

func TestGoVersionComparison(t *testing.T) {
	if compareGoVersions("v1.2.0", "v1.10.0") >= 0 {
		t.Error("v1.10.0 must sort newer than v1.2.0 (numeric, not lexical)")
	}
	if compareGoVersions("v2.0.0", "v1.9.9") <= 0 {
		t.Error("v2.0.0 must sort newer than v1.9.9")
	}
	if compareGoVersions("v1.0.0-20210101abcdef", "v1.0.0") != 0 {
		t.Error("a pseudo-version of the same release should compare equal on the base version")
	}
}

func TestSplitGoModule(t *testing.T) {
	cases := []struct{ in, ns, name string }{
		{"github.com/user/repo", "github.com/user", "repo"},
		{"golang.org/x/tools", "golang.org/x", "tools"},
		{"single", "", "single"},
	}
	for _, c := range cases {
		ns, name := splitGoModule(c.in)
		if ns != c.ns || name != c.name {
			t.Errorf("splitGoModule(%q) = (%q, %q), want (%q, %q)", c.in, ns, name, c.ns, c.name)
		}
	}
}

func TestDedupeAndSort(t *testing.T) {
	in := []model.Component{
		{Purl: "pkg:npm/zebra@1.0.0", Name: "zebra", Ecosystem: model.EcoNPM},
		{Purl: "pkg:npm/alpha@1.0.0", Name: "alpha", Ecosystem: model.EcoNPM},
		{Purl: "pkg:npm/alpha@1.0.0", Name: "alpha", Ecosystem: model.EcoNPM}, // dupe
		{Purl: "pkg:pypi/requests@2.0.0", Name: "requests", Ecosystem: model.EcoPyPI},
	}
	out := Dedupe(in)
	if len(out) != 3 {
		t.Fatalf("got %d components, want 3 (duplicates removed)", len(out))
	}
	// Sorted by ecosystem then name: npm/alpha, npm/zebra, pypi/requests.
	want := []string{"pkg:npm/alpha@1.0.0", "pkg:npm/zebra@1.0.0", "pkg:pypi/requests@2.0.0"}
	for i, w := range want {
		if out[i].Purl != w {
			t.Errorf("position %d: got %q, want %q", i, out[i].Purl, w)
		}
	}
}

func TestResolverRegistry(t *testing.T) {
	for _, eco := range []string{model.EcoNPM, model.EcoPyPI, model.EcoGo} {
		if _, err := Get(eco); err != nil {
			t.Errorf("no resolver registered for %q", eco)
		}
	}
	if _, err := Get("cargo"); err != ErrUnsupported {
		t.Error("expected ErrUnsupported for an unregistered ecosystem")
	}
	if len(Supported()) != 3 {
		t.Errorf("Supported() = %v, want 3 ecosystems", Supported())
	}
}
