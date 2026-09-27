package resolve

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestNPMPackagesMapKeyOrder documents how duplicate installs are represented.
//
// A tree CAN install two copies of one package at different depths. Dedupe
// keys on the full PURL, so both survive as distinct components -- correctly,
// because both versions really are present on disk and both must be
// vulnerability-matched. Collapsing them here would silently drop a
// vulnerable copy. internal/graph is where the nesting is modelled, via the
// install path.
//
// This test exists to pin that decision, because "which copy is in effect" is
// exactly the kind of assumption that silently rots.
func TestNPMPackagesMapKeyOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"root","dependencies":{"dup":"^1.0.0"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"name":"root","lockfileVersion":3,"requires":true,
		"packages":{
			"": {"name":"root","dependencies":{"dup":"^1.0.0"}},
			"node_modules/dup": {"version":"1.2.0"},
			"node_modules/other/node_modules/dup": {"version":"1.0.0"}
		}
	}`)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	deduped := Dedupe(comps)
	versions := map[string]bool{}
	for _, c := range deduped {
		if c.Name == "dup" {
			versions[c.Version] = true
		}
	}
	// Both copies are reported; neither is dropped.
	if !versions["1.2.0"] || !versions["1.0.0"] {
		t.Errorf("expected both 1.2.0 and 1.0.0 to survive dedupe, got %v", versions)
	}
	// And they are distinct PURLs, so vulnerability matching covers each.
	purls := map[string]bool{}
	for _, c := range deduped {
		if c.Name == "dup" {
			purls[c.Purl] = true
		}
	}
	if len(purls) != 2 {
		t.Errorf("expected 2 distinct PURLs for the two copies, got %d", len(purls))
	}
}

// TestNPMScopedNameInBothLockfileShapes covers the same package expressed the
// v1 way and the v3 way, because a v2 lockfile carries both and the resolver
// must not emit it twice under two spellings.
func TestNPMScopedNameInBothLockfileShapes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"root","dependencies":{"@scope/pkg":"^1.0.0"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"name":"root","lockfileVersion":2,"requires":true,
		"dependencies": {"@scope/pkg": {"version":"1.4.0","integrity":"sha512-x","license":"MIT"}},
		"packages": {
			"": {"name":"root","dependencies":{"@scope/pkg":"^1.0.0"}},
			"node_modules/@scope/pkg": {"version":"1.4.0","integrity":"sha512-x","license":"MIT"}
		}
	}`)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) == 0 {
		t.Fatal("scoped package not resolved from a v2 lockfile")
	}
	for _, c := range comps {
		if c.Name != "@scope/pkg" {
			t.Errorf("unexpected name %q", c.Name)
		}
		// packageurl-go percent-encodes both "@" and "/" in the namespace,
		// which is the canonical PURL form: pkg:npm/%40scope%2Fpkg@version.
		if c.Purl != "pkg:npm/%40scope%2Fpkg@1.4.0" {
			t.Errorf("scoped PURL = %q, want pkg:npm/%%40scope%%2Fpkg@1.4.0", c.Purl)
		}
	}
}

// TestNPMEmptyLockfileIsExplicit guards the "a lockfile that resolves to
// nothing" case that the policy engine treats as a possible empty-lockfile
// protection. The resolver must distinguish an empty tree from a missing
// file, and must not silently return zero for a file it could not read.
func TestNPMEmptyLockfileIsExplicit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"empty"}`)
	empty := `{"name":"empty","lockfileVersion":3,"requires":true,"packages":{}}`
	writeFile(t, filepath.Join(dir, "package-lock.json"), empty)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatalf("an empty but valid lockfile is not an error: %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("got %d components, want 0", len(comps))
	}

	// A lockfile that is not valid JSON at all must be an error, never a
	// silent zero that reads as "no dependencies".
	bad := t.TempDir()
	writeFile(t, filepath.Join(bad, "package-lock.json"), `{ this is not json `)
	if _, err := (npmResolver{}).Resolve(bad, "package-lock.json"); err == nil {
		t.Error("malformed lockfile returned no error; that reads as CLEAN")
	}
}

// TestRealLockfileLicenseShapes documents the license shapes the corpus found
// in the wild, so a future change to flexString cannot silently narrow it.
func TestRealLockfileLicenseShapes(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`"MIT"`, "MIT"},
		{`["MIT","Apache2"]`, "MIT OR Apache2"},
		{`["ISC"]`, "ISC"},
		{`null`, ""},
		{`[]`, ""},
		{`""`, ""},
		// Order is preserved so the expression is stable across runs.
		{`["Apache-2.0","MIT"]`, "Apache-2.0 OR MIT"},
	}
	for _, c := range cases {
		var f flexString
		if err := f.UnmarshalJSON([]byte(c.raw)); err != nil {
			t.Errorf("Unmarshal(%s): %v", c.raw, err)
			continue
		}
		if f.String() != c.want {
			t.Errorf("Unmarshal(%s) = %q, want %q", c.raw, f.String(), c.want)
		}
	}
}

// TestLicenseRoundTripsAsString ensures flexString does not turn a plain
// string into a one-element array on re-encode.
func TestLicenseRoundTripsAsString(t *testing.T) {
	var f flexString
	if err := f.UnmarshalJSON([]byte(`"MIT"`)); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"MIT"` {
		t.Errorf("re-encoded as %s, want \"MIT\"", b)
	}
}
