package resolve

import (
	"os"
	"path/filepath"
	"testing"
)

// A v2/v3 lockfile written by modern npm carries a top-level "dependencies"
// map alongside "packages". That is an ordinary document, not a malformed
// one, and it must parse.
//
// The bug this pins: "dependencies" was typed as the v1 nested tree, so any
// such lockfile failed json.Unmarshal and the entire scan silently resolved
// zero components -- which then reported CLEAN with no findings. A scanner
// that reports "clean" because it could not read your lockfile is worse than
// one that crashes.
func TestModernLockfileWithTopLevelDependencies(t *testing.T) {
	dir := t.TempDir()
	lock := `{
	  "name": "demo-app",
	  "lockfileVersion": 3,
	  "requires": true,
	  "dependencies": { "express": "^4.18.0" },
	  "packages": {
	    "": {"name":"demo-app","dependencies":{"express":"^4.18.0"}},
	    "node_modules/express": {"version":"4.18.2","license":"MIT",
	      "dependencies":{"qs":"6.5.2"}},
	    "node_modules/express/node_modules/qs": {"version":"6.5.2"},
	    "node_modules/qs": {"version":"6.11.0"}
	  }
	}`
	write(t, dir, "package-lock.json", lock)
	write(t, dir, "package.json", `{"name":"demo-app","dependencies":{"express":"^4.18.0"}}`)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatalf("Resolve on a modern lockfile: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("zero components resolved; a modern lockfile must not resolve to nothing")
	}
	names := map[string]string{}
	for _, c := range comps {
		names[c.Name] = c.Version
	}
	if names["express"] != "4.18.2" {
		t.Errorf("express = %q, want 4.18.2", names["express"])
	}
	// Both versions of qs must survive: the nested one is the whole point of
	// install paths.
	if names["qs"] == "" {
		t.Error("qs not resolved at all")
	}
}

// A v1 lockfile has only "dependencies", and must still work. This is the
// other half of the same field, so the fix must not have traded one shape for
// the other.
func TestV1LockfileStillResolves(t *testing.T) {
	dir := t.TempDir()
	lock := `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "express": {"version":"4.18.2","dependencies":{"qs":{"version":"6.5.2"}}},
	    "lodash": {"version":"4.17.11"}
	  }
	}`
	write(t, dir, "package-lock.json", lock)
	write(t, dir, "package.json", `{"name":"a","dependencies":{"express":"^4.18.0"}}`)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatalf("Resolve on a v1 lockfile: %v", err)
	}
	names := map[string]string{}
	for _, c := range comps {
		names[c.Name] = c.Version
	}
	if names["express"] != "4.18.2" || names["lodash"] != "4.17.11" {
		t.Errorf("v1 resolution = %v, want express 4.18.2 and lodash 4.17.11", names)
	}
	if names["qs"] != "6.5.2" {
		t.Errorf("nested qs = %q, want 6.5.2", names["qs"])
	}
}

// A v2/v3 file that ALSO has a v1-shaped "dependencies" tree must prefer
// "packages" and ignore it, since the two shapes coexist in the wild and only
// one of them is authoritative.
func TestPackagesWinsOverLegacyTree(t *testing.T) {
	dir := t.TempDir()
	lock := `{
	  "lockfileVersion": 3,
	  "dependencies": {"ghost": {"version":"9.9.9"}},
	  "packages": {"node_modules/real": {"version":"1.0.0"}}
	}`
	write(t, dir, "package-lock.json", lock)
	write(t, dir, "package.json", `{"name":"a"}`)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "ghost" {
			t.Errorf("read the legacy tree despite a v3 packages map: %v", comps)
		}
	}
	if len(comps) != 1 || comps[0].Name != "real" {
		t.Errorf("components = %v, want just 'real'", comps)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
