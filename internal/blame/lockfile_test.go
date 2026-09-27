package blame

import "testing"

// These cover the parsing layer, which is where a wrong answer would be
// silently plausible. A blame feature that reports the wrong commit is worse
// than no feature: it looks authoritative.

func TestVersionFromNpmPackagesPicksShallowest(t *testing.T) {
	// The realistic case: two versions of qs, one nested. A reader asking
	// "what version do I have" means the top-level one.
	lock := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name":"app"},
	    "node_modules/qs": {"version":"6.11.0"},
	    "node_modules/express": {"version":"4.18.2"},
	    "node_modules/express/node_modules/qs": {"version":"6.5.2"}
	  }
	}`)
	v, ok := versionFromNpmPackages(lock, "qs")
	if !ok || v != "6.11.0" {
		t.Errorf("got %q ok=%v, want 6.11.0", v, ok)
	}
}

func TestVersionFromNpmPackagesScopedName(t *testing.T) {
	lock := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "node_modules/@babel/core": {"version":"7.24.0"}
	  }
	}`)
	v, ok := versionFromNpmPackages(lock, "@babel/core")
	if !ok || v != "7.24.0" {
		t.Errorf("scoped name: got %q ok=%v", v, ok)
	}
	// A bare "core" must NOT match the scoped package.
	if _, ok := versionFromNpmPackages(lock, "core"); ok {
		t.Error("unscoped fragment matched a scoped package")
	}
}

func TestVersionFromNpmPackagesAbsent(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1"}}}`)
	if v, ok := versionFromNpmPackages(lock, "ghost"); ok {
		t.Errorf("reported %q for a package that is not in the lockfile", v)
	}
}

func TestVersionFromNpmV1Nested(t *testing.T) {
	lock := []byte(`{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "express": {"version":"4.18.2","dependencies":{"qs":{"version":"6.5.2"}}},
	    "lodash": {"version":"4.17.11"}
	  }
	}`)
	if v, ok := versionFromNpmV1(lock, "qs"); !ok || v != "6.5.2" {
		t.Errorf("nested v1: got %q ok=%v", v, ok)
	}
	if v, ok := versionFromNpmV1(lock, "lodash"); !ok || v != "4.17.11" {
		t.Errorf("top-level v1: got %q ok=%v", v, ok)
	}
}

func TestVersionFromRequirements(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"pyyaml==5.1", "5.1", true},
		{"pyyaml>=5.1", "5.1", true},
		{"pyyaml ~= 5.1", "5.1", true},
		{"pyyaml[foo]==5.1", "5.1", true},
		{"pyyaml==5.1  # pinned for CVE-2020-14343", "5.1", true},
		{"pyyaml==5.1 ; python_version < '3.9'", "5.1", true},
		{"pyyaml", "", true},
		{"# pyyaml==5.1", "", false},
		{"pyyaml==5.1 \\", "", false},
		{"other==1.0", "", false},
	}
	for _, c := range cases {
		v, ok := versionFromRequirements([]byte(c.line), "pyyaml")
		if ok != c.ok || (ok && v != c.want) {
			t.Errorf("requirements %q -> %q ok=%v; want %q ok=%v", c.line, v, ok, c.want, c.ok)
		}
	}
}

// A lockfile that is valid as BOTH npm shapes must be read the way the
// scanner reads it, or blame and scan would disagree about the version.
func TestVersionInLockfilePrefersStructuredFormat(t *testing.T) {
	both := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {"node_modules/lodash": {"version":"4.17.21"}},
	  "dependencies": {"lodash": {"version":"4.17.11"}}
	}`)
	v, ok := versionInLockfile(both, "lodash")
	if !ok || v != "4.17.21" {
		t.Errorf("got %q ok=%v, want 4.17.21 (the structured form)", v, ok)
	}
}
