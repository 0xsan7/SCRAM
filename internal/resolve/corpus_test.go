package resolve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file covers the real-world lockfile corpus. See D01 and D22 in
// DECISIONS.md: hand-authored fixtures inherit their author's blind spots, so
// every resolver needs lockfiles nobody on this project wrote by hand.
//
// The corpus is fetched reproducibly by scripts/fetch-corpus.sh. These tests
// assert the properties that must hold for ANY real lockfile, rather than
// pinning exact counts, which would make them fail on every upstream release.

const corpusDir = "../../testdata/fixtures"

func corpusFiles(t *testing.T, sub string, match func(string) bool) []string {
	t.Helper()
	root := filepath.Join(corpusDir, sub)
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !match(filepath.Base(p)) {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

func isNpmLockfile(name string) bool { return name == "package-lock.json" }
func isGoSum(name string) bool       { return name == "go.sum" }
func isPyLock(name string) bool {
	return name == "poetry.lock" || name == "requirements.txt"
}

// TestNPMCorpusResolvesNonEmpty is the property that D01 violated: a real,
// large lockfile must never parse to zero components. Zero used to mean
// "clean" on the terminal, which is a false all-clear.
func TestNPMCorpusResolvesNonEmpty(t *testing.T) {
	files := corpusFiles(t, filepath.Join("npm", "real"), isNpmLockfile)
	if len(files) == 0 {
		t.Skip("no npm corpus present; run scripts/fetch_corpus.sh npm")
	}
	for _, f := range files {
		t.Run(relName(t, f), func(t *testing.T) {
			comps, err := npmResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			// A few real projects genuinely commit an EMPTY lockfile. ceph's
			// is 83 bytes with "packages": {} -- a monorepo whose JS is
			// built elsewhere. Resolving zero components from it is correct,
			// so the property to assert is "did we read the document", not
			// "did we find packages". The distinction matters: a lockfile
			// that fails to parse also yields zero, and that is the D01 bug.
			if !lockfileIsEmpty(t, f) && len(comps) == 0 {
				t.Fatal("resolved to ZERO components from a non-empty real lockfile — " +
					"this is the D01 failure mode")
			}
			if lockfileIsEmpty(t, f) && len(comps) != 0 {
				t.Errorf("lockfile declares no packages but resolver returned %d", len(comps))
			}
			for _, c := range comps {
				if c.Purl == "" {
					t.Errorf("component %q has no PURL", c.Name)
				}
				if c.Name == "" {
					t.Errorf("component with version %q has no name", c.Version)
				}
				if c.Version == "" {
					t.Errorf("component %q has no version", c.Name)
				}
			}
		})
	}
}

// lockfileIsEmpty reports whether an npm lockfile on disk declares any
// packages. It parses the file independently of the resolver, so "empty" and
// "unparseable" are never conflated.
func lockfileIsEmpty(t *testing.T, path string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc struct {
		Packages     map[string]json.RawMessage `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s is not valid JSON, so the corpus itself is corrupt: %v", path, err)
	}
	return len(doc.Packages) == 0 && len(doc.Dependencies) == 0
}

// TestNPMCorpusComponentsAreWellFormed checks invariants that hold across
// every real lockfile, and which a hand-written fixture would never stumble
// into because the author controls the shape.
func TestNPMCorpusComponentsAreWellFormed(t *testing.T) {
	files := corpusFiles(t, filepath.Join("npm", "real"), isNpmLockfile)
	if len(files) == 0 {
		t.Skip("no npm corpus present")
	}
	for _, f := range files {
		t.Run(relName(t, f), func(t *testing.T) {
			comps, err := npmResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
			if err != nil {
				t.Fatal(err)
			}
			// Duplicate PURLs are EXPECTED here: npm installs the same package
			// at several paths when a tree has version conflicts
			// (node_modules/a/node_modules/semver alongside node_modules/semver).
			// resolve.Dedupe collapses them before scoring, so the resolver's
			// job is to report what is installed, not to pre-collapse. What
			// must hold is that every component is well-formed, first
			// occurrence or not.
			checked := map[string]bool{}
			for _, c := range comps {
				if c.Purl == "" {
					t.Errorf("component %q has no PURL", c.Name)
				}
				// A scoped npm package keeps its scope in the name.
				if len(c.Name) > 0 && c.Name[0] == '@' && !containsSlash(c.Name) {
					t.Errorf("scoped name %q has no scope/name split", c.Name)
				}
				if c.License == " OR " {
					t.Error("license parsed to a bare OR expression")
				}
				// Assert each distinct PURL's shape once, not per duplicate.
				if !checked[c.Purl] {
					checked[c.Purl] = true
					if !strings.HasPrefix(c.Purl, "pkg:npm/") {
						t.Errorf("PURL %q is not a well-formed npm purl", c.Purl)
					}
				}
			}
		})
	}
}

// TestNPMCorpusDualLicenseIsPreserved is the regression test for the bug this
// corpus found: `pause-stream` in nestjs/nest carries
// "license": ["MIT", "Apache2"], an ARRAY. Declaring the field as a string
// made json.Unmarshal fail on the whole document, so a 1676-package project
// scanned as zero components.
func TestNPMCorpusDualLicenseIsPreserved(t *testing.T) {
	files := corpusFiles(t, filepath.Join("npm", "real"), isNpmLockfile)
	if len(files) == 0 {
		t.Skip("no npm corpus present")
	}
	found := false
	for _, f := range files {
		comps, err := npmResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range comps {
			// Only the corpus copy that actually carries the array. The same
			// package can appear in several repos with different metadata, so
			// the assertion has to be conditional rather than global.
			if c.Name == "pause-stream" && c.License != "" {
				found = true
				if c.License != "MIT OR Apache2" {
					t.Errorf("%s: pause-stream license = %q, want %q",
						relName(t, f), c.License, "MIT OR Apache2")
				}
			}
		}
	}
	if !found {
		t.Skip("no array-licensed pause-stream in the current corpus; the shape is " +
			"covered directly by TestFlexStringArrayLicense")
	}
}

// TestFlexStringArrayLicense exercises the array-license shape directly, so
// the guarantee does not depend on one upstream package staying installed.
func TestFlexStringArrayLicense(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"x","dependencies":{"dual":"1.0.0"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"name": "x", "lockfileVersion": 3, "requires": true,
		"packages": {
			"": {"name":"x","dependencies":{"dual":"1.0.0"}},
			"node_modules/dual": {"version":"1.0.0","license":["MIT","Apache2"]}
		}
	}`)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatalf("an array-valued license must not fail the whole parse: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components, want 1", len(comps))
	}
	if comps[0].License != "MIT OR Apache2" {
		t.Errorf("license: got %q, want %q", comps[0].License, "MIT OR Apache2")
	}
}

func TestFlexStringNullAndEmpty(t *testing.T) {
	for _, raw := range []string{`null`, `""`, `[]`} {
		var f flexString
		if err := f.UnmarshalJSON([]byte(raw)); err != nil {
			t.Errorf("Unmarshal(%s): %v", raw, err)
		}
		if f.String() == " OR " {
			t.Errorf("Unmarshal(%s) produced a bare OR expression", raw)
		}
	}
	// A single-element array is just the string.
	var f flexString
	if err := f.UnmarshalJSON([]byte(`["MIT"]`)); err != nil {
		t.Fatal(err)
	}
	if f.String() != "MIT" {
		t.Errorf("got %q, want MIT", f.String())
	}
}

// TestNPMCorpusModernTopLevelDependencies is the D01 regression, kept as a
// direct test so it does not depend on the corpus being present.
func TestNPMCorpusModernTopLevelDependencies(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"x","dependencies":{"lodash":"4.17.21"}}`)
	// The exact shape that broke: v3 packages map AND a top-level
	// "dependencies" map of name -> version string.
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"name": "x", "lockfileVersion": 3, "requires": true,
		"dependencies": {"lodash": "4.17.21"},
		"packages": {
			"": {"name":"x","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},
			"node_modules/lodash": {"version":"4.17.21","resolved":"https://r/lodash-4.17.21.tgz","integrity":"sha512-abc","license":"MIT"}
		}
	}`)

	comps, err := npmResolver{}.Resolve(dir, "package-lock.json")
	if err != nil {
		t.Fatalf("D01 regression: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components, want 1", len(comps))
	}
	if comps[0].Name != "lodash" || comps[0].Version != "4.17.21" {
		t.Errorf("got %s@%s, want lodash@4.17.21", comps[0].Name, comps[0].Version)
	}
	if !comps[0].Direct {
		t.Error("lodash is in package.json dependencies, so it should be direct")
	}
}

// TestGoCorpusResolvesNonEmpty applies the same non-empty guarantee to Go.
func TestGoCorpusResolvesNonEmpty(t *testing.T) {
	files := corpusFiles(t, filepath.Join("gomod", "real"), isGoSum)
	if len(files) == 0 {
		t.Skip("no go corpus present; run scripts/fetch-corpus.sh go")
	}
	for _, f := range files {
		t.Run(relName(t, f), func(t *testing.T) {
			comps, err := goResolver{}.Resolve(filepath.Dir(f), "go.sum")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if len(comps) == 0 {
				t.Fatal("resolved to ZERO components from a real go.sum")
			}
			for _, c := range comps {
				if c.Version == "" {
					t.Errorf("module %q has no version", c.Name)
				}
				if c.Purl == "" {
					t.Errorf("module %q has no PURL", c.Name)
				}
			}
		})
	}
}

// TestPyPICorpusResolvesNonEmpty applies it to PyPI.
func TestPyPICorpusResolvesNonEmpty(t *testing.T) {
	files := corpusFiles(t, filepath.Join("pypi", "real"), isPyLock)
	if len(files) == 0 {
		t.Skip("no pypi corpus present; run scripts/fetch_corpus.py pypi")
	}
	for _, f := range files {
		t.Run(relName(t, f), func(t *testing.T) {
			comps, err := pypiResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			// Same distinction as the npm test: a requirements file can be
			// entirely comments (ansible's is), which correctly yields zero,
			// while a file that FAILED to parse also yields zero, which is
			// the D25 bug. Assert on "did we read it", not "did we find
			// packages".
			if !pyFileHasRequirements(t, f) && len(comps) == 0 {
				return // genuinely no requirements in the file
			}
			if pyFileHasRequirements(t, f) && len(comps) == 0 {
				t.Fatal("resolved to ZERO components from a requirements file " +
					"that declares dependencies — this is the D25 failure mode")
			}
			for _, c := range comps {
				if c.Purl == "" {
					t.Errorf("package %q has no PURL", c.Name)
				}
			}
		})
	}
}

// pyFileHasRequirements reports whether a requirements file contains at least
// one non-comment, non-option, non-VCS line.
func pyFileHasRequirements(t *testing.T, path string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if strings.Contains(line, "://") {
			continue
		}
		return true
	}
	return false
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func relName(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.Rel(corpusDir, p)
	if err != nil {
		return filepath.Base(p)
	}
	return r
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}
