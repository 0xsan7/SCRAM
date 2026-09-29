package resolve

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// This file enforces the invariant that D01, D22, and D23 each violated:
// a resolver must never return zero components for a file that declares
// dependencies.
//
// All three bugs had the same shape. A parse step silently failed, the
// resolver returned an empty slice, and the scan reported CLEAN with exit 0.
// From the outside, a security tool that cannot read your lockfile is
// indistinguishable from a secure project.
//
// The property: for every lockfile in the corpus, if the file declares
// dependencies then ResolveFile returns either components or an error. Never
// (empty, nil).
//
// The ecosystem list is `Supported()` rather than a literal. An earlier
// version of this test iterated a hardcoded []string{"npm", "pypi", "gomod"},
// which meant a newly added resolver was exempt from the invariant purely
// by not being written down -- the same class of bug as the ones this file
// exists to catch, one level up. Deriving the list from the registry makes
// coverage a property of the code rather than of someone's memory.

// TestInvariantNoSilentZeroOverCorpus is the whole-corpus property check. It
// deliberately uses ResolveFile rather than Resolve, so it also proves the
// guard is wired up: if the guard regressed, this fails rather than quietly
// passing on empty results.
func TestInvariantNoSilentZeroOverCorpus(t *testing.T) {
	checked, empty := 0, 0
	for _, eco := range Supported() {
		files := corpusFiles(t, filepath.Join(corpusSubdir(eco), "real"), isAnyLockfile)
		if len(files) == 0 {
			t.Logf("%s corpus absent; run scripts/fetch_corpus.py %s", eco, eco)
			continue
		}
		for _, f := range files {
			name := relName(t, f)
			ecoName := ecosystemFor(f)
			// GetFor because an ecosystem can have several resolvers and
			// the filename decides which one applies.
			r, err := GetFor(ecoName, filepath.Base(f))
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			declared := declaredDependencies(f)

			comps, err := ResolveFile(r, filepath.Dir(f), filepath.Base(f))
			checked++

			if err != nil {
				if !errors.Is(err, ErrSilentZero) {
					// A real parse error is fine; the corpus may contain a
					// format this build does not support yet.
					t.Logf("%s: parse error (not a silent zero): %v", name, err)
					continue
				}
				t.Errorf("SILENT ZERO: %s: %v", name, err)
				continue
			}

			if len(comps) == 0 {
				if declared > 0 {
					t.Errorf("SILENT ZERO: %s: declared %d dependencies, returned 0, no error",
						name, declared)
					continue
				}
				empty++
				continue
			}
			// Sanity: a non-empty result must carry usable identity, or it is
			// not much better than an empty one.
			for _, c := range comps {
				if c.Purl == "" || c.Name == "" {
					t.Errorf("%s: component missing identity: %+v", name, c)
					break
				}
			}
		}
	}
	if checked == 0 {
		t.Skip("no corpus present; nothing to assert")
	}
	t.Logf("invariant held for %d lockfiles (%d genuinely empty)", checked, empty)
}

// TestResolveFileRejectsSilentZero builds the D23 shape directly: a
// requirements file full of ranged requirements, and a resolver that drops
// every one of them, which is exactly what the ==-only regex did.
func TestResolveFileRejectsSilentZero(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "requirements.txt")
	// 22 ranged dependencies, no exact pins: prefect's real shape.
	var b strings.Builder
	for _, n := range []string{"click", "dask", "flask", "requests", "urllib3", "boto3"} {
		b.WriteString(n + " >= 1.0\n")
	}
	if err := os.WriteFile(lock, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	// A deliberately broken resolver: reads the file, returns nothing, no error.
	// Note the absolute path -- ResolveFile's guard re-reads the file to count
	// declarations, and it resolves `path` relative to `root`, so a bare
	// filename would make the counter see nothing and quietly disable the
	// very guard this test exists to prove.
	broken := fakeResolver{eco: "pypi", count: 0}
	_, err := ResolveFile(broken, dir, lock)
	if err == nil {
		t.Fatal("ResolveFile accepted a silent zero; the invariant is not enforced")
	}
	if !errors.Is(err, ErrSilentZero) {
		t.Fatalf("got %v, want ErrSilentZero", err)
	}
	var e *EmptyDependencyCountError
	if !errors.As(err, &e) {
		t.Fatalf("error is not an *EmptyDependencyCountError: %T", err)
	}
	if e.Declared != 6 {
		t.Errorf("Declared = %d, want 6", e.Declared)
	}
	if !strings.Contains(e.Error(), "false negative") {
		t.Errorf("error message should explain the consequence, got: %s", e)
	}
}

// TestResolveFileAllowsGenuinelyEmpty is the other half: the guard must not
// fire on a lockfile that really has no dependencies, or every monorepo with
// an empty lockfile becomes an error.
func TestResolveFileAllowsGenuinelyEmpty(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	// ceph's real lockfile, 83 bytes, "packages": {}.
	if err := os.WriteFile(lock, []byte(
		`{"name":"ceph","lockfileVersion":3,"requires":true,"packages":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	comps, err := ResolveFile(npmResolver{}, dir, "package-lock.json")
	if err != nil {
		t.Fatalf("an empty lockfile is a true observation, not a bug: %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("got %d components, want 0", len(comps))
	}
}

// TestResolveFilePassesThroughRealErrors confirms the guard does not swallow
// genuine parse failures, which must still surface as errors.
func TestResolveFilePassesThroughRealErrors(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lock, []byte(`{ not json at all`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveFile(npmResolver{}, dir, "package-lock.json")
	if err == nil {
		t.Fatal("malformed JSON returned no error; that reads as CLEAN")
	}
	if errors.Is(err, ErrSilentZero) {
		t.Error("a parse error was misreported as a silent zero")
	}
}

// TestDeclaredDependenciesCountsIndependently checks the counter that drives
// the invariant. It must not use any resolver, or a resolver bug could hide
// itself by making the counter agree with it.
func TestDeclaredDependenciesCountsIndependently(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		want int
	}{
		{"npm v3", "package-lock.json", `{"packages":{"":{"name":"x"},
			"node_modules/a":{"version":"1"},"node_modules/b":{"version":"2"}}}`, 2},
		{"npm v2 both maps", "package-lock.json", `{"packages":{"":{"name":"x"},
			"node_modules/a":{"version":"1"}},"dependencies":{"a":{"version":"1"}}}`, 1},
		{"npm empty", "package-lock.json", `{"packages":{}}`, 0},
		{"go.sum", "go.sum", "a b v1.0 h1:x\na b/v1/go.mod h1:y\nc d v2 h1:z\n", 3},
		{"go.sum with comment", "go.sum", "// indirect\n", 0},
		{"requirements ranged", "requirements.txt", "# c\nflask>=1\nrequests\n-r other\n", 2},
		{"requirements all comment", "requirements.txt", "# just\n# comments\n", 0},
		{"poetry.lock", "poetry.lock", "[[package]]\nname = \"a\"\n[[package]]\nname = \"b\"\n", 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, c.file)
			if err := os.WriteFile(p, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := declaredDependencies(p); got != c.want {
				t.Errorf("declaredDependencies = %d, want %d", got, c.want)
			}
		})
	}
}

func TestDeclaredDependenciesMissingFile(t *testing.T) {
	// Must not panic, and must not claim a count for a file it never read.
	if got := declaredDependencies(filepath.Join(t.TempDir(), "nope.json")); got != 0 {
		t.Errorf("got %d for a missing file, want 0", got)
	}
}

// fakeResolver lets the test supply a resolver that misbehaves on purpose,
// which is the only way to exercise the guard without first breaking the
// product.
type fakeResolver struct {
	eco   string
	count int
}

func (f fakeResolver) Ecosystem() string { return f.eco }

func (f fakeResolver) Resolve(root, path string) ([]model.Component, error) {
	out := make([]model.Component, f.count)
	for i := range out {
		out[i] = model.Component{Purl: "pkg:npm/x@1", Name: "x", Version: "1"}
	}
	return out, nil
}

// corpusSubdir maps an ecosystem to the directory its fixtures live in.
// They are not the same string: the Go ecosystem is "go" but its corpus
// lives in "gomod", matching the layout scripts/fetch_corpus.py writes.
func corpusSubdir(eco string) string {
	if eco == "go" {
		return "gomod"
	}
	return eco
}

// isAnyLockfile recognises lockfile NAMES without hardcoding a list. It
// asks the registry which resolvers claim which filenames, so a new
// ecosystem's lockfile is picked up by the invariant automatically.
func isAnyLockfile(name string) bool {
	for eco := range registry {
		for _, r := range registry[eco] {
			if h, ok := r.(FileMatcher); ok && h.Handles(name) {
				return true
			}
		}
	}
	// Formats with no FileMatcher (a resolver that handles a whole
	// ecosystem) still have conventional names; keep the known ones so an
	// existing corpus is not silently skipped.
	switch name {
	case "package-lock.json", "go.sum", "poetry.lock", "requirements.txt":
		return true
	}
	return false
}

// ecosystemFor decides which ecosystem a corpus file belongs to, by asking
// the registry rather than by pattern-matching the name.
func ecosystemFor(path string) string {
	base := filepath.Base(path)
	// Collect every ecosystem whose resolver claims this filename. In
	// practice exactly one does; the loop exists so a future resolver that
	// overlaps is resolved by explicit preference rather than by map
	// iteration order, which would make the corpus result non-reproducible.
	var claims []string
	for eco, rs := range registry {
		for _, r := range rs {
			if h, ok := r.(FileMatcher); ok && h.Handles(base) {
				claims = append(claims, eco)
				break
			}
		}
	}
	sort.Strings(claims)
	switch len(claims) {
	case 0:
		// No resolver claims it. The fallback keeps a pre-existing corpus
		// visible rather than silently skipping it.
		switch base {
		case "go.sum":
			return "go"
		case "package-lock.json":
			return "npm"
		default:
			return "pypi"
		}
	case 1:
		return claims[0]
	default:
		// Ambiguous. Prefer the ecosystem that shares the filename's
		// stem, then fall back to the sort order above.
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		for _, eco := range claims {
			if eco == stem {
				return eco
			}
		}
		return claims[0]
	}
}

// TestInvariantCatchesAResolverThatDropsEverything is the meta-test. The
// whole-corpus check above is only worth something if it actually fails when
// a resolver is broken -- and the previous version of that check iterated a
// hardcoded ecosystem list, so it went quiet on a new one instead of
// failing. This asserts the plumbing is live: register a resolver for a real
// corpus ecosystem, make it return nothing, and confirm the invariant's own
// helpers still route that ecosystem's files to it.
func TestInvariantCatchesAResolverThatDropsEverything(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	// Real npm v3 shape with two packages: a resolver that drops these is
	// the D01 bug.
	if err := os.WriteFile(lock, []byte(
		`{"lockfileVersion":3,"packages":{"":{"name":"x"},`+
			`"node_modules/a":{"version":"1.0.0"},"node_modules/b":{"version":"2.0.0"}}}`),
		0o644); err != nil {
		t.Fatal(err)
	}

	// Route the file through the registry, exactly as the corpus loop does.
	ecoName := ecosystemFor(lock)
	if ecoName != "npm" {
		t.Fatalf("ecosystemFor(%s) = %q, want npm -- the invariant would "+
			"silently skip this file if the routing is wrong", filepath.Base(lock), ecoName)
	}
	if !isAnyLockfile(filepath.Base(lock)) {
		t.Fatal("isAnyLockfile does not recognise a real npm lockfile name")
	}
	r, err := GetFor(ecoName, filepath.Base(lock))
	if err != nil {
		t.Fatalf("GetFor: %v", err)
	}
	// A resolver that reads the file and returns nothing, with no error.
	// Absolute path on purpose: the guard re-reads the file to count
	// declarations and resolves `path` against `root`, so a bare filename
	// would make the counter see nothing and quietly disable the guard.
	if _, err := ResolveFile(fakeResolver{eco: ecoName, count: 0}, dir, lock); err == nil {
		t.Fatal("a resolver returning zero for a two-package lockfile was accepted")
	}
	// And the real resolver still passes on the same file.
	// `path` is resolved relative to `root`, so it must be the bare
	// filename here, not the absolute path.
	comps, err := ResolveFile(r, dir, filepath.Base(lock))
	if err != nil {
		t.Fatalf("real npm resolver: %v", err)
	}
	if len(comps) != 2 {
		t.Errorf("npm resolver returned %d components, want 2", len(comps))
	}
}
