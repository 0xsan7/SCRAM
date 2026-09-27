package resolve

import (
	"errors"
	"os"
	"path/filepath"
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

// TestInvariantNoSilentZeroOverCorpus is the whole-corpus property check. It
// deliberately uses ResolveFile rather than Resolve, so it also proves the
// guard is wired up: if the guard regressed, this fails rather than quietly
// passing on empty results.
func TestInvariantNoSilentZeroOverCorpus(t *testing.T) {
	checked, empty := 0, 0
	for _, eco := range []string{"npm", "pypi", "gomod"} {
		files := corpusFiles(t, filepath.Join(eco, "real"), isAnyLockfile)
		if len(files) == 0 {
			t.Logf("%s corpus absent; run scripts/fetch_corpus.py %s", eco, eco)
			continue
		}
		for _, f := range files {
			name := relName(t, f)
			ecoName := ecosystemFor(f)
			// GetFor because PyPI has two resolvers and the filename decides.
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

func isAnyLockfile(name string) bool {
	return name == "package-lock.json" || name == "go.sum" ||
		name == "poetry.lock" || strings.HasPrefix(name, "requirements")
}

func ecosystemFor(path string) string {
	base := filepath.Base(path)
	switch {
	case base == "package-lock.json":
		return "npm"
	case base == "go.sum":
		return "go"
	default:
		return "pypi"
	}
}
