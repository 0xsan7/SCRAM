package resolve

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// D27: SCRAM could not read pyproject.toml at all, so the large population of
// modern Python projects that ship no lockfile and no requirements.txt
// (click, starlette, fastapi, pydantic, httpx) scanned as having no Python
// dependencies. That is the silent-zero shape D01/D22/D23 each had, and it was
// found by running the section-1 invariant against real files.
//
// These tests are written against the real corpus in pypi/real/pp/ rather than
// hand-authored TOML, for the reason D24 records: a fixture written by the same
// person as the parser cannot contain a shape the parser does not anticipate.

const ppCorpus = "../../testdata/fixtures/pypi/real/pp"

func ppFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(ppCorpus, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "pyproject.toml" {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walking %s: %v", ppCorpus, err)
	}
	return out
}

// TestPyprojectCorpusAgreesWithItsOwnContents is the section-1 invariant
// applied to the new format: the resolver's answer is compared against the
// file's own declaration, not against another resolver.
func TestPyprojectCorpusAgreesWithItsOwnContents(t *testing.T) {
	files := ppFiles(t)
	if len(files) == 0 {
		t.Skip("no pyproject corpus; run scripts/fetch_corpus.py pypi")
	}
	var withDeps, withoutDeps int
	for _, f := range files {
		rel, _ := filepath.Rel(ppCorpus, f)
		t.Run(filepath.ToSlash(rel), func(t *testing.T) {
			declared := declaredDependencies(f)

			comps, err := pyprojectResolver{}.Resolve(filepath.Dir(f), "pyproject.toml")
			if err != nil {
				t.Fatalf("parse error on a real upstream file: %v", err)
			}
			// A TOML parse failure must not be reported as a silent zero: the
			// counter deliberately returns 0 for unparseable input so the real
			// error surfaces.
			if declared > 0 && len(comps) == 0 {
				t.Fatalf("SILENT ZERO: declares %d dependencies, resolved 0", declared)
			}
			if declared == 0 && len(comps) > 0 {
				t.Fatalf("declares no dependencies but resolved %d: %v",
					len(comps), purlList(comps))
			}
			for _, c := range comps {
				if c.Name == "python" || c.Name == "python_version" {
					t.Errorf("resolved %q: the interpreter constraint is not a package", c.Name)
				}
				if c.Purl == "" {
					t.Errorf("component %q has no PURL", c.Name)
				}
				if c.Ecosystem != "pypi" {
					t.Errorf("component %q has ecosystem %q, want pypi", c.Name, c.Ecosystem)
				}
			}
		})
		if declaredDependencies(f) > 0 {
			withDeps++
		} else {
			withoutDeps++
		}
	}
	// The corpus is only useful if it contains BOTH outcomes. A suite that
	// only ever sees "resolved something" cannot catch a counter that
	// invents dependencies.
	if withDeps == 0 || withoutDeps == 0 {
		t.Errorf("corpus needs both cases to be meaningful: %d declare deps, %d do not",
			withDeps, withoutDeps)
	}
	t.Logf("corpus: %d with declared deps, %d legitimately without", withDeps, withoutDeps)
}

// TestPyprojectCorpusHasKnownTrueNegatives pins the specific real files that
// legitimately declare nothing, so a future "improvement" that starts
// inventing dependencies for them fails here rather than in production.
func TestPyprojectCorpusHasKnownTrueNegatives(t *testing.T) {
	// These are real: each has a [project] table and no runtime dependencies.
	for _, repo := range []string{"pallets/click", "python-hyper/h11", "urllib3/urllib3"} {
		dir := filepath.Join(ppCorpus, filepath.FromSlash(repo))
		if _, err := os.Stat(dir); err != nil {
			t.Logf("%s not in corpus, skipping", repo)
			continue
		}
		t.Run(filepath.ToSlash(repo), func(t *testing.T) {
			declared := declaredDependencies(filepath.Join(dir, "pyproject.toml"))
			if declared != 0 {
				t.Errorf("%s declares %d dependencies; the corpus entry changed, "+
					"re-check whether it should now be a positive case", repo, declared)
			}
			comps, err := pyprojectResolver{}.Resolve(dir, "pyproject.toml")
			if err != nil {
				t.Fatal(err)
			}
			if len(comps) != 0 {
				t.Errorf("got %v, want no components", purlList(comps))
			}
		})
	}
}

// TestPoetryTableIgnoresPythonConstraint is the real-world trap: rich's
// [tool.poetry.dependencies] contains `python = ">=3.9.0"`, which is the
// interpreter constraint. Treating it as a package would invent a dependency
// called "python" that does not exist on PyPI.
func TestPoetryTableIgnoresPythonConstraint(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `
[tool.poetry]
name = "demo"
version = "1.0.0"

[tool.poetry.dependencies]
python = ">=3.9.0"
pygments = "^2.13.0"
pywidgets = { version = ">=7.5.1,<9", optional = true }
markdown-it-py = ">=2.2.0"
`)

	comps, err := pyprojectResolver{}.Resolve(dir, "pyproject.toml")
	if err != nil {
		t.Fatal(err)
	}
	got := nameSet(comps)
	want := map[string]bool{"pygments": true, "pywidgets": true, "markdown-it-py": true}
	if len(comps) != len(want) {
		t.Fatalf("got %d components %v, want %d", len(comps), got, len(want))
	}
	for _, n := range []string{"python", "demo"} {
		if got[n] {
			t.Errorf("resolved %q; the interpreter constraint and the project itself "+
				"are not dependencies", n)
		}
	}
	for n := range want {
		if !got[n] {
			t.Errorf("missing dependency %q", n)
		}
	}
	// The optional inline-table form must still yield a version.
	for _, c := range comps {
		if c.Name == "pywidgets" && c.Version != "7.5.1" {
			t.Errorf("pywidgets version = %q, want 7.5.1 (lower bound)", c.Version)
		}
	}
}

// TestPEP621Shapes covers the array, the PEP 735 table, extras, markers, and
// direct references, each of which appears in the real corpus.
func TestPEP621Shapes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `
[project]
name = "demo"
version = "1.0.0"
dependencies = [
    "starlette>=0.46.0",
    "pydantic >= 2.9.0",
    "requests[security]==2.32.0",
    "urllib3>=1.26.0,<3",
    "typing-extensions; python_version < '3.11'",
    "somepkg @ git+https://github.com/foo/bar.git",
    "bare",
]
`)
	comps, err := pyprojectResolver{}.Resolve(dir, "pyproject.toml")
	if err != nil {
		t.Fatal(err)
	}
	got := versionOf(comps)
	for _, want := range []struct{ name, version string }{
		{"starlette", "0.46.0"},
		{"pydantic", "2.9.0"},
		{"requests", "2.32.0"},
		{"urllib3", "1.26.0"},
		{"bare", ""},
		{"somepkg", ""},
	} {
		v, ok := got[want.name]
		if !ok {
			t.Errorf("missing %q; got %v", want.name, nameSet(comps))
			continue
		}
		if v != want.version {
			t.Errorf("%s version = %q, want %q", want.name, v, want.version)
		}
	}
	// The marker-only entry has a name but no version; dropping it would lose a
	// real dependency.
	if _, ok := got["typing-extensions"]; !ok {
		t.Errorf("marker-only dependency was dropped; got %v", nameSet(comps))
	}
	// The project's own name is not a dependency of itself.
	if _, ok := got["demo"]; ok {
		t.Error("resolved the project itself as its own dependency")
	}
}

// TestPEP735DependencyTable covers the [project.dependencies] table form.
func TestPEP735DependencyTable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `
[project]
name = "demo"
version = "1.0.0"

[project.dependencies]
requests = ">=2.31"
urllib3 = ">=1.26"
`)
	comps, err := pyprojectResolver{}.Resolve(dir, "pyproject.toml")
	if err != nil {
		t.Fatal(err)
	}
	got := versionOf(comps)
	if len(comps) != 2 {
		t.Fatalf("got %d components %v, want 2", len(comps), purlList(comps))
	}
	if got["requests"] != "2.31" || got["urllib3"] != "1.26" {
		t.Errorf("versions wrong: %v", got)
	}
}

// TestPyprojectLocklessProjectEndToEnd is the case that motivated D27: a
// project with only a pyproject.toml must produce components, and must not
// trip the silent-zero guard.
func TestPyprojectLocklessProjectEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `
[project]
name = "lockless"
version = "0.1.0"
dependencies = ["requests>=2.31.0", "click>=8.0"]
`)
	comps, err := ResolveFile(pyprojectResolver{}, dir, "pyproject.toml")
	if err != nil {
		t.Fatalf("a lock-less project with declared deps must resolve: %v", err)
	}
	if len(comps) != 2 {
		t.Fatalf("got %d components, want 2", len(comps))
	}
}

// TestDeclaredInPyprojectDoesNotCountMetadata is the regression for the bug
// the invariant found: the counter tallied every non-comment line, so
// `name = "click"` and `[build-system]` counted as dependencies. That produced
// 275 phantom dependencies for ruff and rejected 12 correct results.
func TestDeclaredInPyprojectDoesNotCountMetadata(t *testing.T) {
	dir := t.TempDir()
	// click's real shape: a full [project] table with metadata and no deps.
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `
[build-system]
requires = ["flit_core >=3.11,<4"]
build-backend = "flit_core.buildapi"

[project]
name = "click"
version = "8.6.0.dev"
description = "Composable command line interface toolkit"
readme = "README.md"
license = "BSD-3-Clause"
requires-python = ">=3.10"
maintainers = [{name = "Pallets", email = "x@y"}]
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
]
dependencies = []

[dependency-groups]
dev = ["ruff", "tox"]
`)
	if n := declaredDependencies(filepath.Join(dir, "pyproject.toml")); n != 0 {
		t.Errorf("declaredDependencies = %d, want 0: metadata and build-system "+
			"requirements are not runtime dependencies", n)
	}
}

func TestDeclaredInPyprojectCountsRealDeps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `
[project]
name = "demo"
version = "1.0.0"
dependencies = ["a>=1", "b>=2", "c>=3"]
`)
	if n := declaredDependencies(filepath.Join(dir, "pyproject.toml")); n != 3 {
		t.Errorf("declaredDependencies = %d, want 3", n)
	}
}

// TestDeclaredInPyprojectIgnoresUnparseable confirms a broken file reports 0
// rather than a bogus count, so the real parse error surfaces instead of a
// misleading silent zero.
func TestDeclaredInPyprojectIgnoresUnparseable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pyproject.toml")
	writeFile(t, p, "this is [not valid toml ===")
	if n := declaredDependencies(p); n != 0 {
		t.Errorf("declaredDependencies = %d for unparseable input, want 0", n)
	}
	// And the resolver must surface the parse error, not an empty list.
	_, err := pyprojectResolver{}.Resolve(dir, "pyproject.toml")
	if err == nil {
		t.Fatal("unparseable TOML returned no error")
	}
	if errors.Is(err, ErrSilentZero) {
		t.Error("a TOML parse error was misreported as a silent zero")
	}
}

func nameSet(comps []model.Component) map[string]bool {
	out := map[string]bool{}
	for _, c := range comps {
		out[c.Name] = true
	}
	return out
}

func versionOf(comps []model.Component) map[string]string {
	out := map[string]string{}
	for _, c := range comps {
		out[c.Name] = c.Version
	}
	return out
}

func purlList(comps []model.Component) []string {
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		out = append(out, c.Name+"@"+c.Version)
	}
	return out
}
