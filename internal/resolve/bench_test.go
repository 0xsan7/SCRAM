package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Benchmarks run against the real corpus rather than synthetic input, so a
// regression shows up as a regression on files that exist. Every benchmark
// reports ns/op and allocs/op; run with -benchmem.
//
// These exist to catch a specific class of change: someone makes resolution
// quadratic, or adds a regexp inside a loop, and CI goes quiet because the
// correctness tests all still pass. There are no hard thresholds -- a
// benchmark that fails the build on a noisy machine is a benchmark people
// delete -- but the numbers are recorded in BENCHMARKS.md and compared by
// hand when a change is suspect.

// fixtureFiles returns the real corpus paths for one ecosystem, so a
// benchmark can run over all of them.
func fixtureFiles(tb testing.TB, eco, filename string) []string {
	tb.Helper()
	base := filepath.Join("..", "..", "testdata", "fixtures", eco, "real")
	var out []string
	_ = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || d.Name() != filename {
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out
}

// bNpmRealCorpus resolves every real npm lockfile in the corpus, including
// the six npm v1 fixtures, on each iteration.
func BenchmarkNpmRealCorpus(b *testing.B) {
	files := fixtureFiles(b, "npm", "package-lock.json")
	if len(files) == 0 {
		b.Fatal("no npm fixtures found; the corpus is required for this benchmark")
	}
	root := filepath.Join("..", "..", "testdata", "fixtures", "npm", "real")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		total := 0
		for _, f := range files {
			comps, err := npmResolver{}.Resolve(root, relTo(b, root, f))
			if err != nil {
				continue
			}
			total += len(comps)
		}
		if total == 0 {
			b.Fatal("resolved zero components across the whole npm corpus")
		}
	}
}

// BenchmarkNpmLargestFixture is the single worst case in the corpus. The
// largest lockfile is the one that decides whether a scan is usable on a big
// monorepo, and a total across 16 files would hide a per-file blowup.
func BenchmarkNpmLargestFixture(b *testing.B) {
	files := fixtureFiles(b, "npm", "package-lock.json")
	var biggest string
	var biggestSize int64
	root := filepath.Join("..", "..", "testdata", "fixtures", "npm", "real")
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil && fi.Size() > biggestSize {
			biggestSize, biggest = fi.Size(), f
		}
	}
	if biggest == "" {
		b.Fatal("no npm fixtures found")
	}
	rel := relTo(b, root, biggest)
	b.Logf("largest npm fixture: %s (%d bytes)", rel, biggestSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := (npmResolver{}).Resolve(root, rel); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGoRealCorpus covers 63 real go.sum files, 11,600+ components.
func BenchmarkGoRealCorpus(b *testing.B) {
	files := fixtureFiles(b, "gomod", "go.sum")
	if len(files) == 0 {
		b.Fatal("no go fixtures found")
	}
	root := filepath.Join("..", "..", "testdata", "fixtures", "gomod", "real")
	b.Logf("%d go.sum files", len(files))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		total := 0
		for _, f := range files {
			comps, err := goResolver{}.Resolve(root, relTo(b, root, f))
			if err != nil {
				continue
			}
			total += len(comps)
		}
		if total == 0 {
			b.Fatal("resolved zero components across the whole go corpus")
		}
	}
}

// BenchmarkPyprojectCorpus covers the 44 real pyproject.toml files, the
// lock-less path introduced in D27.
func BenchmarkPyprojectCorpus(b *testing.B) {
	files := fixtureFiles(b, "pypi", "pyproject.toml")
	if len(files) == 0 {
		b.Fatal("no pyproject fixtures found")
	}
	root := filepath.Join("..", "..", "testdata", "fixtures", "pypi", "real", "pp")
	b.Logf("%d pyproject.toml files", len(files))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		total := 0
		for _, f := range files {
			comps, err := pyprojectResolver{}.Resolve(root, relTo(b, root, f))
			if err != nil {
				continue
			}
			total += len(comps)
		}
		if total == 0 {
			b.Fatal("resolved zero components across the whole pyproject corpus")
		}
	}
}

// BenchmarkNpmLicenseNormalization targets flexString.UnmarshalJSON
// specifically. D22 came from this path, and it is a hot spot: one call per
// package in the lockfile, so a regression here multiplies by the component
// count -- nest alone is 1,676 calls.
func BenchmarkNpmLicenseNormalization(b *testing.B) {
	inputs := []string{
		`"MIT"`,
		`""`,
		`["MIT", "Apache2"]`,
		`["MIT","Apache2","BSD-3-Clause"]`,
		`null`,
		`[null]`,
		`["GPL-3.0-only","MIT","MIT"]`,
		`[]`,
		`["MIT", null, "", "ISC"]`,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, in := range inputs {
			var f flexString
			if err := f.UnmarshalJSON([]byte(in)); err != nil {
				b.Fatalf("%s: %v", in, err)
			}
		}
	}
}

// BenchmarkParsePEP508 measures the requirement-specifier parser, which runs
// once per line in every Python file and is the D23 hot path.
func BenchmarkParsePEP508(b *testing.B) {
	inputs := []string{
		"requests==2.19.1",
		"pytest>=2.8.0,<10",
		"httpbin~=0.10.0",
		"urllib3 >= 1.23",
		"Django",
		"flask==1.0.*",
		"package[extra]>=1.0",
		"git+https://github.com/org/repo.git#egg=pkg",
		"pkg; python_version < '3.9'",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, in := range inputs {
			_, _ = parsePEP508(in)
		}
	}
}

// BenchmarkGoSumLine is the per-line hot path for Go fixtures: 63 files,
// tens of thousands of lines, each producing or not producing a component.
func BenchmarkGoSumLine(b *testing.B) {
	// splitGoModule splits "namespace/name" for a PURL, so the input is the
	// module path as it appears in go.sum.
	line := "github.com/hashicorp/consul"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ns, name := splitGoModule(line)
		if ns != "github.com/hashicorp" || name != "consul" {
			b.Fatalf("got %q/%q, want github.com/hashicorp/consul", ns, name)
		}
	}
}

// relTo makes an absolute or relative fixture path root-relative, which is
// what the resolvers expect.
func relTo(tb testing.TB, root, p string) string {
	tb.Helper()
	rel, err := filepath.Rel(root, p)
	if err != nil {
		// Fall back to the path with the corpus root stripped, which is
		// what a resolver needs on a case-insensitive filesystem.
		if r, e2 := filepath.Rel(mustAbs(tb, root), mustAbs(tb, p)); e2 == nil {
			return filepath.ToSlash(r)
		}
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

func mustAbs(tb testing.TB, p string) string {
	tb.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// BenchmarkResolveFileSilentZeroGuard measures the D26 guard itself. It runs
// only when a resolver returns zero, so on a healthy corpus it is never
// hit -- which is exactly why it needs a benchmark: a guard that only runs
// on failure can be accidentally quadratic without anyone noticing.
func BenchmarkDeclaredDependenciesTOML(b *testing.B) {
	// project.dependencies is the branch that counts; optional-dependencies
	// is deliberately included as a distractor, since the D28 bug was a
	// line counter that tallied every key in the file.
	data := []byte("[project]\nname = \"x\"\nversion = \"1\"\n" +
		"dependencies = [\"requests>=2.19\", \"jinja2<3\", \"urllib3\"]\n\n" +
		"[project.optional-dependencies]\ndev = [\"pytest>=7\", \"black\"]\n")
	dir := b.TempDir()
	p := filepath.Join(dir, "pyproject.toml")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 3 from project.dependencies. The optional-dependencies table and
		// the name/version keys must not be counted, which is the D28 bug.
		if n := declaredDependencies(p); n != 3 {
			b.Fatalf("declared %d, want 3", n)
		}
	}
}

// BenchmarkNormalizePyPIName measures the name-normalization path, which runs
// once per requirement and is where the D35 trim bug lived.
func BenchmarkNormalizePyPIName(b *testing.B) {
	inputs := []string{"Requests", "Flask_Login", "zope.interface", "Django", "ruamel.yaml.clib"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, in := range inputs {
			_ = normalizePyPIName(in)
		}
	}
}

// TestBenchmarksRunAgainstRealFiles guards the benchmarks themselves. A
// benchmark that silently measures nothing looks exactly like a fast one.
func TestBenchmarksRunAgainstRealFiles(t *testing.T) {
	for _, eco := range []struct{ name, file string }{
		{"npm", "package-lock.json"},
		{"gomod", "go.sum"},
		{"pypi", "pyproject.toml"},
	} {
		files := fixtureFiles(t, eco.name, eco.file)
		if len(files) == 0 {
			t.Errorf("%s: no %s fixtures; the benchmarks would measure "+
				"nothing and look fast", eco.name, eco.file)
		}
	}
	if strings.TrimSpace(string(npmV1Warning)) == "" {
		t.Error("npmV1Warning is empty")
	}
}
