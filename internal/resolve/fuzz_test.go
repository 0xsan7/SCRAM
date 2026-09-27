package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// Fuzz targets cover every parser SCRAM runs on input it does not control:
// JSON from a repository, TOML from a repository, and plain-text lockfiles.
//
// Two properties are asserted for every input, and neither is "it parses":
//
//  1. No panic. These parse untrusted files from repos anyone can push, and a
//     panic is a crash in a security tool.
//  2. No silent zero. A file that declares dependencies must either resolve
//     at least one component or return an explicit error. Returning an empty
//     list with no error is the D01/D22/D23 failure mode, and the fuzzer is
//     the cheapest way to find a new shape that triggers it.
//
// Property 2 needs a declaration count, so ResolveFile is used rather than
// calling Resolve directly -- that is the same invariant the corpus property
// tests assert, applied to arbitrary input.

// fuzzResolve writes the fuzz input to a real file and runs the full resolve
// path, because the resolvers read from disk and there is no byte-slice entry
// point to fuzz.
//
// dir is created ONCE per fuzz run via f.TempDir(), not per exec. With
// t.TempDir() the fuzzer ran at 0 execs/sec -- it appeared to "run for 180
// seconds" while exploring 47 inputs, which is the same failure as a tool
// reporting a number it did not earn. f.TempDir() is removed when the whole
// run finishes, so the cleanup cost is paid once instead of per input.
func fuzzResolveIn(dir, filename string, data []byte) []model.Component {
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil
	}
	r, err := GetFor(ecoFor(filename), filename)
	if err != nil {
		return nil // unsupported file for this ecosystem
	}
	comps, err := ResolveFile(r, dir, filename)
	if err != nil {
		return nil // an explicit error is a valid outcome
	}
	return comps
}

// ecoFor maps a filename to its ecosystem, mirroring detect's candidates.
func ecoFor(filename string) string {
	switch filename {
	case "package-lock.json", "npm-shrinkwrap.json":
		return model.EcoNPM
	case "go.sum", "go.mod":
		return model.EcoGo
	default:
		return model.EcoPyPI
	}
}

func FuzzNpmLockfile(f *testing.F) {
	// Seeded from the real corpus so the fuzzer starts from shapes that are
	// known to occur, not from strings invented here. D24: hand-authored
	// seeds inherit the author's blind spots.
	seedFromCorpus(f, "npm", "package-lock.json")
	f.Add([]byte(`{"lockfileVersion":1,"requires":true,"dependencies":{"lodash":{"version":"4.17.4"}}}`))
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/a":{"version":"1.0.0"}}}`))
	// The shape that produced D22: an array-valued license.
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"node_modules/p":{"version":"1.0.0","license":["MIT","Apache2"]}}}`))
	// The shape that produced D01: top-level "requires": true.
	f.Add([]byte(`{"lockfileVersion":3,"requires":true,"packages":{}}`))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = fuzzResolveIn(dir, "package-lock.json", data)
	})
}

func FuzzPyprojectToml(f *testing.F) {
	seedFromCorpus(f, "pypi", "pyproject.toml")
	f.Add([]byte(`[project]
name = "x"
version = "1.0.0"
dependencies = ["requests>=2.31.0", "click>=8.0"]
`))
	// The Poetry table form, which is a TABLE rather than an array.
	f.Add([]byte(`[tool.poetry.dependencies]
python = ">=3.9.0"
pygments = "^2.13.0"
`))
	// The inline-table entry with an optional flag.
	f.Add([]byte(`[tool.poetry.dependencies]
foo = { version = ">=7.5.1,<9", optional = true }
`))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = fuzzResolveIn(dir, "pyproject.toml", data)
	})
}

func FuzzPoetryLock(f *testing.F) {
	seedFromCorpus(f, "pypi", "poetry.lock")
	f.Add([]byte(`[[package]]
name = "requests"
version = "2.19.1"
category = "main"
`))
	f.Add([]byte(`[[package]]
name = "x"
version = ""

[[package]]
version = "1.0.0"
`))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = fuzzResolveIn(dir, "poetry.lock", data)
	})
}

func FuzzRequirementsTxt(f *testing.F) {
	seedFromCorpus(f, "pypi", "requirements.txt")
	f.Add([]byte("requests==2.19.1\n"))
	// The D23 shape: a ranged requirement that must still resolve.
	f.Add([]byte("requests>=2.31.0\njinja2~=2.10\n"))
	// The VCS shape that must be skipped rather than parsed as a package.
	f.Add([]byte("git+https://github.com/foo/bar.git#egg=bar\n"))
	f.Add([]byte("pkg @ https://example.com/pkg.whl\n"))
	f.Add([]byte("\n\n   \n-r other.txt\n--index-url https://x\n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = fuzzResolveIn(dir, "requirements.txt", data)
	})
}

func FuzzGoSum(f *testing.F) {
	seedFromCorpus(f, "go", "go.sum")
	f.Add([]byte("github.com/pkg/errors v0.9.1 h1:iURUrlRGxPUNPdy5z7M4E+77sj2Kpf79I2/F/q4rR7U=\n"))
	f.Add([]byte("github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n"))
	// Malformed: a module path with no version, and a version with no module.
	f.Add([]byte("\n v1.0.0 h1:x=\nv0.0.0 h1:x=\ngithub.com/a/b v1 h1:x=\n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = fuzzResolveIn(dir, "go.sum", data)
	})
}

// FuzzNpmV1Warning covers the advisory path from D30, which reads the file a
// second time and must not panic on malformed input.
func FuzzNpmV1Warning(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":1,"dependencies":{}}`))
	f.Add([]byte(`{"lockfileVersion":3}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(dir, "package-lock.json")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Skip()
		}
		_ = WarningsFor(npmResolver{}, dir, "package-lock.json")
		_ = declaredDependencies(p)
	})
}

// --- pure-function targets -------------------------------------------------

// FuzzParseIntegrity covers SRI hash parsing, which is pure string handling
// on attacker-controlled data.
func FuzzParseIntegrity(f *testing.F) {
	f.Add("sha512-abc123==")
	f.Add("sha1-deadbeef")
	f.Add("")
	f.Add("not-a-hash")
	f.Add("sha512-")
	f.Fuzz(func(t *testing.T, s string) {
		_ = parseIntegrity(s)
	})
}

// FuzzNameFromKey covers npm install-path parsing: the component name is
// derived from a path, so pathological keys are the interesting input.
func FuzzNameFromKey(f *testing.F) {
	f.Add("node_modules/lodash")
	f.Add("node_modules/@scope/pkg")
	f.Add("node_modules/a/node_modules/b")
	f.Add("")
	f.Add("node_modules/")
	f.Add(strings.Repeat("node_modules/", 50) + "x")
	f.Fuzz(func(t *testing.T, key string) {
		_ = nameFromKey(key)
	})
}

// FuzzPEP508 covers the single-requirement parser, which is where D23 lived.
func FuzzPEP508(f *testing.F) {
	f.Add("requests>=2.31.0")
	f.Add("requests[security]>=2.0,<3")
	f.Add("name @ https://example.com/pkg.whl")
	f.Add("")
	f.Add("!!!")
	f.Fuzz(func(t *testing.T, s string) {
		c, ok := parsePEP508(s)
		if ok && c.Name == "" {
			t.Fatalf("parsePEP508(%q) returned ok with an empty name", s)
		}
		_ = specifierVersion(s)
		_ = normalizePyPIName(s)
		_ = componentFromNameSpec("", s)
	})
}

// FuzzSplitGoModule covers go.sum path splitting.
func FuzzSplitGoModule(f *testing.F) {
	f.Add("github.com/pkg/errors")
	f.Add("")
	f.Add("gopkg.in/yaml.v2")
	f.Add("/")
	f.Add("a/b/c")
	f.Fuzz(func(t *testing.T, module string) {
		ns, name := splitGoModule(module)
		_ = goPURL(ns, name)
		_ = compareGoVersions("v1.0.0", "v1.2.0")
		_ = atoiSafe("999999999999999999999")
	})
}

// FuzzIsPythonConstraintKey guards the D27 check specifically: if this ever
// returns false for "python", every Poetry project invents a fake package.
func FuzzIsPythonConstraintKey(f *testing.F) {
	f.Add("python")
	f.Add("requests")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if strings.EqualFold(strings.TrimSpace(s), "python") && !isPythonConstraintKey(s) {
			t.Fatalf("isPythonConstraintKey(%q) = false; the interpreter "+
				"constraint would be parsed as a package named python", s)
		}
	})
}

// seedFromCorpus adds real fixtures as fuzz seeds. Without this the fuzzer
// only explores shapes invented in this file, which is D24's blind spot in a
// new place.
func seedFromCorpus(f *testing.F, eco, filename string) {
	f.Helper()
	// Inputs the fuzzer itself found, promoted to permanent seeds. Fuzzing
	// that does not leave a regression test behind has not been done, only
	// performed: these are the shapes that reached new coverage, and they
	// replay in `go test` without a fuzzer.
	seedFromDir(f, filepath.Join("..", "..", "testdata", "fuzz",
		"internal_resolve", fuzzTargetFor(filename)))
	root := filepath.Join("..", "..", "testdata", "fixtures", eco, "real")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a missing corpus is not a fuzz failure
		}
		if filepath.Base(path) != filename {
			return nil
		}
		if b, err := os.ReadFile(path); err == nil && len(b) < 2<<20 {
			f.Add(b)
		}
		return nil
	})
}

// seedFromDir adds every file in dir as a fuzz seed. Multiple fuzz args are
// supported by the corpus encoding, so string-shaped targets are covered by
// encoding the file as the single string argument each target expects.
func seedFromDir(f *testing.F, dir string) {
	f.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return // no promoted corpus for this target yet
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		f.Add(b)
	}
}

// fuzzTargetFor maps a corpus filename to the fuzz target that owns it.
func fuzzTargetFor(filename string) string {
	switch filename {
	case "package-lock.json":
		return "FuzzNpmLockfile"
	case "pyproject.toml":
		return "FuzzPyprojectToml"
	case "poetry.lock":
		return "FuzzPoetryLock"
	case "requirements.txt":
		return "FuzzRequirementsTxt"
	case "go.sum":
		return "FuzzGoSum"
	default:
		return ""
	}
}
