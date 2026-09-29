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

// The three lockfile parsers added for yarn, pnpm and Cargo read files that
// anyone with push access controls, so they get the same treatment as the
// original three. They additionally assert a third property, because the
// first two parsers to ship here both passed "no panic" and "no silent
// zero" while still being wrong:
//
//   3. Every component the parser emits is internally consistent -- the
//      name and version it reports are both findable in the PURL it builds.
//
// That third property is the one that would have caught both real defects
// found during this work. The yarn key splitter could emit a NAME
// containing an entire descriptor list ("@babel/code-frame@npm:^7.0.0,
// @babel/code-frame@npm:^7.10.4"), and the pnpm v9 key splitter could emit
// a VERSION taken from inside a peer-resolution suffix ("zod@4.1.12" ->
// version 4.1.12). Neither crashed. Neither returned an empty list. Both
// produced inventories that look populated and can never match an OSV
// advisory, so the scanner would report a clean bill of health for a
// project it never actually looked at -- a silent false clean, which is
// the specific failure this project treats as unrecoverable.

// purlAgreesWithFields reports whether a component's PURL actually carries
// the name and version the component claims to have.
//
// The comparison is against the percent-ENCODED form, because that is what
// a PURL contains. A module named "A.!" legitimately yields
// "pkg:golang/A.%21@v0" -- the encoding is the spec, not a corruption --
// and a naive substring check on the raw name reports a false failure on
// correct output.
//
// The property being guarded is the one that actually broke: a name or
// version that is a FRAGMENT of the real one, or that contains more than
// the real one. Comparing the full encoded name and version against the
// PURL catches that, and cannot be satisfied by a shortened value.
func purlAgreesWithFields(c model.Component) bool {
	if c.Purl == "" || c.Name == "" || c.Version == "" {
		return false
	}
	// The name must be reconstructed from the PURL, in order, with the
	// separators the spec uses.
	//
	// A plain substring test over the whole name is wrong for every
	// ecosystem whose PURL splits the name across a namespace separator:
	// the Go ecosystem renders "github.com/gin-gonic/gin" as namespace
	// "github.com/gin-gonic" plus name "gin", so the full name is not a
	// contiguous substring of the PURL. That is the spec's encoding, not
	// a defect.
	//
	// But splitting the check into independent per-segment "contains"
	// tests is worse, because it is order-blind: a PURL reading
	// ".../github.com/errors" would satisfy a name of
	// "github.com/pkg/errors" on the two segments it happens to share.
	// So the segments have to appear in ORDER and ADJACENT, which is
	// what rebuilding the suffix and looking for one contiguous run
	// actually tests.
	// A PURL is built from a name in one of two shapes, and the spec
	// percent-encodes them differently:
	//
	//	npm:    the leading "@" of a scope is encoded, the "/" is not:
	//	        "@babel/core" -> "%40babel/core"
	//	others: slashes separate namespace from name and stay literal:
	//	        "github.com/pkg/errors" -> "github.com/pkg/errors"
	//
	// So the check has to try both encodings rather than assume one. The
	// full percent-encoded form is also tried, because a name that itself
	// contains no separators (npm, cargo, pypi) reduces to it.
	for _, enc := range purlNameEncodings(c.Name) {
		if strings.Contains(c.Purl, enc) {
			goto versionOK
		}
	}
	return false

versionOK:
	return strings.Contains(c.Purl, purlEscape(c.Version))
}

// purlEscape applies the percent-encoding a PURL uses for each character
// that is not allowed verbatim. It is deliberately a small, explicit
// subset: a Go module path and semver never legitimately contain anything
// outside the unreserved set plus the separators PURL leaves alone.
func purlEscape(s string) string {
	const safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

func checkPurlConsistency(t *testing.T, comps []model.Component) {
	t.Helper()
	for _, c := range comps {
		if !purlAgreesWithFields(c) {
			t.Errorf("PURL does not agree with the fields it was built from: "+
				"name=%q version=%q purl=%q", c.Name, c.Version, c.Purl)
		}
	}
}

// FuzzYarnLock covers yarn.lock in both dialects: classic's individually
// quoted descriptor list and Berry's single quoted key.
func FuzzYarnLock(f *testing.F) {
	seedFromCorpus(f, "yarn", "yarn.lock")
	f.Add([]byte(""))
	f.Add([]byte("# yarn lockfile v1\n"))
	f.Add([]byte("lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity sha512-x\n"))
	// Berry: ONE pair of quotes around the whole key.
	f.Add([]byte("\"@babel/code-frame@npm:^7.0.0, @babel/code-frame@npm:^7.10.4\":\n  version: 7.10.4\n"))
	// Classic: a quote around EACH descriptor.
	f.Add([]byte("\"a@npm:^1\", \"b@npm:^2\":\n  version: 1.0.0\n"))
	f.Add([]byte("__metadata:\n  version: 10\n"))
	// Unterminated quote, empty version, and a key with no @.
	f.Add([]byte("\"unterminated:\n"))
	f.Add([]byte("a@:\n  version: \n"))
	f.Add([]byte("@@@:\n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		comps := fuzzResolveIn(dir, "yarn.lock", data)
		checkPurlConsistency(t, comps)
	})
}

// FuzzPnpmLock covers both pnpm key schemas, since a versioned lockfile
// format is exactly the case where a parser can be quietly half-right.
func FuzzPnpmLock(f *testing.F) {
	seedFromCorpus(f, "pnpm", "pnpm-lock.yaml")
	f.Add([]byte(""))
	f.Add([]byte("lockfileVersion: '9.0'\n"))
	f.Add([]byte("lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n"))
	// The peer-context key that broke LastIndex("@").
	f.Add([]byte("lockfileVersion: '9.0'\n\npackages:\n\n  '@ai-sdk/anthropic@3.0.58(zod@4.1.12)':\n    resolution: {integrity: x}\n"))
	// The older slash schema, scoped and with the underscore peer suffix.
	f.Add([]byte("lockfileVersion: '5.4'\n\npackages:\n\n  /@algolia/core/1.5.0_algoliasearch@4.11.0:\n    resolution: {integrity: x}\n"))
	f.Add([]byte("packages:\n  a@1.0.0:\n  'b@2.0.0':\n  c@3.0.0:\n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		comps := fuzzResolveIn(dir, "pnpm-lock.yaml", data)
		checkPurlConsistency(t, comps)
		for _, c := range comps {
			// A pnpm version is a bare semver; a paren or underscore means
			// peer-resolution context survived into the component.
			if strings.ContainsAny(c.Version, "()_ ") {
				t.Errorf("version carries peer context: %q -> %s", c.Version, c.Purl)
			}
		}
	})
}

// FuzzCargoLock covers [[package]] blocks, including workspace-local
// packages that carry no source line at all.
func FuzzCargoLock(f *testing.F) {
	seedFromCorpus(f, "cargo", "Cargo.lock")
	f.Add([]byte(""))
	f.Add([]byte("version = 4\n"))
	f.Add([]byte("version = 4\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.18\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"))
	f.Add([]byte("version = 3\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/x/y?branch=main#abc123\"\n"))
	// A workspace member: name and version, no source.
	f.Add([]byte("[[package]]\nname = \"my-crate\"\nversion = \"0.1.0\"\n"))
	// The versioned-dependency form that disambiguates duplicate versions.
	f.Add([]byte("version = 4\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.18\"\ndependencies = [\n \"ryu 1.0.18\",\n]\n"))
	f.Add([]byte("[[package]]\nname = \"\"\nversion = \"\"\n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		comps := fuzzResolveIn(dir, "Cargo.lock", data)
		checkPurlConsistency(t, comps)
	})
}

// FuzzGoMod covers the go.mod fallback, which is the one path with no
// upstream source of truth in the old corpus: a project with no go.sum is
// now inventoried from go.mod instead of silently scanning as empty.
func FuzzGoMod(f *testing.F) {
	seedFromCorpus(f, "go", "go.mod")
	f.Add([]byte(""))
	f.Add([]byte("module github.com/go-chi/chi/v5\n\n// Chi supports the four most recent major versions of Go.\ngo 1.24\n"))
	f.Add([]byte("module x\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.1\n"))
	f.Add([]byte("module x\ngo 1.24\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v2.0.0 // indirect\n)\n"))
	f.Add([]byte("module x\n// require github.com/a/b v1.0.0\n"))
	f.Add([]byte("module x\ntoolchain go1.24.0\n\nreplace github.com/a/b => ../local\n"))
	f.Add([]byte("require \n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		// fuzzResolveIn writes go.mod beside any go.sum already in dir;
		// there is none, so this is the fallback branch specifically.
		path := filepath.Join(dir, "go.mod")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		comps, err := goResolver{}.Resolve(dir, "go.mod")
		if err != nil {
			return
		}
		checkPurlConsistency(t, comps)
	})
}

// purlNameEncodings returns the forms a PURL may use to render a package
// name, most specific first.
//
// The PURL spec leaves a namespace separator ("/") literal but percent-
// encodes an "@" that is part of the name rather than a version separator.
// npm composes the two, so "@babel/core" appears as "%40babel/core" while
// a Go module path appears with its slashes intact. Rather than hardcoding
// which ecosystem does which, the invariant accepts any of the encodings
// the spec permits and rejects a name that matches none of them.
func purlNameEncodings(name string) []string {
	all := purlEscape(name)
	forms := []string{all}

	// Literal slashes, everything else percent-encoded.
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			b.WriteByte('/')
			continue
		}
		b.WriteString(purlEscape(string(name[i])))
	}
	forms = append(forms, b.String())

	// Only a leading "@" encoded, which is the npm scope form.
	if strings.HasPrefix(name, "@") {
		forms = append(forms, "@"+strings.ReplaceAll(purlEscape(name[1:]), "/", "/"))
		forms = append(forms, "%40"+strings.ReplaceAll(purlEscape(name[1:]), "/", "/"))
	}
	return forms
}
