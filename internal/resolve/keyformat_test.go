package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two tests in this file exist because the mutation audit reported
// that reverting the corresponding fixes left the suite green. Both were
// real defects found by running the resolvers against the corpus, and
// both produced plausible-looking output rather than an error:
//
//   - a scoped package whose name kept a leading quote, so its PURL was
//     pkg:npm/%22%40babel%2Fcore@... and matched no OSV advisory
//   - a peer-suffixed version that was never stripped, so the component
//     was named "@ai-sdk/anthropic@3.0.58(zod" at version "4.1.12"
//
// A resolver that invents a package nobody publishes is indistinguishable,
// from the outside, from a resolver that found nothing. Neither showed up
// as a failing count.

// TestYarnKeySplitKeepsQuotesOutOfNames is the regression test for the
// comma split that ignored quoting.
func TestYarnKeySplitKeepsQuotesOutOfNames(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want []string
	}{
		{
			// The real form, from jest's Berry lockfile: two descriptors,
			// each quoted, separated by a comma.
			name: "two quoted descriptors",
			key:  `"@babel/code-frame@npm:^7.0.0", "@babel/code-frame@npm:^7.10.4"`,
			want: []string{"@babel/code-frame@npm:^7.0.0", "@babel/code-frame@npm:^7.10.4"},
		},
		{
			// A bare (unquoted) key, which is what classic writes for an
			// unscoped package.
			name: "bare single",
			key:  "lodash@^4.17.21",
			want: []string{"lodash@^4.17.21"},
		},
		{
			// A scoped key with NO quotes, which real files contain.
			name: "bare scoped",
			key:  "@babel/core@^7.11.1",
			want: []string{"@babel/core@^7.11.1"},
		},
		{
			name: "empty",
			key:  "",
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitYarnKey(c.key)
			if len(got) != len(c.want) {
				t.Fatalf("splitYarnKey(%q) = %q, want %q", c.key, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestYarnScopedNamesProduceMatchablePURLs checks the end result rather
// than the splitter: for every real scoped package in the Berry corpus, the
// PURL must carry a name with no quote characters in it.
//
// A name containing a quote percent-encodes to %22, which OSV has no
// record of, so the component is inventoried and never matched. The
// assertion is on the PURL string because that is the thing OSV sees.
func TestYarnScopedNamesProduceMatchablePURLs(t *testing.T) {
	files := corpusFiles(t, "yarn/real/berry", func(n string) bool { return n == "yarn.lock" })
	if len(files) == 0 {
		t.Skip("no yarn berry corpus present; run scripts/fetch_corpus.py yarn")
	}
	for _, f := range files {
		comps, err := yarnResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		checked := 0
		for _, c := range comps {
			if !strings.HasPrefix(c.Name, "@") {
				continue
			}
			checked++
			if strings.ContainsAny(c.Name, `"'`) {
				t.Errorf("%s: scoped name has quote characters: %q", filepath.Base(f), c.Name)
			}
			if strings.Contains(c.Purl, "%22") || strings.Contains(c.Purl, "%27") {
				t.Errorf("%s: PURL has a quoted name and cannot match: %s", filepath.Base(f), c.Purl)
			}
			if c.Version == "" {
				t.Errorf("%s: scoped component has no version: %+v", filepath.Base(f), c)
			}
		}
		if checked == 0 {
			t.Errorf("%s: no scoped packages found; the corpus or the parser changed", filepath.Base(f))
		}
	}
}

// TestPnpmPeerContextIsStrippedFromKeys is the regression test for the
// v9 `snapshots` key that was split on the wrong "@".
func TestPnpmPeerContextIsStrippedFromKeys(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want pnpmPackage
	}{
		{
			// From directus's real lockfile. LastIndex("@") lands inside
			// the parens, so splitting first produced the name
			// "@ai-sdk/anthropic@3.0.58(zod" at version "4.1.12".
			name: "v9 snapshot key with peer context",
			key:  "@ai-sdk/anthropic@3.0.58(zod@4.1.12)",
			want: pnpmPackage{name: "@ai-sdk/anthropic", version: "3.0.58"},
		},
		{
			name: "v9 package key, no peer context",
			key:  "@babel/core@7.11.1",
			want: pnpmPackage{name: "@babel/core", version: "7.11.1"},
		},
		{
			name: "v9 unscoped",
			key:  "lodash@4.17.21",
			want: pnpmPackage{name: "lodash", version: "4.17.21"},
		},
		{
			// The older underscore form, from a 5.4 lockfile.
			name: "v5 slash key with underscore peer suffix",
			key:  "/@algolia/autocomplete-preset-algolia/1.5.0_algoliasearch@4.11.0",
			want: pnpmPackage{name: "@algolia/autocomplete-preset-algolia", version: "1.5.0"},
		},
		{
			name: "v5 slash key, no suffix",
			key:  "/@algolia/autocomplete-core/1.5.0",
			want: pnpmPackage{name: "@algolia/autocomplete-core", version: "1.5.0"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			slash := pnpmUsesSlashKeys("lockfileVersion: '5.4'\n")
			if c.name == "v9 package key, no peer context" || c.name == "v9 unscoped" ||
				c.name == "v9 snapshot key with peer context" {
				slash = pnpmUsesSlashKeys("lockfileVersion: '9.0'\n")
			}
			got, ok := parsePnpmKey(c.key, slash)
			if !ok {
				t.Fatalf("parsePnpmKey(%q) refused the key", c.key)
			}
			if got.name != c.want.name || got.version != c.want.version {
				t.Errorf("parsePnpmKey(%q) = {%q %q}, want {%q %q}",
					c.key, got.name, got.version, c.want.name, c.want.version)
			}
		})
	}
}

// TestPnpmCorpusVersionsAreBare is the whole-corpus version of the same
// property. A pnpm version may be a bare semver and nothing else; a paren
// or an underscore in a version means peer context leaked through, and
// every PURL built from it is a component OSV cannot match.
func TestPnpmCorpusVersionsAreBare(t *testing.T) {
	files := corpusFiles(t, "pnpm/real", func(n string) bool { return n == "pnpm-lock.yaml" })
	if len(files) == 0 {
		t.Skip("no pnpm corpus present; run scripts/fetch_corpus.py pnpm")
	}
	total := 0
	for _, f := range files {
		comps, err := pnpmResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(comps) == 0 {
			t.Errorf("%s: resolved to ZERO components", filepath.Base(f))
			continue
		}
		for _, c := range comps {
			total++
			if strings.ContainsAny(c.Version, "()_ ") {
				t.Errorf("%s: version carries peer context %q -> %s",
					filepath.Base(f), c.Version, c.Purl)
			}
			if strings.ContainsAny(c.Name, `"' `) {
				t.Errorf("%s: name carries quoting %q -> %s", filepath.Base(f), c.Name, c.Purl)
			}
		}
	}
	if total == 0 {
		t.Fatal("no components examined at all; the assertion proved nothing")
	}
	t.Logf("checked %d pnpm components across %d lockfiles", total, len(files))
}

// TestYarnCorpusVersionsAndNamesAreBare is the same property for yarn,
// where the failure mode was a quoted name rather than a suffixed
// version.
func TestYarnCorpusVersionsAndNamesAreBare(t *testing.T) {
	for _, sub := range []string{"yarn/yarn-v1/real", "yarn/real/berry"} {
		files := corpusFiles(t, sub, func(n string) bool { return n == "yarn.lock" })
		if len(files) == 0 {
			t.Logf("%s absent; run scripts/fetch_corpus.py yarn", sub)
			continue
		}
		for _, f := range files {
			comps, err := yarnResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if len(comps) == 0 {
				t.Errorf("%s: resolved to ZERO components", filepath.Base(f))
				continue
			}
			for _, c := range comps {
				if strings.ContainsAny(c.Name, `"' `) {
					t.Errorf("%s: name carries quoting %q -> %s", filepath.Base(f), c.Name, c.Purl)
				}
				if c.Version == "" {
					t.Errorf("%s: empty version for %q", filepath.Base(f), c.Name)
				}
			}
		}
	}
}

// TestPnpmGenerationBoundaries pins the key schema of every pnpm
// lockfile generation, because the delimiter moved at 6.0 and not at 9.0.
//
// The generations are:
//
//	5.3 / 5.4   /name/version          (unquoted lockfileVersion)
//	6.0        /name@version          (quoted, SLASH-PREFIXED but @-delimited)
//	9.0 / 10   name@version           (no prefix, @-delimited)
//
// 6.0 is the trap. It is the only generation that is slash-prefixed AND
// @-delimited, so a parser that infers the format from "is there a slash"
// handles 5.x and 9.0 and silently drops most of a 6.0 file: the name comes
// out as "lodash@4.17.21" with an empty version. Measured against a real
// pnpm 7 repository, that was 361 components instead of 1523 -- a 76%
// undercount that raised no error, which is the failure mode this project
// treats as unrecoverable.
func TestPnpmGenerationBoundaries(t *testing.T) {
	cases := []struct {
		name     string
		header   string
		key      string
		wantName string
		wantVer  string
	}{
		{"5.3 unscoped", "lockfileVersion: 5.3", "/lodash/4.17.21", "lodash", "4.17.21"},
		{"5.4 scoped", "lockfileVersion: 5.4", "/@algolia/core/1.5.0", "@algolia/core", "1.5.0"},
		{"5.4 peer suffix", "lockfileVersion: 5.4",
			"/@algolia/autocomplete-core/1.5.0_algoliasearch@4.11.0", "@algolia/autocomplete-core", "1.5.0"},
		// The generation that was wrong.
		{"6.0 unscoped", "lockfileVersion: '6.0'", "/lodash@4.17.21", "lodash", "4.17.21"},
		{"6.0 scoped", "lockfileVersion: '6.0'", "/@aashutoshrathi/word-wrap@1.2.6",
			"@aashutoshrathi/word-wrap", "1.2.6"},
		{"6.0 peer suffix", "lockfileVersion: '6.0'", "/@ai-sdk/anthropic@3.0.58(zod@4.1.12)",
			"@ai-sdk/anthropic", "3.0.58"},
		{"9.0 unscoped", "lockfileVersion: '9.0'", "lodash@4.17.21", "lodash", "4.17.21"},
		{"9.0 scoped", "lockfileVersion: '9.0'", "@babel/core@7.11.1", "@babel/core", "7.11.1"},
		{"9.0 peer suffix", "lockfileVersion: '9.0'", "@ai-sdk/anthropic@3.0.58(zod@4.1.12)",
			"@ai-sdk/anthropic", "3.0.58"},
		{"10.0", "lockfileVersion: '9.0'", "@babel/core@7.11.1", "@babel/core", "7.11.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			slash := pnpmUsesSlashKeys(c.header)
			got, ok := parsePnpmKey(c.key, slash)
			if !ok {
				t.Fatalf("parsePnpmKey(%q, slash=%v) refused the key", c.key, slash)
			}
			if got.name != c.wantName || got.version != c.wantVer {
				t.Errorf("parsePnpmKey(%q, slash=%v) = {%q %q}, want {%q %q}",
					c.key, slash, got.name, got.version, c.wantName, c.wantVer)
			}
		})
	}
}

// TestPnpmCorpusCoversEveryGeneration records which generations the
// committed corpus actually contains.
//
// A resolver that is only ever run against 5.4 and 9.0 files will pass every
// test and still misparse 6.0, because 6.0 is a distinct schema that looks
// like a hybrid of the two. The corpus has to contain it, or the gap is
// invisible.
func TestPnpmCorpusCoversEveryGeneration(t *testing.T) {
	files := corpusFiles(t, "pnpm/real", func(n string) bool { return n == "pnpm-lock.yaml" })
	if len(files) == 0 {
		t.Skip("no pnpm corpus present; run scripts/fetch_corpus.py pnpm")
	}
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		seen[pnpmGeneration(string(b))] = true
	}
	for _, want := range []string{"5", "6", "9"} {
		if !seen[want] {
			t.Errorf("the pnpm corpus has no lockfileVersion %s.x file; generations present: %v",
				want, seen)
		}
	}
	t.Logf("pnpm corpus generations: %v", seen)
}

// TestCargoCorpusCoversVersionlessLockfiles records the same fact for
// Cargo.
//
// Cargo emits `version = N` only for the v3 and v4 formats. v1 and v2 omit
// it entirely and are told apart by content alone: v1 puts checksums in a
// [metadata] block and carries "(source)" in dependency strings, v2 writes
// an inline `checksum` key. A parser that required the version line, or
// that inferred the generation from it, would skip every pre-1.51 lockfile
// -- which includes the ones in long-lived projects that have not run
// `cargo update` in years.
func TestCargoCorpusCoversVersionlessLockfiles(t *testing.T) {
	files := corpusFiles(t, "cargo/real", func(n string) bool { return n == "Cargo.lock" })
	if len(files) == 0 {
		t.Skip("no cargo corpus present; run scripts/fetch_corpus.py cargo")
	}
	versioned, versionless := 0, 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		// The schema line is only a schema line BEFORE the first
		// [[package]] block. After that, every `version = ` is a PACKAGE
		// version, so searching the whole file -- or even just its first
		// few hundred bytes -- reports a V1 lockfile as versioned. That
		// mistake is the reason this test exists: it was the bug that
		// made the research corpus look like it had no V1 files in it.
		if cargoHasSchemaLine(string(b)) {
			versioned++
		} else {
			versionless++
		}
		// And every one of them must actually parse, version line or not.
		comps, err := cargoResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(comps) == 0 {
			t.Errorf("%s: resolved to ZERO components", f)
		}
	}
	if versionless == 0 {
		t.Errorf("no version-less Cargo.lock in the corpus; the v1/v2 formats are untested")
	}
	t.Logf("cargo corpus: %d with a version line, %d without (v1/v2)", versioned, versionless)
}

// pnpmGeneration returns the major component of a lockfileVersion, or "" if
// the file has none.
func pnpmGeneration(src string) string {
	for _, line := range strings.SplitN(src, "\n", 40) {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "lockfileVersion:") {
			continue
		}
		v := unquoteYarn(strings.TrimSpace(strings.TrimPrefix(t, "lockfileVersion:")))
		if i := strings.Index(v, "."); i > 0 {
			return v[:i]
		}
		return v
	}
	return ""
}

// cargoHasSchemaLine reports whether a Cargo.lock carries the `version = N`
// schema header.
//
// It is emitted only by the v3 and v4 formats. v1 and v2 omit it, and the
// only reliable way to tell is positional: a schema line appears before the
// first [[package]] block, whereas a package's own version line always
// appears after it. A substring search for "version = " cannot make that
// distinction and will call a v1 file versioned.
func cargoHasSchemaLine(src string) bool {
	firstPkg := strings.Index(src, "[[package]]")
	if firstPkg < 0 {
		// No packages at all; fall back to a whole-file search, since
		// there is no package version to confuse it with.
		return strings.Contains(src, "version = ")
	}
	head := src[:firstPkg]
	return strings.Contains(head, "version = ")
}

// TestGoModNameIsTheFullModulePath is the regression test for a bug that
// made every go.mod-only project report zero vulnerabilities.
//
// The OSV client queries by Component.Name, and OSV's Go ecosystem is keyed
// on the module PATH. The go.mod fallback was setting Name to the bare final
// path segment, so
//
//	github.com/gin-gonic/gin   was queried as   gin
//
// which matches no advisory in any registry. The PURL was correct, so the
// inventory looked right, the badge looked right, the score looked right,
// and the only thing that was wrong was the part the tool exists to do.
//
// The tell was that a project WITH a go.sum found the advisories and the
// same project WITHOUT one found none. This test pins the invariant that
// makes those two paths agree.
func TestGoModNameIsTheFullModulePath(t *testing.T) {
	cases := []struct{ module, wantName string }{
		{"github.com/gin-gonic/gin", "github.com/gin-gonic/gin"},
		{"golang.org/x/text", "golang.org/x/text"},
		// A nested path: the last segment alone is wildly ambiguous.
		{"github.com/aws/aws-sdk-go-v2/service/s3", "github.com/aws/aws-sdk-go-v2/service/s3"},
		// Names that collide once the path is stripped. If Name were the
		// last segment these two would be indistinguishable to OSV.
		{"github.com/gin-gonic/gin", "github.com/gin-gonic/gin"},
		{"gopkg.in/yaml.v3", "gopkg.in/yaml.v3"},
		{"go.uber.org/zap", "go.uber.org/zap"},
	}
	for _, c := range cases {
		if got := goModuleName(c.module); got != c.wantName {
			t.Errorf("goModuleName(%q) = %q, want %q", c.module, got, c.wantName)
		}
	}
}

// TestGoSumAndGoModAgreeOnIdentity is the property that would have caught it
// without needing to know any specific advisory: the two Go paths must
// produce the SAME Name for the same module, because only one of them was
// correct and the difference is invisible in the output.
func TestGoSumAndGoModAgreeOnIdentity(t *testing.T) {
	dir := t.TempDir()

	mod := "module example.com/demo\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n"
	if err := os.WriteFile(dir+"/go.mod", []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	fromMod, err := goResolver{}.Resolve(dir, "go.mod")
	if err != nil {
		t.Fatal(err)
	}

	sumDir := t.TempDir()
	sum := "github.com/gin-gonic/gin v1.6.0 h1:5cCxZcfmzQiNGRn5Wd4Z5SqUD1Fz7b3+8ghx5RX8Vk=\n"
	if err := os.WriteFile(sumDir+"/go.sum", []byte(sum), 0o644); err != nil {
		t.Fatal(err)
	}
	fromSum, err := goResolver{}.Resolve(sumDir, "go.sum")
	if err != nil {
		t.Fatal(err)
	}

	if len(fromMod) != 1 || len(fromSum) != 1 {
		t.Fatalf("expected one component from each path, got go.mod=%d go.sum=%d",
			len(fromMod), len(fromSum))
	}
	if fromMod[0].Name != fromSum[0].Name {
		t.Errorf("the two Go paths disagree on Name for the same module:\n"+
			"  go.mod -> %q\n  go.sum -> %q\n"+
			"OSV is queried by Name, so only one of these can find advisories",
			fromMod[0].Name, fromSum[0].Name)
	}
	if fromMod[0].Purl != fromSum[0].Purl {
		t.Errorf("the two Go paths disagree on Purl:\n  go.mod -> %q\n  go.sum -> %q",
			fromMod[0].Purl, fromSum[0].Purl)
	}
}
