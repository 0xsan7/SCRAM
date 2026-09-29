package resolve

import (
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
