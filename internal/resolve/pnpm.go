package resolve

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/0xsan7/scram/internal/model"
)

func init() { Register(pnpmResolver{}) }

type pnpmResolver struct{}

// Ecosystem is npm: a pnpm-lock.yaml resolves npm packages, and OSV
// publishes advisories against the npm ecosystem. See the same note on
// yarnResolver -- registering this as its own ecosystem would produce
// PURLs no advisory could match.
func (pnpmResolver) Ecosystem() string { return model.EcoNPM }

// Priority is declared, not inherited. npm now has three resolvers, and
// the dispatch rule is only safe when each one states its own rank rather
// than falling back on init() order -- which is the thing a future edit
// to the file list would silently reorder. All three read a lockfile and
// report exact resolved versions, so all three are PriorityLockfile;
// they are never ranked against each other because each claims a
// different filename via Handles.
func (pnpmResolver) Priority() int { return PriorityLockfile }

func (pnpmResolver) Handles(path string) bool {
	return filepath.Base(path) == "pnpm-lock.yaml"
}

// pnpmPackage is one resolved package from a pnpm-lock.yaml.
type pnpmPackage struct {
	name    string
	version string
	// integrity is the sha512 from the `resolution:` field.
	integrity string
	// direct is true when the root package.json asked for it.
	direct bool
	// dev is true when the entry is marked `dev: true`, i.e. it is only
	// reachable from devDependencies.
	dev bool
	// optional is true when the entry is marked `optional: true`, which
	// for pnpm includes platform-specific binaries that never install on
	// the current machine.
	optional bool
	// deps are the keys of this package's resolved dependencies.
	deps []string
}

// Resolve parses a pnpm-lock.yaml.
//
// This is the format with the largest gap between its versions, and the
// gap is not cosmetic. pnpm 5 and 6 (lockfileVersion 5.3/5.4/6.0) write
// package keys as slash-delimited paths with a peer-dependency suffix:
//
//	/@algolia/autocomplete-core/1.5.0:
//	/@algolia/autocomplete-preset-algolia/1.5.0_algoliasearch@4.11.0:
//
// pnpm 9 (lockfileVersion 9.0) writes them as `name@version` with no
// suffix, and splits the document in two: `packages` holds resolution
// metadata while `snapshots` holds the resolved dependency graph.
//
// Reading a v9 file with a v6 parser yields no packages at all, and
// reading a v5 file with a v9 parser does the same. Both are silent
// zeros -- an empty inventory that scans as clean. So the version is
// read first and the key format is chosen from it, rather than the
// parser guessing from the shape of a key.
func (r pnpmResolver) Resolve(root, path string) ([]model.Component, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil, err
	}
	doc := string(data)
	pkgs := parsePnpmLock(doc)
	if len(pkgs) == 0 {
		return nil, nil
	}

	direct := map[string]bool{}
	if b, err := os.ReadFile(filepath.Join(root, filepath.Dir(path), "package.json")); err == nil {
		direct = npmDirectFromPackageJSON(b)
	}

	out := make([]model.Component, 0, len(pkgs))
	for _, p := range pkgs {
		c := model.Component{
			Name:      p.name,
			Version:   p.version,
			Ecosystem: model.EcoNPM,
			Purl:      makeSimplePURL("npm", p.name, p.version),
			Direct:    p.direct || direct[p.name],
		}
		if h := parseIntegrity(p.integrity); h != "" {
			c.Hashes = map[string]string{"sha512": h}
		}
		out = append(out, c)
	}
	return Dedupe(out), nil
}

// parsePnpmLock reads both lockfile generations.
//
// It is a targeted line reader rather than a YAML parse for two reasons.
// The documents are large -- the corpus runs to 2.26 MB -- and, more
// importantly, the shape being read is not general YAML: package keys are
// quoted or bare depending on whether they contain a scope, and the
// distinction between a key and a field is positional, not syntactic. A
// general YAML parser would accept the file and then hand back a map
// whose keys need the same interpretation anyway.
func parsePnpmLock(s string) []pnpmPackage {
	// The lockfileVersion decides the key format. pnpm writes it as
	// `lockfileVersion: '9.0'`, `lockfileVersion: '6.0'` or bare
	// `lockfileVersion: 5.4`, so the quotes and the float both need
	// tolerating.
	slashFormat := pnpmUsesSlashKeys(s)

	var out []pnpmPackage
	var cur *pnpmPackage
	// section tracks which top-level block we are inside, so a
	// `dependencies:` key under `packages` is not mistaken for a
	// dependency of something else.
	var section string
	inDeps := false

	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}

	lines := strings.Split(s, "\n")
	for n := 0; n < len(lines); n++ {
		line := lines[n]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		// A top-level key, at indent 0.
		if indent == 0 {
			name, _, _ := strings.Cut(trimmed, ":")
			if name != "packages" && name != "snapshots" {
				if cur != nil {
					flush()
				}
				section = name
				inDeps = false
				continue
			}
			if cur != nil {
				flush()
			}
			// Both blocks are read. On a v9 file `packages` carries the
			// identity and integrity and `snapshots` carries the graph;
			// the merge is done by key at the end. On a v5 file only
			// `packages` exists and it holds both.
			section = name
			inDeps = false
			continue
		}

		// A package key sits at indent 2, but ONLY inside the
		// packages/snapshots blocks. `importers` uses indent 2 for
		// project paths and `overrides` for package names, and treating
		// those as packages is what produced PURLs like
		// pkg:npm/packages@apply-release-plan -- plausible-looking
		// components that are actually filesystem paths.
		if indent == 2 && strings.HasSuffix(trimmed, ":") &&
			(section == "packages" || section == "snapshots") {
			// Flush the PREVIOUS entry first. Assigning over `cur`
			// without doing this keeps only the last package in the
			// file, which is how a 2.26 MB lockfile with 2389 entries
			// reported three components and no error.
			flush()
			key := strings.TrimSuffix(trimmed, ":")
			key = unquoteYarn(key) // pnpm quotes scoped keys with SINGLE quotes
			p, ok := parsePnpmKey(key, slashFormat)
			if !ok {
				cur = nil
				inDeps = false
				continue
			}
			cur = &pnpmPackage{name: p.name, version: p.version}
			inDeps = false
			continue
		}

		if cur == nil {
			continue
		}

		// Fields under a package.
		if indent >= 4 {
			switch {
			case strings.HasPrefix(trimmed, "resolution:"):
				cur.integrity = pnpmIntegrity(strings.TrimSpace(strings.TrimPrefix(trimmed, "resolution:")))
			case trimmed == "dev: true":
				cur.dev = true
			case trimmed == "optional: true":
				cur.optional = true
			case trimmed == "dependencies:" || trimmed == "optionalDependencies:":
				inDeps = true
			default:
				if inDeps && strings.HasSuffix(trimmed, ":") {
					k := unquoteYarn(strings.TrimSuffix(trimmed, ":"))
					if k != "" {
						cur.deps = append(cur.deps, k)
					}
				}
			}
			continue
		}
	}
	flush()

	if section == "" {
		return out
	}
	// On a v9 file, `snapshots` may hold entries whose identity only
	// appears there. Merge by key so an entry seen in both blocks is not
	// counted twice and an entry seen in only one is not lost.
	return pnpmMergeByKey(out)
}

// pnpmUsesSlashKeys reports whether this lockfile predates the 9.0 key
// format. Detection is by the declared version, not by inspecting a key,
// so a v6 file whose first package happens to look unusual is still read
// as v6.
func pnpmUsesSlashKeys(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 40) {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "lockfileVersion:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(t, "lockfileVersion:"))
		v = unquoteYarn(v)
		// "9" and "9.0" are the same generation; so is anything
		// starting with 9. Compare on the major component only.
		major := v
		if i := strings.Index(v, "."); i > 0 {
			major = v[:i]
		}
		// The KEY SCHEMA changed at 6.0, not at 9.0, and the change is
		// not simply "slash vs no slash":
		//
		//	5.3 / 5.4   /name/version           (slash separated)
		//	6.0        /name@version           (slash PREFIX, @ delimiter)
		//	9.0 / 10   name@version            (no prefix, @ delimiter)
		//
		// Treating 6.0 as a 5.x file is wrong twice over: the delimiter is
		// the one from 9.0, so a 5.x parse of `/lodash@4.17.21` yields
		// name "lodash@4.17.21" at version "" and the component is
		// dropped. Measured against a real pnpm 7 repository
		// (lockfileVersion '6.0'), that cost 361 components where the
		// same parser reads ~1650 from a 9.0 file -- a silent undercount
		// of roughly 78% of the real dependency tree, from a file that
		// parsed without error.
		//
		// So the question is not "is there a slash" but "is the last
		// segment a bare version". parsePnpmKey decides per key, and
		// this returns the DEFAULT for the generation.
		switch major {
		case "5":
			return true
		case "6":
			// 6.0 keeps a leading slash on the key -- "/lodash@4.17.21" --
			// but the delimiter is "@", the same as 9.0. The leading
			// slash is stripped by the @-branch below, so this is a
			// non-slash key as far as parsing is concerned.
			return false
		case "9", "10":
			return false
		default:
			return true
		}
	}
	// No version line at all: pre-date-stamped files exist, and the older
	// format is the safer assumption because the newer one is a superset
	// only in the direction of more splitting.
	return true
}

// parsePnpmKey splits a package key into name and version.
//
// Two real shapes, and mixing them up loses packages:
//
//	v5   /@algolia/autocomplete-core/1.5.0
//	v5   /@algolia/autocomplete-preset-algolia/1.5.0_algoliasearch@4.11.0
//	v9   '@algolia/autocomplete-core@1.5.0'
//	v9   react-dom@18.2.0
//
// The v5 peer suffix is the trap. `1.5.0_algoliasearch@4.11.0` is a
// version of 1.5.0 resolved against a specific peer version; the
// underscore is not part of the version, and the "@" inside the suffix is
// not a separator. Taking everything after the last slash verbatim yields
// a version string that matches no advisory in existence.
func parsePnpmKey(key string, slashFormat bool) (pnpmPackage, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return pnpmPackage{}, false
	}
	if !slashFormat {
		// Strip the peer context FIRST. On a v9 file the `snapshots` block
		// keys entries as
		//
		//	@ai-sdk/anthropic@3.0.58(zod@4.1.12)
		//
		// whose LAST "@" belongs to the peer package, not to the
		// dependency itself. Splitting first would make the name
		// "@ai-sdk/anthropic@3.0.58(zod" and the version "4.1.12" --
		// a component that exists in no registry, which OSV will never
		// match, so a real dependency reads as clean.
		base := stripPnpmPeerSuffix(key)
		// A 6.0 key carries a LEADING SLASH that the 9.0 form does not:
		//
		//	6.0   /@scope/name@1.2.3
		//	9.0   @scope/name@1.2.3
		//
		// Without stripping it, LastIndex("@") is still correct but the
		// NAME comes out as "/@scope/name" -- with a slash in it, so the
		// PURL names a package that does not exist and matches nothing.
		// The same fix covers a 9.0 key that was quoted with the slash
		// still attached.
		base = strings.TrimPrefix(base, "/")
		i := strings.LastIndex(base, "@")
		if i <= 0 {
			return pnpmPackage{}, false
		}
		name, version := base[:i], base[i+1:]
		if name == "" || version == "" {
			return pnpmPackage{}, false
		}
		return pnpmPackage{name: name, version: version}, true
	}
	// /name/version, with an optional _peer@ver suffix on the version.
	//
	// A SCOPED name makes this three parts, not two:
	//
	//	/@algolia/autocomplete-core/1.5.0
	//
	// Taking parts[len-2] and parts[len-1] yields the name
	// "autocomplete-core" and throws the scope away, so the component is
	// filed under a name that does not exist and the real
	// @algolia/autocomplete-core is never inventoried at all. The version
	// is always last; everything before it is the name, joined back up.
	parts := strings.Split(key, "/")
	if len(parts) < 2 {
		return pnpmPackage{}, false
	}
	version := parts[len(parts)-1]
	// Drop the leading empty segment produced by the leading slash.
	name := strings.Join(parts[:len(parts)-1], "/")
	name = strings.TrimPrefix(name, "/")
	if name == "" || version == "" {
		return pnpmPackage{}, false
	}
	version = stripPnpmPeerSuffix(version)
	return pnpmPackage{name: name, version: version}, true
}

// stripPnpmPeerSuffix removes the peer-dependency resolution context from
// a version.
//
// pnpm records it as "_algoliasearch@4.11.0" (v5) or "(algoliasearch@4.11.0)"
// (v9). Neither is part of the version number, and both would otherwise
// end up inside a PURL where OSV has no record of it -- the package would
// be inventoried and never match, which is the silent-zero failure with
// a plausible-looking inventory attached.
func stripPnpmPeerSuffix(v string) string {
	if i := strings.Index(v, "("); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "_"); i >= 0 {
		v = v[:i]
	}
	return v
}

// pnpmIntegrity pulls the sha512 out of a resolution flow mapping.
func pnpmIntegrity(res string) string {
	// resolution: {integrity: sha512-...., tarball: https://...}
	if i := strings.Index(res, "integrity:"); i >= 0 {
		rest := res[i+len("integrity:"):]
		end := strings.IndexAny(rest, ",}")
		if end < 0 {
			end = len(rest)
		}
		return strings.TrimSpace(rest[:end])
	}
	return ""
}

// pnpmMergeByKey collapses entries that appear in both `packages` and
// `snapshots`, keeping whichever copy carries the resolution metadata.
func pnpmMergeByKey(in []pnpmPackage) []pnpmPackage {
	if len(in) == 0 {
		return in
	}
	byKey := map[string]pnpmPackage{}
	order := make([]string, 0, len(in))
	for _, p := range in {
		k := p.name + "@" + p.version
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
			byKey[k] = p
			continue
		}
		// Already present: keep the richer record.
		old := byKey[k]
		if p.integrity != "" {
			old.integrity = p.integrity
		}
		old.dev = old.dev || p.dev
		old.optional = old.optional || p.optional
		old.deps = append(old.deps, p.deps...)
		byKey[k] = old
	}
	out := make([]pnpmPackage, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}
