package resolve

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xsan7/scram/internal/graph"
	"github.com/0xsan7/scram/internal/model"
)

func init() { Register(yarnResolver{}) }

type yarnResolver struct{}

// Ecosystem is npm, not "yarn". A yarn.lock describes npm packages, and
// OSV publishes advisories against the npm ecosystem. Registering this as a
// separate ecosystem would give every component a PURL no advisory could
// ever match, which is the silent-zero failure in a new costume: the scan
// would report components and match nothing.
func (yarnResolver) Ecosystem() string { return model.EcoNPM }

// Priority is declared, not inherited. npm now has three resolvers, and
// the dispatch rule is only safe when each one states its own rank rather
// than falling back on init() order -- which is the thing a future edit
// to the file list would silently reorder. All three read a lockfile and
// report exact resolved versions, so all three are PriorityLockfile;
// they are never ranked against each other because each claims a
// different filename via Handles.
func (yarnResolver) Priority() int { return PriorityLockfile }

// Handles keeps yarn out of the npm resolver's way. Both are the npm
// ecosystem, and both lockfiles are named "package-lock.json"-adjacent
// enough that the fallback path in GetFor would otherwise hand a yarn.lock
// to the npm parser and report a parse error rather than a clean result.
func (yarnResolver) Handles(path string) bool {
	return filepath.Base(path) == "yarn.lock"
}

// yarnEntry is one resolved package: a set of descriptors that all resolve
// to the same version.
//
// A yarn.lock entry key is a comma-separated list of `name@range` requests
// that were collapsed into a single resolution. lodash@^4.0.0 and
// lodash@^4.17.0 usually get their own entries, but when two ranges resolve
// to the same tarball yarn merges them, and the file then says:
//
//	"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
//
// Treating that as one package and the other form as many is the whole
// difference between reporting lodash twice and reporting it once. The
// identity used for the PURL is the name, which is shared by every
// descriptor in the entry.
type yarnEntry struct {
	// name is the package name, scope included.
	name string
	// version is the resolved version, e.g. "7.10.4".
	version string
	// integrity is the sha512-... string, empty in older lockfiles.
	integrity string
	// deps are the entries of the `dependencies:` block, in file order.
	deps []string
	// descriptors are the raw key descriptors that resolved to this
	// entry, kept for Edges, which needs the exact `name@range` strings
	// to look a range up in.
	descriptors []string
	// direct is true when the root package.json asked for this package.
	direct bool
	// optional is true when the entry declares an optionalDependencies
	// block. Tracked because an optional platform-specific package that
	// never installs is not the same finding as a required one, and
	// dropping the distinction here would lose it downstream.
	optional bool
}

// Resolve parses a yarn.lock.
//
// The format is not YAML, despite the extension being .lock, and it is not
// TOML either. It is a bespoke line-oriented format with four rules that a
// naive parser gets wrong:
//
//  1. Keys may be quoted or bare, and scoped names contain an "@" that is
//     not a version separator -- "@babel/core@^7.0.0" is the name
//     "@babel/core" at range "^7.0.0". The LAST "@" in a descriptor splits
//     name from range; the first one may be the scope marker.
//  2. An entry's key line is followed by indented `key value` lines with no
//     `=` and no colon on the value side: `version "7.10.4"`.
//  3. Yarn Berry (v2+) rewrote the file. It uses `version: 1.2.3` with
//     colons, `resolution:` instead of `resolved:`, `checksum:` instead of
//     `integrity:`, and an `__metadata:` block. Both dialects appear in
//     real repositories and both must parse.
//  4. A `dependencies:` block lists ranges, not versions, and those ranges
//     must be resolved through the entry table to get a version. Not
//     resolving them yields edges that point at nothing, which is worse
//     than having no edges at all because it looks like a complete graph.
func (r yarnResolver) Resolve(root, path string) ([]model.Component, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil, err
	}
	entries := parseYarnLock(string(data))
	if len(entries) == 0 {
		return nil, nil
	}

	// Direct dependencies come from the root package.json, which is the only
	// reliable statement of what the project asked for. A yarn.lock entry
	// key is a request range, not a dependency name, so "direct" cannot be
	// derived from the lockfile itself.
	direct := map[string]bool{}
	if b, err := os.ReadFile(filepath.Join(root, filepath.Dir(path), "package.json")); err == nil {
		direct = npmDirectFromPackageJSON(b)
	}

	out := make([]model.Component, 0, len(entries))
	for _, e := range entries {
		c := model.Component{
			Name:      e.name,
			Version:   e.version,
			Ecosystem: model.EcoNPM,
			Purl:      makeSimplePURL("npm", e.name, e.version),
			Direct:    e.direct || direct[e.name],
		}
		if h := parseIntegrity(e.integrity); h != "" {
			c.Hashes = map[string]string{"sha512": h}
		}
		out = append(out, c)
	}
	return Dedupe(out), nil
}

// Edges recovers the dependency graph from the ranges in each entry's
// dependency block, resolved through the entry table.
//
// This is where a range is a liability rather than a fact: "lodash@^4.0.0"
// is not a component, it is a request. The entry table maps every descriptor
// to the version that answered it, so a range is resolvable by looking up
// `name@range`. When a range is not in the table the edge is dropped rather
// than emitted with an empty version, because an edge to a component that
// was never inventoried is a claim this tool cannot support.
func (r yarnResolver) Edges(root, path string) ([]graph.Edge, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil, err
	}
	entries := parseYarnLock(string(data))
	if len(entries) == 0 {
		return nil, nil
	}

	// descriptor -> version, and name -> the version it resolved to.
	byDescriptor := map[string]string{}
	for _, e := range entries {
		for _, d := range e.descriptors {
			byDescriptor[d] = e.version
		}
	}

	var out []graph.Edge
	for _, e := range entries {
		for _, dep := range e.deps {
			name, _ := splitYarnDescriptor(dep)
			// Prefer the exact descriptor; fall back to name-only, which
			// is what a range that no longer matches any entry needs.
			version, ok := byDescriptor[dep]
			if !ok {
				if v, found := yarnByName(entries, name); found {
					version = v
				} else {
					continue
				}
			}
			if version == "" {
				continue
			}
			out = append(out, graph.Edge{
				Parent: makeSimplePURL("npm", e.name, e.version),
				Child:  makeSimplePURL("npm", name, version),
			})
		}
	}
	return out, nil
}

// parseYarnLock turns lockfile text into entries, accepting both the v1 and
// the Berry dialects. Neither uses a real parser -- v1 is a bespoke line
// format and Berry is a YAML-like subset that would need a real YAML engine
// to round-trip correctly -- so this is a line reader with the two
// dialects' differences handled by accepting both separators rather than by
// branching on a version.
func parseYarnLock(s string) []yarnEntry {
	var out []yarnEntry
	var cur *yarnEntry
	// section is the most recent bare `key:` line at indent 1, e.g.
	// "dependencies:" or "optionalDependencies:".
	var section string
	// inDeps records that we are collecting indented list items.
	inDeps := false

	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}

	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// A key line is at indent 0 and ends with ":". Everything else is
		// a field or a list item.
		if indent == 0 {
			flush()
			inDeps = false
			// `section` is deliberately NOT reset here. It is only ever
			// read on the very next branch, immediately after being
			// written (see the indent-1/2 `key:` handler), so a reset
			// here would never be read -- and clearing it would be
			// actively wrong anyway, since `inDeps` is what guards the
			// list items between a key line and the next section.
			if !strings.HasSuffix(trimmed, ":") {
				continue
			}
			key := strings.TrimSuffix(trimmed, ":")
			key = strings.TrimSpace(key)
			if key == "__metadata" {
				// Berry metadata block; its `version: 10` is the
				// lockfile format, not a package version.
				continue
			}
			descs := splitYarnKey(key)
			if len(descs) == 0 {
				continue
			}
			// All descriptors in one key share a name; take the first
			// that yields one.
			name, _ := splitYarnDescriptor(descs[0])
			if name == "" {
				continue
			}
			cur = &yarnEntry{name: name, descriptors: descs}
			continue
		}

		if cur == nil {
			continue
		}

		// A bare `key:` at indent 1 opens a section.
		if indent <= 2 && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			section = strings.TrimSuffix(trimmed, ":")
			inDeps = section == "dependencies" || section == "optionalDependencies"
			if section == "optionalDependencies" {
				cur.optional = true
			}
			continue
		}

		// List items under a dependency block: `range` or `"range"`.
		if inDeps {
			if v := unquoteYarn(trimmed); v != "" {
				cur.deps = append(cur.deps, v)
			}
			continue
		}

		field, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			// v1 style: `version "7.10.4"`, separated by a space.
			field, value, ok = strings.Cut(trimmed, " ")
			if !ok {
				continue
			}
			// A v1 dependency list item is `name "range"`, and it is
			// handled above by the inDeps branch, so reaching here with
			// a quoted second field is a field, not a list.
			if len(value) > 0 && value[0] == '"' && !isYarnField(field) {
				continue
			}
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(field) {
		case "version":
			cur.version = unquoteYarn(value)
		case "integrity":
			cur.integrity = unquoteYarn(value)
		case "checksum":
			// Berry's checksum is "10/<hex>", not a Subresource
			// Integrity string. It is not a CycloneDX hash source,
			// so it is not mapped; the field exists here only so a
			// Berry entry is not mistaken for a malformed v1 one.
		case "resolved", "resolution":
			// The tarball URL. The version has already been read from
			// the explicit `version` field, and re-deriving it from
			// the URL would break on the scoped and prerelease names
			// that appear in real files.
		}
	}
	flush()
	return out
}

// isYarnField reports whether a bare word is one of yarn.lock's field names.
// A v1 dependency line is `name "range"`, so without this check a
// dependency named "version" would be read as a field.
func isYarnField(s string) bool {
	switch s {
	case "version", "resolved", "integrity", "dependencies",
		"optionalDependencies", "peerDependencies":
		return true
	}
	return false
}

// splitYarnKey splits a comma-separated key into its descriptors.
//
// The quoting is the whole difficulty, and it differs by dialect:
//
//	classic  "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
//	         ^ each descriptor is individually quoted
//	Berry    "@babel/code-frame@npm:^7.0.0, @babel/code-frame@npm:^7.10.4":
//	         ^ ONE pair of quotes around the entire key
//
// Berry's form is the one that breaks a per-descriptor reader. A comma
// inside a quoted string is not a separator, so a naive strings.Split on
// "," leaves every descriptor after the first with a leading quote, and
// the last with a trailing one. Worse, treating the whole key as one
// descriptor yields a package NAME containing every range:
//
//	@babel/code-frame@npm:^7.0.0, @babel/code-frame@npm:^7.10.4
//
// which is not a package, produces a PURL matching no OSV advisory, and
// still counts as a component -- an inventory that looks populated and
// cannot match anything.
//
// So: if the key is quoted as a whole, the commas inside it ARE
// separators; if it is a list of individually quoted descriptors, the
// commas between them are. Both are handled, and the outer quotes are
// removed once the key is split rather than per fragment.
func splitYarnKey(key string) []string {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	// A key that is quoted as a whole. Which dialect that is does not
	// matter: the commas inside it are separators, and each part may
	// carry its own pair of quotes on top.
	//
	// Both dialects actually produce this shape. Classic writes
	//
	//	"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
	//
	// which is not one quoted string but two, and Berry writes
	//
	//	"@babel/code-frame@npm:^7.0.0, @babel/code-frame@npm:^7.10.4":
	//
	// which is one. Treating the first as a single quoted string leaves a
	// trailing quote on the first descriptor and a leading one on the
	// last, so each layer has to be peeled separately: the outer pair
	// first, then a per-part unquote.
	if strings.Contains(key, `"`) {
		var out []string
		for _, part := range strings.Split(key, ",") {
			// Each part is trimmed of whitespace and then has every
			// leading and trailing quote removed -- one layer for the
			// classic form (one pair per descriptor) and one for the
			// Berry form (one pair around the whole key), so the same
			// trim handles both without deciding which it is.
			part = strings.TrimSpace(part)
			part = strings.Trim(part, `"`)
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	}
	// Classic: a comma-separated list, each part possibly quoted.
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		v := unquoteYarn(cur.String())
		cur.Reset()
		if v != "" {
			out = append(out, v)
		}
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// splitYarnDescriptor splits `name@range` into its parts.
//
// The last "@" is the separator, not the first: "@babel/core@^7.0.0" is the
// scoped name "@babel/core" at range "^7.0.0". Splitting on the first "@"
// yields name "" and range "babel/core@^7.0.0", which is how a scoped
// package silently disappears from an inventory.
func splitYarnDescriptor(d string) (name, rng string) {
	i := strings.LastIndex(d, "@")
	if i <= 0 {
		// No version range, or a leading "@" with nothing after it.
		return strings.TrimPrefix(d, "@"), ""
	}
	return d[:i], d[i+1:]
}

// unquoteYarn strips one layer of quotes from a lockfile token.
//
// yarn quotes with double quotes and pnpm quotes with SINGLE quotes, for
// the same reason both choose quotes at all: a scoped package name
// contains an "@" and a pnpm key may contain characters YAML would treat
// as structure. A helper that only handles the double-quoted form leaves
// pnpm's keys looking like
//
//	'@pnpm/exe.android-arm64@12.4.2'
//
// whose trailing quote becomes part of the version. The resulting PURL,
// pkg:npm/%27%40pnpm%2Fexe.android-arm64@12.4.2%27, matches no advisory
// in existence, so the package is inventoried and silently never
// vulnerable -- a clean-looking scan over a lockfile nothing understood.
func unquoteYarn(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// yarnByName finds the version a package name resolved to. Used only as a
// fallback when an exact descriptor is absent.
func yarnByName(entries []yarnEntry, name string) (string, bool) {
	for _, e := range entries {
		if e.name == name {
			return e.version, true
		}
	}
	return "", false
}
