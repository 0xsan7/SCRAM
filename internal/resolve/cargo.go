package resolve

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/0xsan7/scram/internal/model"
)

func init() { Register(cargoResolver{}) }

type cargoResolver struct{}

func (cargoResolver) Ecosystem() string { return model.EcoCargo }

func (cargoResolver) Handles(path string) bool {
	return filepath.Base(path) == "Cargo.lock"
}

// cargoPackage is one [[package]] entry from a Cargo.lock.
type cargoPackage struct {
	name    string
	version string
	// source is the `source =` line: a registry index, a git URL, or
	// absent for a path/workspace member.
	source string
	// checksum is the crates.io content hash.
	checksum string
	// local is true when there is no `source` line, i.e. the package is a
	// member of the workspace being scanned rather than a fetched
	// dependency.
	local bool
	// deps are the entries of the `dependencies` array, which name
	// packages as either "name" or "name version" when two versions of
	// the same crate are present.
	deps []string
}

// Resolve parses a Cargo.lock.
//
// The format is TOML, but it is not read with a TOML parser, for a reason
// worth stating rather than assuming: this is an untrusted input, and the
// only thing a security tool needs from a lockfile is a list of name and
// version pairs. A full TOML parse accepts far more grammar than that --
// inline tables, dotted keys, multi-line strings, date-time values -- and
// every one of those is a place for a parser to allocate on the strength
// of a number the attacker chose. The line reader below has no such
// surface.
//
// The format is deceptively regular. Each dependency is a [[package]]
// block with `name`, `version`, optionally `source`, `checksum`, and
// optionally a `dependencies` array. Three details decide whether a
// parser is right or merely close:
//
//  1. A `version = 4` line at the top of the file is the LOCKFILE format
//     version, not a package version. Reading it as a package produces a
//     phantom component called "version".
//  2. A package with no `source` line is a workspace member or a path
//     dependency, not a registry crate. rust-lang's own Cargo.lock has 98
//     of these out of 575. They are still real components of the build,
//     so they are reported, but they are not third-party code and are
//     marked local so a later stage can tell them apart.
//  3. The `dependencies` array disambiguates duplicate names with a
//     version: "itoa 1.0.18" rather than "itoa". Taking the whole token
//     as a name gives a component called "itoa 1.0.18", which matches
//     nothing.
func (r cargoResolver) Resolve(root, path string) ([]model.Component, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil, err
	}
	pkgs := parseCargoLock(string(data))
	if len(pkgs) == 0 {
		return nil, nil
	}

	// Direct dependencies come from Cargo.toml's [dependencies]. A
	// Cargo.lock records every crate in the graph, direct or not, and
	// nothing in it distinguishes the two.
	direct := cargoDirectFromManifest(root, filepath.Dir(path))

	out := make([]model.Component, 0, len(pkgs))
	for _, p := range pkgs {
		// crates.io has no namespace, so the PURL is
		// pkg:cargo/name@version.
		c := model.Component{
			Name:      p.name,
			Version:   p.version,
			Ecosystem: model.EcoCargo,
			Purl:      makeSimplePURL("cargo", p.name, p.version),
			Direct:    p.local || direct[p.name],
		}
		if p.checksum != "" {
			// Cargo's checksum field is a bare SHA-256 hex with no
			// algorithm prefix.
			c.Hashes = map[string]string{"sha256": p.checksum}
		}
		out = append(out, c)
	}
	return Dedupe(out), nil
}

// parseCargoLock reads the [[package]] blocks.
func parseCargoLock(s string) []cargoPackage {
	var out []cargoPackage
	var cur *cargoPackage
	inDeps := false
	// atTopVersion guards the `version = 4` line, which is the lockfile
	// format version and appears before any [[package]] block.
	sawBlock := false

	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}

	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if trimmed == "[[package]]" {
			flush()
			cur = &cargoPackage{}
			sawBlock = true
			inDeps = false
			continue
		}
		// A `[metadata]` table (lockfile v1/v2) contains a `checksum
		// <name> <version> <hash>` line per package. Those are not
		// [[package]] blocks and must not be read as one.
		if strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "[[") {
			flush()
			inDeps = false
			continue
		}
		if cur == nil {
			continue
		}

		if trimmed == "dependencies = [" {
			inDeps = true
			continue
		}
		if inDeps {
			if trimmed == "]" {
				inDeps = false
				continue
			}
			// "serde", or "itoa 1.0.18" when the name is ambiguous.
			if name, _, ok := strings.Cut(trimmed, " "); ok && name != "" {
				cur.deps = append(cur.deps, name)
			} else if trimmed != "" {
				cur.deps = append(cur.deps, unquoteYarn(trimmed))
			}
			continue
		}

		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "name":
			cur.name = unquoteYarn(value)
		case "version":
			if !sawBlock {
				// The lockfile format version. Recorded nowhere,
				// because a component named "version" is not a thing.
				continue
			}
			cur.version = unquoteYarn(value)
		case "source":
			cur.source = unquoteYarn(value)
		case "checksum":
			cur.checksum = unquoteYarn(value)
		}
	}
	flush()
	// A package with no `source` is a path/workspace member. Applied
	// after parsing so the rule is stated once.
	for i := range out {
		out[i].local = out[i].source == ""
	}
	return out
}

// cargoDirectFromManifest reads [dependencies] from Cargo.toml.
//
// Section headers are matched by prefix because Cargo allows several
// dependency tables: [dependencies], [dev-dependencies],
// [build-dependencies], and [target.'cfg(unix)'.dependencies].
func cargoDirectFromManifest(root, dir string) map[string]bool {
	b, err := os.ReadFile(filepath.Join(root, dir, "Cargo.toml"))
	if err != nil {
		return map[string]bool{}
	}
	out := map[string]bool{}
	inDeps := false
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inDeps = strings.HasSuffix(trimmed, "dependencies]")
			continue
		}
		if !inDeps {
			continue
		}
		// name = "1.0"  /  name = { version = "1.0" }
		name, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		n := strings.TrimSpace(name)
		if n == "" {
			continue
		}
		// Table form has a trailing "{" on the value side; the bare form
		// does not, and both give the same name.
		out[n] = true
	}
	return out
}
