// Package resolve turns lockfiles into a flat, de-duplicated component list.
//
// Every ecosystem implements Resolver. Adding a new ecosystem should mean
// writing one new file here and registering it — nothing else in the codebase
// needs to change (see CONTRIBUTING.md).
package resolve

import (
	"errors"
	"sort"

	"github.com/0xsan7/scram/internal/model"
)

// ErrUnsupported is returned when a lockfile's ecosystem has no resolver.
var ErrUnsupported = errors.New("no resolver for ecosystem")

// Resolver reads one lockfile format. Implementations must not shell out to a
// package manager — lockfiles are parsed directly so a scan never needs a
// network fetch or a build step (FR-101).
type Resolver interface {
	// Ecosystem reports the model.Eco* constant this resolver handles.
	Ecosystem() string
	// Resolve returns the components declared by the lockfile at path.
	Resolve(root, path string) ([]model.Component, error)
}

// registry maps an ecosystem name to its resolver.
var registry = map[string]Resolver{}

// Register adds a resolver. Called from each ecosystem's init().
func Register(r Resolver) {
	registry[r.Ecosystem()] = r
}

// Get returns the resolver for an ecosystem.
func Get(eco string) (Resolver, error) {
	r, ok := registry[eco]
	if !ok {
		return nil, ErrUnsupported
	}
	return r, nil
}

// Supported lists every registered ecosystem, sorted.
func Supported() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Dedupe merges components that resolve to the same PURL, which happens when
// several lockfiles in a monorepo share a dependency at the same version.
// The first occurrence wins so ordering stays stable across runs.
func Dedupe(in []model.Component) []model.Component {
	seen := make(map[string]bool, len(in))
	out := make([]model.Component, 0, len(in))
	for _, c := range in {
		if seen[c.Purl] {
			continue
		}
		seen[c.Purl] = true
		out = append(out, c)
	}
	// Sort by ecosystem then name so output is reproducible run-to-run, which
	// golden-file tests and SARIF diffs both depend on.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
