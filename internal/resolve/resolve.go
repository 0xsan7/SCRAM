// Package resolve turns lockfiles into a flat, de-duplicated component list.
//
// Every ecosystem implements Resolver. Adding a new ecosystem should mean
// writing one new file here and registering it — nothing else in the codebase
// needs to change (see CONTRIBUTING.md).
package resolve

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0xsan7/scram/internal/model"
)

// ErrUnsupported is returned when a lockfile's ecosystem has no resolver.
var ErrUnsupported = errors.New("no resolver for ecosystem")

// ErrSilentZero is returned when a lockfile was found and opened but produced
// no components, and the file itself declares dependencies.
//
// This is the single most dangerous failure mode a supply-chain scanner can
// have, and it is the shared root cause of D01, D22, and D23: a partial or
// wholly failed parse returned an empty slice, and an empty slice was
// indistinguishable downstream from a repository with genuinely no
// dependencies. The scan then reported CLEAN and exited 0.
//
// Concretely, in the real cases:
//
//	D01  npm v3 lockfile whose top-level "dependencies" key was typed wrongly
//	D22  npm lockfile where one package had "license": ["MIT","Apache2"],
//	     failing json.Unmarshal for the whole 1676-package document
//	D23  PyPI requirements.txt whose regex matched only "==", discarding all
//	     22 of prefect's ">=" requirements
//
// A resolver must therefore never return (empty, nil) for a file that declares
// dependencies. Returning an explicit error is correct; returning an empty
// slice is not.
var ErrSilentZero = errors.New("lockfile declares dependencies but resolver returned none")

// EmptyDependencyCountError reports the silent-zero condition with enough
// context to act on, including the counts that prove the file is not empty.
type EmptyDependencyCountError struct {
	Path      string
	Ecosystem string
	// Declared is the number of dependency declarations found by inspecting
	// the file independently of the resolver. It is what makes this an error
	// rather than an observation.
	Declared int
}

func (e *EmptyDependencyCountError) Error() string {
	return fmt.Sprintf("%s: %s lockfile declares %d dependencies but the resolver returned 0 "+
		"(this is a parser bug, not an empty project; treating it as clean would be a false negative)",
		e.Path, e.Ecosystem, e.Declared)
}

func (e *EmptyDependencyCountError) Is(target error) bool { return target == ErrSilentZero }

// ResolveFile is the only sanctioned way to turn a lockfile into components.
//
// It wraps Resolver.Resolve with the silent-zero invariant: if the file
// declares dependencies but the resolver returns none, the caller gets an
// error rather than an empty list. Every caller goes through this instead of
// calling Resolve directly, so the guard cannot be bypassed by a new
// call site.
//
// A genuinely empty lockfile (ceph commits an 83-byte one with "packages":
// {}) still returns zero components and no error, because that is a true
// observation about the project.
func ResolveFile(r Resolver, root, path string) ([]model.Component, error) {
	comps, err := r.Resolve(root, path)
	if err != nil {
		return nil, err
	}
	if len(comps) == 0 {
		// The count must be read from the SAME file the resolver read. Resolve
		// takes `path` relative to `root`, so resolve it before re-reading:
		// passing the bare filename would make the counter miss the file, and
		// a guard that silently disables itself is worse than no guard.
		full := path
		if !filepath.IsAbs(full) {
			full = filepath.Join(root, path)
		}
		if n := declaredDependencies(full); n > 0 {
			return nil, &EmptyDependencyCountError{
				Path:      full,
				Ecosystem: r.Ecosystem(),
				Declared:  n,
			}
		}
	}
	return comps, nil
}

// declaredDependencies counts dependency declarations in a lockfile without
// using any resolver, so the check cannot be fooled by the same bug that
// produced the empty result. Returns 0 for an empty or unreadable file, which
// leaves a genuine parse error to surface as an error instead.
func declaredDependencies(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	switch filepath.Base(path) {
	case "package-lock.json":
		var doc struct {
			Packages     map[string]json.RawMessage `json:"packages"`
			Dependencies map[string]json.RawMessage `json:"dependencies"`
		}
		if json.Unmarshal(b, &doc) != nil {
			return 0
		}
		n := len(doc.Dependencies)
		for k := range doc.Packages {
			// The "" key is the project itself, not a dependency.
			if k != "" {
				n++
			}
		}
		// A v2 lockfile has both maps describing the same tree; the smaller
		// count is the real one, so take whichever key set is smaller.
		if len(doc.Packages) > 0 && len(doc.Dependencies) > 0 {
			keys := 0
			for k := range doc.Packages {
				if k != "" {
					keys++
				}
			}
			if len(doc.Dependencies) < keys {
				return len(doc.Dependencies)
			}
			return keys
		}
		return n
	case "poetry.lock":
		return countLines(b, func(l string) bool {
			return strings.HasPrefix(l, "[[package]]") || strings.HasPrefix(l, "name = ")
		})
	case "go.sum":
		// Every non-comment, non-blank line is module@version.
		return countLines(b, func(l string) bool {
			l = strings.TrimSpace(l)
			return l != "" && !strings.HasPrefix(l, "//")
		})
	default:
		// Text formats (requirements*.txt, pyproject.toml, go.mod): any line
		// that is not blank, not a comment, and not a pip option.
		return countLines(b, func(l string) bool {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
				return false
			}
			return !strings.Contains(t, "://")
		})
	}
}

func countLines(b []byte, match func(string) bool) int {
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if match(line) {
			n++
		}
	}
	return n
}

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
