package graph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// EdgeProvider is implemented by resolvers that can recover parentage.
type EdgeProvider interface {
	// Edges returns raw "npm:<name>" -> "npm:<name>" pairs discovered in the
	// lockfile at path. Names are not versions: the path does not carry a
	// version, and resolving it needs the component set.
	Edges(root, path string) (pairs []Edge, err error)
}

// NpmEdges reads edges out of a package-lock.json at the given path. It is
// exported so the npm resolver can satisfy EdgeProvider without the graph
// package importing resolve (which would be a cycle).
func NpmEdges(root, path string) ([]Edge, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil, err
	}
	var lock struct {
		LockfileVersion int                        `json:"lockfileVersion"`
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		Packages        map[string]struct {
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var out []Edge
	if len(lock.Packages) > 0 {
		out = edgesFromPackages(lock.Packages)
	} else {
		out = edgesFromV1(lock.Dependencies)
	}
	return out, nil
}

// edgesFromPackages derives parentage from install paths. For
// "node_modules/a/node_modules/b", the parent is the path up to the previous
// node_modules segment, and the declared dependencies give a second,
// independent route to the same answer -- both are recorded so a package that
// is declared as a dependency of its parent AND nested under it is not
// double-counted downstream.
func edgesFromPackages(pkgs map[string]struct {
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}) []Edge {
	var out []Edge
	for key, pkg := range pkgs {
		if key == "" {
			continue
		}
		parentName := NpmParentOf(key, "")
		if parentName == "" {
			continue // direct dependency: a root, no edge
		}
		parentPurl := parentName
		if pv, ok := versionOfKey(pkgs, parentName); ok {
			parentPurl = parentName + "@" + pv
		}
		childName := NameFromInstallPath(key)
		if childName == "" {
			continue
		}
		childPurl := childName
		if pkg.Version != "" {
			childPurl = childName + "@" + pkg.Version
		}
		// NpmParentOf already returns an "npm:"-prefixed identifier, so only
		// the child needs the prefix added here. Prefixing both produces
		// "npm:npm:express", which matches nothing in the component index and
		// silently yields an empty graph.
		out = append(out, Edge{Parent: parentPurl, Child: "npm:" + childPurl})
	}
	return out
}

// versionOfKey recovers the version a parent name resolves to, by finding the
// install path that names it. Returns false when the parent is not itself a
// recorded package (it can be the root project, or a dev-only subtree).
func versionOfKey(pkgs map[string]struct {
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}, parentName string) (string, bool) {
	short := strings.TrimPrefix(parentName, "npm:")
	want := short
	for key, pkg := range pkgs {
		if key == "" || pkg.Version == "" {
			continue
		}
		if NameFromInstallPath(key) == want {
			return pkg.Version, true
		}
	}
	return "", false
}

// edgesFromV1 walks the nested legacy tree. Here the parentage is explicit:
// we recursed into it, so it is the parent.
func edgesFromV1(deps map[string]json.RawMessage) []Edge {
	var out []Edge
	var walk func(m map[string]json.RawMessage, parent string, depth int)
	walk = func(m map[string]json.RawMessage, parent string, depth int) {
		// Bound the recursion. A hand-edited or maliciously deep lockfile
		// should not be able to blow the stack.
		if depth > 64 {
			return
		}
		for name, raw := range m {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			if parent != "" && d.Version != "" {
				out = append(out, Edge{
					Parent: "npm:" + parent + "@" + d.Version,
					Child:  "npm:" + name + "@" + d.Version,
				})
			}
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies, name, depth+1)
			}
		}
	}
	walk(deps, "", 0)
	return out
}
