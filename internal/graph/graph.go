// Package graph reconstructs the dependency edges that lockfiles imply.
//
// The resolvers in package resolve return a flat, de-duplicated component
// list, which is all the SBOM needs but is not enough to answer "how did this
// package get into my tree?". A lockfile does record that relationship, in
// two different shapes depending on its version:
//
//   - npm v2/v3: the KEY of the "packages" map is the install path, so
//     "node_modules/a/node_modules/b" means b is nested under a. The parent is
//     derivable from the path alone, with no extra field.
//   - npm v1: the "dependencies" value is a nested tree, so the parent is
//     whatever we recursed into.
//
// PyPI requirements.txt is a flat list with no edges at all, and Go's go.sum
// records module checksums rather than parentage. Both are reported as
// isolated nodes rather than guessed at -- an invented edge would be worse
// than an honest "we do not know".
package graph

import (
	"sort"
	"strings"

	"github.com/0xsan7/scram/internal/model"
)

// Edge is a parent -> child relationship between two components.
type Edge struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
}

// Graph is an adjacency map keyed by child PURL. Roots are components with no
// recorded parent.
type Graph struct {
	// Parents maps a child PURL to its parent PURLs. A component can have
	// several parents when it is depended on from more than one place.
	Parents map[string][]string `json:"parents"`
	// Children is the reverse index, kept in sync so callers do not rebuild it.
	Children map[string][]string `json:"children"`
	// Known holds every PURL that appeared in the component set, so an edge
	// pointing at something the scan did not record can be dropped rather than
	// rendered as a phantom node.
	Known map[string]bool `json:"-"`
}

// New returns an empty graph seeded with the given components as known nodes.
func New(comps []model.Component) *Graph {
	g := &Graph{
		Parents:  map[string][]string{},
		Children: map[string][]string{},
		Known:    make(map[string]bool, len(comps)),
	}
	for _, c := range comps {
		g.Known[c.Purl] = true
	}
	return g
}

// Add records a parent -> child edge. Edges are deduplicated, and any edge
// whose endpoints are not in the known component set is ignored: a lockfile
// can reference a dev-only or optional dependency that the resolver
// deliberately skipped, and rendering it would overstate the tree.
func (g *Graph) Add(parent, child string) {
	if parent == "" || child == "" || parent == child {
		return
	}
	if !g.Known[parent] || !g.Known[child] {
		return
	}
	if contains(g.Parents[child], parent) {
		return
	}
	g.Parents[child] = append(g.Parents[child], parent)
	g.Children[parent] = append(g.Children[parent], child)
}

// Roots returns every known component with no recorded parent, sorted. These
// are the packages the repo asked for directly, so they are where a blast
// radius walk starts.
func (g *Graph) Roots() []string {
	var out []string
	for purl := range g.Known {
		if len(g.Parents[purl]) == 0 {
			out = append(out, purl)
		}
	}
	sort.Strings(out)
	return out
}

// PathTo returns the shortest dependency path from any root to target, or nil
// if the target is unreachable. BFS rather than DFS so the result is the
// most direct explanation, not just the first one found.
func (g *Graph) PathTo(target string) []string {
	if !g.Known[target] {
		return nil
	}
	if len(g.Parents[target]) == 0 {
		return []string{target}
	}
	// visited guards against cycles. A malformed or hand-edited lockfile can
	// easily produce one, and an unbounded walk would hang the CLI.
	visited := map[string]bool{target: true}
	queue := [][]string{{target}}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		head := path[len(path)-1]
		for _, parent := range g.Parents[head] {
			if visited[parent] {
				continue
			}
			visited[parent] = true
			next := append(append([]string{}, path...), parent)
			if len(g.Parents[parent]) == 0 {
				// Reached a root. path is target-first, so reverse it.
				return reverse(next)
			}
			queue = append(queue, next)
		}
	}
	return nil
}

// Dependents returns every component that would be affected if target were
// removed, transitively. This is the "what breaks if I patch or drop this"
// question, which is the other half of blast radius.
func (g *Graph) Dependents(target string) []string {
	if !g.Known[target] {
		return nil
	}
	seen := map[string]bool{target: true}
	var out []string
	queue := []string{target}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, child := range g.Children[cur] {
			if seen[child] {
				continue
			}
			seen[child] = true
			out = append(out, child)
			queue = append(queue, child)
		}
	}
	sort.Strings(out)
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func reverse(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// NpmParentOf derives the parent PURL from an npm v2/v3 install path.
//
//	"node_modules/a"                    -> ""   (direct)
//	"node_modules/a/node_modules/b"      -> a
//	"node_modules/@scope/a/node_modules/b" -> @scope/a
//
// Scoped names are why this walks segment by segment instead of splitting on
// "node_modules/": the separator appears inside the name, not only between
// packages.
func NpmParentOf(installPath, name string) string {
	const marker = "node_modules/"
	// Everything before the LAST node_modules/ segment is the parent chain.
	idx := strings.LastIndex(installPath, marker)
	if idx <= 0 {
		return ""
	}
	parentPath := strings.TrimSuffix(installPath[:idx], "/")
	parentName := NameFromInstallPath(parentPath)
	if parentName == "" {
		return ""
	}
	// The parent version is unknown from the path alone; callers that need a
	// full PURL resolve it against the known component set.
	return "npm:" + parentName
}

// NameFromInstallPath extracts a package name from an npm install path.
func NameFromInstallPath(p string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(p, marker)
	if i < 0 {
		return ""
	}
	rest := p[i+len(marker):]
	if rest == "" {
		return ""
	}
	if strings.HasPrefix(rest, "@") {
		if slash := strings.Index(rest, "/"); slash > 0 {
			return rest
		}
	}
	return rest
}
