package graph

import (
	"strings"

	"github.com/0xsan7/scram/internal/model"
)

// Build reconstructs the dependency graph for a scanned tree.
//
// raw edges arrive as "npm:<name>@<version>" strings because that is the most
// the lockfile gives us. The component list is the authority on which
// (name, version) pairs actually exist, so every edge endpoint is resolved
// against it and any endpoint that does not match a scanned component is
// dropped. That drop is the point: a lockfile can name a dev-only or
// optional package the resolver skipped, and drawing an edge to something
// absent would overstate the tree.
//
// Projects are passed in as (root, lockfile-relative-path) pairs so each
// ecosystem's own lockfile contributes its own edges without edges leaking
// between packages in a monorepo.
func Build(comps []model.Component, rawEdges []Edge) *Graph {
	g := New(comps)
	index := purlIndex(comps)
	for _, e := range rawEdges {
		parentPurl, ok := index[e.Parent]
		if !ok {
			continue
		}
		childPurl, ok := index[e.Child]
		if !ok {
			continue
		}
		g.Add(parentPurl, childPurl)
	}
	return g
}

// purlIndex maps the edge identifier format ("npm:name@version") onto the
// canonical PURL used everywhere else. Falls back to a name-only match when
// the version is absent, which is the right behaviour when a lockfile records
// a parent's existence but not which version of it is installed.
func purlIndex(comps []model.Component) map[string]string {
	byFull := make(map[string]string, len(comps))
	byName := make(map[string]string, len(comps))
	for _, c := range comps {
		byFull[c.Ecosystem+":"+c.Name+"@"+c.Version] = c.Purl
		// First writer wins so the mapping is stable when a name appears at
		// several versions (npm commonly nests two versions of one package).
		if _, exists := byName[c.Ecosystem+":"+c.Name]; !exists {
			byName[c.Ecosystem+":"+c.Name] = c.Purl
		}
	}
	return indexWithFallback(byFull, byName)
}

func indexWithFallback(byFull, byName map[string]string) map[string]string {
	out := make(map[string]string, len(byFull)+len(byName))
	for k, v := range byFull {
		out[k] = v
	}
	for k, v := range byName {
		out[k] = v
	}
	return out
}

// HasEdges reports whether any parentage was recovered. False means the tree
// is genuinely flat, and the caller should say so rather than printing a
// one-node "path".
func (g *Graph) HasEdges() bool { return len(g.Parents) > 0 }

// ShortName renders a PURL as "name@version" for terminal output.
func ShortName(purl string) string {
	i := strings.LastIndex(purl, "@")
	// Guard against a leading "@" from a scoped npm name with no version.
	if i <= 0 {
		return purl
	}
	return purl[i+1:]
}

// Name renders a PURL as just the package name, without the version.
func Name(purl string) string {
	if i := strings.Index(purl, "/"); i >= 0 {
		if j := strings.Index(purl[i:], "@"); j > 0 {
			return purl[i+1 : i+j]
		}
		return purl[i+1:]
	}
	return ShortName(purl)
}
