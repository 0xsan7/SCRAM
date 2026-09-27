package graph

import (
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// The fixture models the shape that matters: one package nested under another
// at a DIFFERENT version than the top-level one, which is the only case where
// npm's install path encodes real parentage.
func testComponents() []model.Component {
	return []model.Component{
		{Purl: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		{Purl: "pkg:npm/body-parser@1.20.1", Name: "body-parser", Version: "1.20.1", Ecosystem: "npm"},
		{Purl: "pkg:npm/qs@6.11.0", Name: "qs", Version: "6.11.0", Ecosystem: "npm"},
		{Purl: "pkg:npm/qs@6.5.2", Name: "qs", Version: "6.5.2", Ecosystem: "npm"},
	}
}

func TestNpmParentOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"node_modules/express", ""},
		{"node_modules/express/node_modules/qs", "npm:express"},
		{"node_modules/@scope/a/node_modules/b", "npm:@scope/a"},
		{"node_modules/a/node_modules/b/node_modules/c", "npm:b"},
	}
	for _, c := range cases {
		if got := NpmParentOf(c.in, ""); got != c.want {
			t.Errorf("NpmParentOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildResolvesNestedEdges(t *testing.T) {
	comps := testComponents()
	// express -> qs@6.5.2, recovered from the install path.
	raw := []Edge{{Parent: "npm:express@4.18.2", Child: "npm:qs@6.5.2"}}
	g := Build(comps, raw)

	if !g.HasEdges() {
		t.Fatal("graph has no edges; the nested parent was not recovered")
	}
	path := g.PathTo("pkg:npm/qs@6.5.2")
	if len(path) != 2 {
		t.Fatalf("path to nested qs = %v, want [express qs@6.5.2]", path)
	}
	if path[0] != "pkg:npm/express@4.18.2" || path[1] != "pkg:npm/qs@6.5.2" {
		t.Errorf("path = %v", path)
	}
	// The top-level qs@6.11.0 is a root, not a dependent of express.
	if p := g.PathTo("pkg:npm/qs@6.11.0"); len(p) != 1 {
		t.Errorf("path to top-level qs = %v, want itself (a root)", p)
	}
}

func TestDependents(t *testing.T) {
	g := Build(testComponents(), []Edge{{Parent: "npm:express@4.18.2", Child: "npm:qs@6.5.2"}})
	if got := g.Dependents("pkg:npm/qs@6.5.2"); len(got) != 0 {
		t.Errorf("dependents of a leaf = %v, want none", got)
	}
	deps := g.Dependents("pkg:npm/express@4.18.2")
	if len(deps) != 1 || deps[0] != "pkg:npm/qs@6.5.2" {
		t.Errorf("dependents of express = %v", deps)
	}
}

// An edge naming a component the scan did not record must be dropped, not
// rendered as a phantom node.
func TestBuildDropsUnknownEndpoints(t *testing.T) {
	g := Build(testComponents(), []Edge{
		{Parent: "npm:ghost@1.0.0", Child: "npm:qs@6.5.2"},
		{Parent: "npm:express@4.18.2", Child: "npm:phantom@9.9.9"},
	})
	if g.HasEdges() {
		t.Errorf("edges to unknown components were kept: %v", g.Parents)
	}
}

// A hand-edited or maliciously cyclic lockfile must not hang the CLI.
func TestPathToTerminatesOnCycle(t *testing.T) {
	comps := []model.Component{
		{Purl: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm"},
		{Purl: "pkg:npm/b@1", Name: "b", Version: "1", Ecosystem: "npm"},
	}
	g := Build(comps, []Edge{
		{Parent: "npm:a@1", Child: "npm:b@1"},
		{Parent: "npm:b@1", Child: "npm:a@1"},
	})
	// Every node has a parent, so there is no root; this must return rather
	// than loop forever.
	_ = g.PathTo("pkg:npm/a@1")
	_ = g.Dependents("pkg:npm/a@1")
}

// A component with no recoverable parentage must be reported as "unknown",
// not as "direct". Conflating those is a confident false claim, and the CLI
// text is the only place that distinction is visible.
func TestNoEdgesIsDistinguishableFromDirect(t *testing.T) {
	comps := []model.Component{
		{Purl: "pkg:pypi/pyyaml@5.1", Name: "pyyaml", Version: "5.1", Ecosystem: "pypi"},
	}
	g := Build(comps, nil)
	if g.HasEdges() {
		t.Fatal("expected no edges from an ecosystem that records no parentage")
	}
	// A root is a root whether or not we could have said more -- but the graph
	// must report HasEdges() false so the caller can say "unknown" instead.
	if len(g.Roots()) != 1 {
		t.Errorf("roots = %v, want the single component", g.Roots())
	}
}

func TestSelfEdgeIgnored(t *testing.T) {
	g := Build(testComponents(), []Edge{{Parent: "npm:qs@6.11.0", Child: "npm:qs@6.11.0"}})
	if g.HasEdges() {
		t.Error("a self-edge was recorded")
	}
}
