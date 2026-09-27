package graph

import (
	"testing"
)

// Probes the real fixture through the same entry point the resolver uses, so
// a regression in edge extraction shows up here rather than only when a user
// runs `scram why`.
func TestNpmEdgesOnNestedFixture(t *testing.T) {
	edges, err := NpmEdges("../../testdata/fixtures/nested", "package-lock.json")
	if err != nil {
		t.Fatalf("NpmEdges: %v", err)
	}
	if len(edges) == 0 {
		t.Fatal("no edges extracted from a lockfile that clearly nests one package")
	}
	t.Logf("extracted %d edges:", len(edges))
	for _, e := range edges {
		t.Logf("  %s -> %s", e.Parent, e.Child)
	}
	found := false
	for _, e := range edges {
		if e.Parent == "npm:express@4.18.2" && e.Child == "npm:qs@6.5.2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected express@4.18.2 -> qs@6.5.2 edge, got %v", edges)
	}
}
