package graph

import (
	"github.com/0xsan7/scram/internal/model"
	"reflect"
	"testing"
)

func TestAuditDependentsWalkParents(t *testing.T) {
	comps := []model.Component{{Purl: "a", Name: "a", Version: "1", Ecosystem: "npm"}, {Purl: "b", Name: "b", Version: "1", Ecosystem: "npm"}, {Purl: "c", Name: "c", Version: "1", Ecosystem: "npm"}}
	g := New(comps)
	g.Add("a", "b")
	g.Add("b", "c")
	if got := g.Dependents("c"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("dependents of leaf=%v, want its consumers a,b", got)
	}
	if got := g.Dependents("a"); len(got) != 0 {
		t.Fatalf("root consumers=%v, want none", got)
	}
}
