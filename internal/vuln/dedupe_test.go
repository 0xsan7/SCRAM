package vuln

import (
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// TestDedupeMergesAliasLinkedRecords covers FR-203: the same bug often
// appears under both a GHSA id and a CVE id, and they must collapse into one
// finding rather than being double-counted.
func TestDedupeMergesAliasLinkedRecords(t *testing.T) {
	in := []model.Vuln{
		{ID: "GHSA-xxxx-yyyy-zzzz", Source: "ghsa", CVSSv3: 0, Aliases: []string{"CVE-2021-23337"}},
		{ID: "CVE-2021-23337", Source: "nvd", CVSSv3: 7.2, Aliases: []string{"GHSA-xxxx-yyyy-zzzz"}},
	}
	out := Dedupe(in)
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1 after merging: %+v", len(out), out)
	}
	// FR-203 says to prefer the source with the most complete CVSS data.
	if out[0].CVSSv3 != 7.2 {
		t.Errorf("CVSS: got %.1f, want 7.2 (the richer record should win)", out[0].CVSSv3)
	}
}

func TestDedupeKeepsDistinctRecords(t *testing.T) {
	in := []model.Vuln{
		{ID: "CVE-A", CVSSv3: 5.0},
		{ID: "CVE-B", CVSSv3: 7.0},
	}
	if out := Dedupe(in); len(out) != 2 {
		t.Errorf("got %d records, want 2 (unrelated vulns must not merge)", len(out))
	}
}

// TestDedupeTakesHighestCVSSAcrossGroup checks that merging never loses
// severity data, even when the winning record came from a source that didn't
// populate CVSS.
func TestDedupeTakesHighestCVSSAcrossGroup(t *testing.T) {
	in := []model.Vuln{
		{ID: "GHSA-a", Source: "ghsa", Summary: "a summary", CVSSv3: 0},
		{ID: "CVE-a", Source: "nvd", CVSSv3: 9.8, Aliases: []string{"GHSA-a"}},
	}
	out := Dedupe(in)
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1", len(out))
	}
	if out[0].CVSSv3 != 9.8 {
		t.Errorf("CVSS: got %.1f, want 9.8", out[0].CVSSv3)
	}
	// The richer record's summary should survive.
	if out[0].Summary == "" {
		t.Error("summary lost during the merge")
	}
}

func TestDedupePreservesAliases(t *testing.T) {
	in := []model.Vuln{
		{ID: "GHSA-x", Aliases: []string{"CVE-1", "SNYK-1"}},
		{ID: "CVE-1", Aliases: []string{"GHSA-x"}},
	}
	out := Dedupe(in)
	if len(out) != 1 {
		t.Fatalf("got %d, want 1", len(out))
	}
	// The record's own ID must not appear in its own alias list.
	for _, a := range out[0].Aliases {
		if a == out[0].ID {
			t.Errorf("alias list contains the record's own id %q", a)
		}
	}
	found := false
	for _, a := range out[0].Aliases {
		if a == "SNYK-1" {
			found = true
		}
	}
	if !found {
		t.Errorf("alias SNYK-1 was lost in the merge; got %v", out[0].Aliases)
	}
}

// TestDedupeSortsWorstFirst keeps reports and SARIF files leading with what
// matters most.
func TestDedupeSortsWorstFirst(t *testing.T) {
	in := []model.Vuln{
		{ID: "CVE-LOW", CVSSv3: 2.0},
		{ID: "CVE-HIGH", CVSSv3: 9.0},
		{ID: "CVE-MID", CVSSv3: 5.0},
	}
	out := Dedupe(in)
	if out[0].ID != "CVE-HIGH" {
		t.Errorf("first record: got %s, want CVE-HIGH", out[0].ID)
	}
}

func TestDedupeEmptyAndSingle(t *testing.T) {
	if out := Dedupe(nil); len(out) != 0 {
		t.Errorf("nil input: got %d records, want 0", len(out))
	}
	one := []model.Vuln{{ID: "CVE-A", CVSSv3: 5.0}}
	if out := Dedupe(one); len(out) != 1 || out[0].ID != "CVE-A" {
		t.Errorf("single input: got %+v", out)
	}
}

// TestDedupeChainMerging covers a transitive case: A aliases B, B aliases C,
// so all three describe one vulnerability and must all collapse.
func TestDedupeChainMerging(t *testing.T) {
	in := []model.Vuln{
		{ID: "GHSA-1", Aliases: []string{"CVE-2"}},
		{ID: "CVE-2", Aliases: []string{"SNYK-3"}},
		{ID: "SNYK-3"},
	}
	out := Dedupe(in)
	if len(out) != 1 {
		t.Errorf("got %d records, want 1 (a chain of aliases is one vulnerability): %+v", len(out), out)
	}
}

func TestDedupeComponents(t *testing.T) {
	comps := []model.Component{{
		Purl: "pkg:npm/x@1.0.0", Name: "x",
		Vulnerabilities: []model.Vuln{
			{ID: "GHSA-a", Aliases: []string{"CVE-a"}, CVSSv3: 0},
			{ID: "CVE-a", CVSSv3: 6.0},
		},
	}}
	DedupeComponents(comps)
	if len(comps[0].Vulnerabilities) != 1 {
		t.Errorf("got %d vulns, want 1 after dedupe", len(comps[0].Vulnerabilities))
	}
}

func TestAsCVEFindsAlias(t *testing.T) {
	// GHSA-primary records carry the CVE as an alias, which is what makes
	// EPSS coverage complete.
	v := model.Vuln{ID: "GHSA-x", Aliases: []string{"CVE-2021-23337"}}
	if cve, ok := asCVE(v); !ok || cve != "CVE-2021-23337" {
		t.Errorf("got (%q, %v), want (CVE-2021-23337, true)", cve, ok)
	}
	// No CVE anywhere means no EPSS lookup is possible.
	if _, ok := asCVE(model.Vuln{ID: "SNYK-X", Aliases: []string{"GHSA-Y"}}); ok {
		t.Error("expected no CVE to be found")
	}
}

func TestMergeAliases(t *testing.T) {
	got := mergeAliases([]string{"CVE-1"}, []string{"CVE-1", "SNYK-2"}, "GHSA-self")
	if len(got) != 2 {
		t.Errorf("got %v, want 2 unique aliases", got)
	}
	for _, a := range got {
		if a == "GHSA-self" {
			t.Error("the record's own id must be excluded from its aliases")
		}
	}
	// Sorted for reproducible output.
	if got[0] != "CVE-1" || got[1] != "SNYK-2" {
		t.Errorf("aliases not sorted: %v", got)
	}
	if mergeAliases(nil, nil, "X") != nil {
		t.Error("expected nil when there are no aliases")
	}
}
