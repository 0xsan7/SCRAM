package score

import (
	"math"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

func f(v float64) *float64 { return &v }

// TestMaintenanceScalesOntoBudget is the property that makes this a
// Scorecard integration rather than a decorative field: a project with a
// known Scorecard must actually move the number.
func TestMaintenanceScalesOntoBudget(t *testing.T) {
	cases := []struct {
		score float64
		want  int
	}{
		{10, 20}, // full budget
		{0, 0},
		{5, 10}, // linear
		{7, 14},
		{2.5, 5},
		// Out-of-range input is clamped rather than trusted.
		{12, 20},
		{-3, 0},
	}
	for _, c := range cases {
		e := New()
		e.SetMaintenance(c.score, 11, 3, "2026-09-28", "abc123")
		got := e.maintenancePoints(model.Component{})
		if got != c.want {
			t.Errorf("Scorecard %v -> maintenance %d, want %d", c.score, got, c.want)
		}
	}
}

// TestMaintenanceNilMeansUnknown is the distinction that matters most. With
// no Scorecard, maintenance is zero points -- but the caller must be able to
// tell that apart from a project that scored zero.
func TestMaintenanceNilMeansUnknown(t *testing.T) {
	e := New()
	if e.HasMaintenance() {
		t.Fatal("a fresh Engine claims to have a maintenance score")
	}
	if got := e.maintenancePoints(model.Component{}); got != 0 {
		t.Errorf("no Scorecard -> %d points, want 0", got)
	}

	// Same points, different fact.
	e.SetMaintenance(0, 11, 3, "2026-09-28", "abc123")
	if !e.HasMaintenance() {
		t.Error("after SetMaintenance(0, ...) HasMaintenance is false; a real 0 is being reported as unknown")
	}
	if got := e.maintenancePoints(model.Component{}); got != 0 {
		t.Errorf("Scorecard 0 -> %d points, want 0", got)
	}
}

// TestMaintenanceAllChecksInapplicable is the "no measurement" case. Every
// check returned -1, so the API's aggregate is 0 for want of data rather
// than for want of maintenance. Scaling that 0 onto the budget would report
// a well-maintained project as badly maintained on the strength of a scan
// that never ran.
//
// The aggregate here is deliberately 5, not 0. With an aggregate of 0 the
// guard and the scale agree by accident and the test proves nothing: this
// case is only distinguishable from a genuinely-unmaintained project if the
// number being suppressed is not itself zero.
func TestMaintenanceAllChecksInapplicable(t *testing.T) {
	e := New()
	e.SetMaintenance(5, 0, 14, "2026-09-28", "abc123")
	if e.HasMaintenance() {
		t.Error("HasMaintenance is true with zero usable checks")
	}
	if got := e.maintenancePoints(model.Component{}); got != 0 {
		t.Errorf("all-inapplicable with aggregate 5 -> %d points, want 0 "+
			"(no usable checks is no measurement, not a score of zero)", got)
	}
}

// TestMaintenanceInapplicableIsNotSilentlyZero documents that one
// inapplicable check among many must NOT zero the term -- only the case
// where nothing at all was measured does. Getting this backwards in either
// direction is wrong, and the two are distinguished here.
func TestMaintenanceInapplicableIsNotSilentlyZero(t *testing.T) {
	// 1 inapplicable out of 12: a real score of 10 is still a real score.
	mostlyScored := New()
	mostlyScored.SetMaintenance(10, 11, 1, "2026-09-28", "abc123")
	if !mostlyScored.HasMaintenance() {
		t.Error("a project with 11 usable checks claims to have no Scorecard")
	}
	if got := mostlyScored.maintenancePoints(model.Component{}); got != 20 {
		t.Errorf("1 inapplicable of 12 -> %d points, want 20 (a partial scan is still a scan)", got)
	}
}

// TestMaintenanceIsTheSameForEveryComponent documents the deliberate design
// choice: the Scorecard measures the repository, not each dependency.
func TestMaintenanceIsTheSameForEveryComponent(t *testing.T) {
	e := New()
	e.SetMaintenance(8, 12, 2, "2026-09-28", "abc123")
	comps := []model.Component{
		{Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0"},
		{Name: "b", Version: "2.0.0", Purl: "pkg:pypi/b@2.0.0"},
		{Name: "c", Version: "3.0.0", Purl: "pkg:golang/c@3.0.0"},
	}
	for i := range comps {
		got := e.maintenancePoints(comps[i])
		if got != 16 {
			t.Errorf("component %s -> %d points, want 16 (repo-level score applied uniformly)", comps[i].Name, got)
		}
	}
}

// TestScoreIncludesMaintenance is the end-to-end property through the public
// API: with a Scorecard set, a component's total must rise by the
// maintenance points. Without this, maintenancePoints could return the right
// number and Score could still ignore it.
func TestScoreIncludesMaintenance(t *testing.T) {
	base := model.Component{
		Name: "x", Version: "1.0.0", Purl: "pkg:npm/x@1.0.0", Ecosystem: "npm",
		Vulnerabilities: []model.Vuln{{ID: "GHSA-test", CVSSv3: 5.0}},
	}
	without := New()
	s1 := without.Score([]model.Component{base})

	with := New()
	with.SetMaintenance(10, 11, 3, "2026-09-28", "abc123")
	s2 := with.Score([]model.Component{base})

	if s1.TotalComponents != 1 || s2.TotalComponents != 1 {
		t.Fatalf("unexpected component counts: %d %d", s1.TotalComponents, s2.TotalComponents)
	}
	// Severity is the only other live term here (no EPSS, no freshness
	// signal), so the delta is exactly the maintenance budget at Scorecard 10.
	want := model.MaxMaintenancePoints
	if s2.RepoScore-s1.RepoScore != want {
		t.Errorf("repo score moved by %d with a perfect Scorecard, want %d",
			s2.RepoScore-s1.RepoScore, want)
	}
	t.Logf("no scorecard: %d | perfect scorecard: %d (delta %d)",
		s1.RepoScore, s2.RepoScore, s2.RepoScore-s1.RepoScore)
}

// TestMaintenanceScaledFormula pins the arithmetic so a future refactor
// cannot quietly change what a Scorecard of 7.5 means.
func TestMaintenanceScaledFormula(t *testing.T) {
	e := New()
	for _, score := range []float64{0, 1, 2.5, 5, 7.5, 9, 10} {
		e.SetMaintenance(score, 11, 3, "2026-09-28", "abc123")
		want := int(math.Round(score / 10 * float64(model.MaxMaintenancePoints)))
		if got := e.maintenancePoints(model.Component{}); got != want {
			t.Errorf("Scorecard %v -> %d, want %d (round(%v/10*20))",
				score, got, want, score)
		}
	}
}

// TestExplainReportsMaintenanceProvenance is the honesty requirement: --explain
// must say where the number came from, and must not claim a measurement it
// does not have.
func TestExplainReportsMaintenanceProvenance(t *testing.T) {
	// No Scorecard available.
	c := model.Component{Name: "x", Version: "1.0.0", Purl: "pkg:npm/x@1.0.0", Ecosystem: "npm"}
	c.Score = &model.Score{Total: 10, Maintenance: 0}
	c.Bucket = BucketFor(10)
	out := Explain(c)
	if !strings.Contains(out, "no OpenSSF Scorecard available") {
		t.Errorf("Explain with no Scorecard does not say so:\n%s", out)
	}

	// Scorecard present: use the entry point that has the provenance.
	c.Score = &model.Score{Total: 30, Maintenance: 20}
	e := New()
	e.SetMaintenance(8.5, 11, 3, "2026-09-28", "abc123def456")
	out2 := ExplainScored(c, e)
	if !strings.Contains(out2, "2026-09-28") {
		t.Errorf("Explain does not report the Scorecard date:\n%s", out2)
	}
	if !strings.Contains(out2, "8.5/10") {
		t.Errorf("Explain does not report the Scorecard aggregate:\n%s", out2)
	}
	if !strings.Contains(out2, "abc123d") {
		t.Errorf("Explain does not report the scored commit:\n%s", out2)
	}
	if !strings.Contains(out2, "3 of 14") {
		t.Errorf("Explain does not report the inapplicable checks:\n%s", out2)
	}
}

// TestExplainNeverContradictsItself is the guard against the bug found while
// writing these tests: a component scored with a full maintenance budget but
// rendered through a path that has no provenance used to print "no OpenSSF
// Scorecard available" next to "maintenance 20 / 20". Both halves were
// individually defensible and together they were a lie.
//
// The invariant: if the points are non-zero, the explanation must not claim
// there was no Scorecard. A reader who sees those two lines together has no
// way to tell which one to believe.
func TestExplainNeverContradictsItself(t *testing.T) {
	c := model.Component{Name: "x", Version: "1.0.0", Purl: "pkg:npm/x@1.0.0", Ecosystem: "npm"}
	c.Score = &model.Score{Total: 40, Severity: 20, Maintenance: 20}
	c.Bucket = BucketFor(40)

	e := New()
	e.SetMaintenance(10, 11, 3, "2026-09-28", "abc123def456")
	out := ExplainScored(c, e)

	if !strings.Contains(out, "maintenance      20 / 20") {
		t.Fatalf("expected a 20-point maintenance term, got:\n%s", out)
	}
	if strings.Contains(out, "no OpenSSF Scorecard available") {
		t.Errorf("output claims no Scorecard while showing 20 maintenance points:\n%s", out)
	}
	if !strings.Contains(out, "OpenSSF Scorecard 10.0/10") {
		t.Errorf("output does not attribute the 20 points to a Scorecard:\n%s", out)
	}
}
