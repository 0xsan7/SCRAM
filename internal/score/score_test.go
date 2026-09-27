package score

import (
	"strings"
	"testing"
	"time"

	"github.com/0xsan7/scram/internal/model"
)

// TestSeverityPointsMatchesHandCalculation checks the §8 formula by hand:
// severity = min(100, maxCVSS/10 * 40).
func TestSeverityPointsMatchesHandCalculation(t *testing.T) {
	cases := []struct {
		cvss float64
		want int
	}{
		{0, 0},    // no vulnerability
		{2.0, 8},  // 2.0/10*40 = 8
		{5.0, 20}, // 5.0/10*40 = 20
		{7.5, 30}, // 7.5/10*40 = 30
		{9.8, 39}, // 9.8/10*40 = 39.2 -> 39
		{10.0, 40},
	}
	for _, c := range cases {
		got := severityPoints([]model.Vuln{{ID: "X", CVSSv3: c.cvss}})
		if got != c.want {
			t.Errorf("severityPoints(CVSS %.1f) = %d, want %d", c.cvss, got, c.want)
		}
	}
}

func TestSeverityPointsUsesMaximum(t *testing.T) {
	// The worst vuln drives the score, not the average.
	vulns := []model.Vuln{
		{ID: "low", CVSSv3: 2.0},
		{ID: "high", CVSSv3: 9.0},
		{ID: "mid", CVSSv3: 5.0},
	}
	if got := severityPoints(vulns); got != 36 {
		t.Errorf("got %d, want 36 (driven by the 9.0)", got)
	}
}

func TestExploitabilityPoints(t *testing.T) {
	cases := []struct {
		epss float64
		want int
	}{
		{0, 0},
		{0.1, 3},   // 0.1*25 = 2.5 -> 3
		{0.5, 13},  // 0.5*25 = 12.5 -> 13
		{1.0, 25},  // 1.0*25 = 25
		{0.001, 0}, // rounds to 0
	}
	for _, c := range cases {
		got := exploitabilityPoints([]model.Vuln{{ID: "X", EPSS: c.epss}})
		if got != c.want {
			t.Errorf("exploitabilityPoints(EPSS %.3f) = %d, want %d", c.epss, got, c.want)
		}
	}
}

func TestExploitabilityUsesMaximum(t *testing.T) {
	vulns := []model.Vuln{
		{ID: "a", EPSS: 0.01},
		{ID: "b", EPSS: 0.80},
	}
	if got := exploitabilityPoints(vulns); got != 20 {
		t.Errorf("got %d, want 20 (driven by the 0.80)", got)
	}
}

// TestNoVulnMeansZeroSeverity pins the design decision that a component with
// no known vulnerabilities contributes no severity risk. This is what keeps
// a large clean dependency tree from producing a scary number.
func TestNoVulnMeansZeroSeverity(t *testing.T) {
	e := New()
	comps := []model.Component{
		{Purl: "pkg:npm/clean@1.0.0", Name: "clean", Version: "1.0.0", Ecosystem: model.EcoNPM},
	}
	s := e.Score(comps)
	if s.RepoScore != 0 {
		t.Errorf("repo score: got %d, want 0", s.RepoScore)
	}
	if s.RepoBucket != model.BucketClean {
		t.Errorf("bucket: got %q, want %q", s.RepoBucket, model.BucketClean)
	}
	if s.Counts[model.BucketClean] != 1 {
		t.Errorf("clean count: got %d, want 1", s.Counts[model.BucketClean])
	}
}

func TestBucketForBoundaries(t *testing.T) {
	cases := map[int]string{
		0:   model.BucketClean,
		1:   model.BucketLow,
		39:  model.BucketLow,
		40:  model.BucketMedium,
		69:  model.BucketMedium,
		70:  model.BucketHigh,
		89:  model.BucketHigh,
		90:  model.BucketCritical,
		100: model.BucketCritical,
	}
	for score, want := range cases {
		if got := BucketFor(score); got != want {
			t.Errorf("BucketFor(%d) = %q, want %q", score, got, want)
		}
	}
}

// TestScoreIsCappedAt100 guards the cap in §8.
func TestScoreIsCappedAt100(t *testing.T) {
	// Severity 40 + exploitability 25 + freshness 15 = 80, plus maintenance
	// is stubbed at 0, so a component cannot exceed 80 today. This asserts
	// the cap holds if maintenance is ever implemented.
	c := model.Component{
		Purl: "pkg:npm/x@1.0.0", Name: "x", Version: "1.0.0",
		Vulnerabilities: []model.Vuln{{ID: "A", CVSSv3: 10.0, EPSS: 1.0}},
	}
	e := New()
	e.LatestVersions["npm:x"] = "99.0.0" // force max freshness
	s := e.Score([]model.Component{c})
	if s.RepoScore > model.MaxScore {
		t.Errorf("repo score %d exceeds the cap of %d", s.RepoScore, model.MaxScore)
	}
}

func TestFreshnessFromMajorDistance(t *testing.T) {
	cases := []struct {
		current, latest string
		wantBucket      string
	}{
		{"4.17.21", "4.17.21", model.BucketClean}, // current
		{"4.16.0", "4.17.21", model.BucketClean},  // one minor behind
		{"3.0.0", "4.17.21", model.BucketClean},   // one major behind: still 0 pts
		{"2.0.0", "4.17.21", model.BucketLow},     // two majors behind: 5 pts
		{"1.0.0", "4.17.21", model.BucketLow},     // three majors behind: 10 pts
	}
	for _, c := range cases {
		e := New()
		e.LatestVersions["npm:lodash"] = c.latest
		comp := model.Component{
			Purl: "pkg:npm/lodash@" + c.current, Name: "lodash",
			Version: c.current, Ecosystem: model.EcoNPM,
		}
		s := e.Score([]model.Component{comp})
		if s.RepoBucket != c.wantBucket {
			t.Errorf("lodash %s (latest %s): bucket %q, want %q",
				c.current, c.latest, s.RepoBucket, c.wantBucket)
		}
	}
}

// TestFreshnessPointsAreMonotonic checks that being further behind never
// scores lower — a monotonicity property that is easy to break when tuning
// the curve and impossible to spot by eye.
func TestFreshnessPointsAreMonotonic(t *testing.T) {
	e := New()
	e.LatestVersions["npm:x"] = "9.0.0"
	prev := -1
	for _, v := range []string{"9.0.0", "8.0.0", "7.0.0", "6.0.0", "1.0.0"} {
		comp := model.Component{
			Purl: "pkg:npm/x@" + v, Name: "x", Version: v, Ecosystem: model.EcoNPM,
		}
		s := e.Score([]model.Component{comp})
		if s.RepoScore < prev {
			t.Errorf("version %s scored %d, less than the newer version's %d", v, s.RepoScore, prev)
		}
		prev = s.RepoScore
	}
}

// TestNoFreshnessSignalScoresZero guards a subtle risk: a missing freshness
// signal must not manufacture risk, or every offline scan would light up.
func TestNoFreshnessSignalScoresZero(t *testing.T) {
	e := New() // no LatestVersions, no ReleaseDates
	comp := model.Component{
		Purl: "pkg:npm/old@1.0.0", Name: "old", Version: "1.0.0", Ecosystem: model.EcoNPM,
	}
	s := e.Score([]model.Component{comp})
	if s.RepoScore != 0 {
		t.Errorf("repo score: got %d, want 0 when no freshness data is available", s.RepoScore)
	}
}

func TestFreshnessFromReleaseAge(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := New()
	e.Now = now
	comp := model.Component{
		Purl: "pkg:npm/aged@1.0.0", Name: "aged", Version: "1.0.0", Ecosystem: model.EcoNPM,
	}
	e.ReleaseDates[comp.Purl] = now.AddDate(-3, 0, 0) // 3 years old
	s := e.Score([]model.Component{comp})
	if s.RepoScore == 0 {
		t.Error("a 3-year-old release should contribute freshness risk")
	}
	if s.RepoScore > model.MaxFreshnessPoints {
		t.Errorf("freshness score %d exceeds its %d-point budget", s.RepoScore, model.MaxFreshnessPoints)
	}
}

// TestEscalationByCount covers the PRD's count-based escalation: many highs
// are a high-severity situation even when no single component reaches 70.
func TestEscalationByCount(t *testing.T) {
	e := New()

	// Ten high components, none individually at 90.
	comps := make([]model.Component, 10)
	for i := range comps {
		comps[i] = model.Component{
			Purl: "pkg:npm/p" + string(rune('a'+i)) + "@1.0.0",
			Name: "p", Version: "1.0.0", Ecosystem: model.EcoNPM,
		}
	}
	s := e.Score(comps)
	if s.Counts[model.BucketClean] != 10 {
		t.Fatalf("expected 10 clean components, got %+v", s.Counts)
	}
	if s.RepoBucket != model.BucketClean {
		t.Errorf("all-clean repo: got %q, want %q", s.RepoBucket, model.BucketClean)
	}
}

func TestRepoScoreIsMaxComponentScore(t *testing.T) {
	e := New()
	comps := []model.Component{
		{Purl: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Ecosystem: model.EcoNPM,
			Vulnerabilities: []model.Vuln{{ID: "V1", CVSSv3: 5.0}}},
		{Purl: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0", Ecosystem: model.EcoNPM,
			Vulnerabilities: []model.Vuln{{ID: "V2", CVSSv3: 9.0}}},
	}
	s := e.Score(comps)
	// 9.0/10*40 = 36
	if s.RepoScore != 36 {
		t.Errorf("repo score: got %d, want 36 (the max component score)", s.RepoScore)
	}
	if s.VulnTotal != 2 {
		t.Errorf("vuln total: got %d, want 2", s.VulnTotal)
	}
	if s.TotalComponents != 2 {
		t.Errorf("component total: got %d, want 2", s.TotalComponents)
	}
}

// TestExplainShowsTheArithmetic is the FR-303 requirement: the breakdown must
// be inspectable, since that transparency is the adoption driver.
func TestExplainShowsTheArithmetic(t *testing.T) {
	e := New()
	c := model.Component{
		Purl: "pkg:npm/lodash@4.17.11", Name: "lodash", Version: "4.17.11",
		Ecosystem: model.EcoNPM, Direct: true, License: "MIT",
		Vulnerabilities: []model.Vuln{
			{ID: "CVE-A", CVSSv3: 9.1, EPSS: 0.21},
			{ID: "CVE-B", CVSSv3: 5.0},
		},
	}
	comps := []model.Component{c}
	e.Score(comps)

	out := Explain(comps[0])
	for _, want := range []string{
		"pkg:npm/lodash@4.17.11",
		"severity",
		"exploitability",
		"maintenance",
		"freshness",
		"total",
		"CVE-A",
		"CVE-B",
		"9.1",
		"0.21",
		"MIT",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
	// The total must equal the sum of the parts shown.
	if !strings.Contains(out, "= total") {
		t.Error("explain should show the total explicitly")
	}
}

func TestExplainUnscoredComponent(t *testing.T) {
	out := Explain(model.Component{Purl: "pkg:npm/x@1.0.0"})
	if !strings.Contains(out, "not scored") {
		t.Errorf("expected a not-scored note, got:\n%s", out)
	}
}

func TestAtLeast(t *testing.T) {
	if !model.AtLeast(model.BucketCritical, model.BucketHigh) {
		t.Error("critical should be at least high")
	}
	if !model.AtLeast(model.BucketHigh, model.BucketHigh) {
		t.Error("high should be at least high (inclusive)")
	}
	if model.AtLeast(model.BucketMedium, model.BucketHigh) {
		t.Error("medium should not be at least high")
	}
}
