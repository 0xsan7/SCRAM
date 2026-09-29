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

// TestBucketForBoundaries pins the presented 0–65 thresholds.
//
// The boundaries are the old 0–100 ones scaled by 65/100 and rounded down,
// so the same underlying risk keeps the same bucket:
//
//	>= 90  ->  >= 58      >= 70  ->  >= 45
//	>= 40  ->  >= 26      >= 1   ->  >= 1
//
// Rounding down is deliberate. Rounding 45.5 to 46 would promote a score
// of 46 from "high" to "critical", i.e. a risk the old scale called High
// would be reported as Critical after a presentation change. Rounding down
// can only ever keep a bucket or lower it, never raise one.
func TestBucketForBoundaries(t *testing.T) {
	cases := map[int]string{
		0:  model.BucketClean,
		1:  model.BucketLow,
		25: model.BucketLow,
		26: model.BucketMedium,
		44: model.BucketMedium,
		45: model.BucketHigh,
		57: model.BucketHigh,
		58: model.BucketCritical,
		65: model.BucketCritical,
	}
	for score, want := range cases {
		if got := BucketFor(score); got != want {
			t.Errorf("BucketFor(%d) = %q, want %q", score, got, want)
		}
	}
}

// TestPresentedIsMonotoneAndClamped is the property the rescale rests on.
// A presented score must never exceed its own denominator, and a worse
// input must never present as better -- otherwise the badge would be
// able to claim a score above 100% of what the tool can express.
func TestPresentedIsMonotoneAndClamped(t *testing.T) {
	if model.PresentedMax != 65 {
		t.Fatalf("PresentedMax = %d, want 65; the presented scale is documented as 0-65", model.PresentedMax)
	}
	prev := -1
	for total := 0; total <= model.MaxScore; total++ {
		got := Presented(total)
		if got < 0 {
			t.Fatalf("Presented(%d) = %d, negative", total, got)
		}
		if got > model.PresentedMax {
			t.Fatalf("Presented(%d) = %d, above the presented maximum %d: a badge would read %d/%d",
				total, got, model.PresentedMax, got, model.PresentedMax)
		}
		if got < prev {
			t.Errorf("Presented(%d) = %d, less than the previous %d: the mapping is not monotone",
				total, got, prev)
		}
		prev = got
	}
	// Endpoints are exact, so the extremes of the scale still mean what
	// they did.
	if Presented(0) != 0 {
		t.Errorf("Presented(0) = %d, want 0", Presented(0))
	}
	if Presented(model.MaxScore) != model.PresentedMax {
		t.Errorf("Presented(%d) = %d, want %d", model.MaxScore, Presented(model.MaxScore), model.PresentedMax)
	}
	// Half-up rounding, pinned at the boundaries that matter.
	for _, c := range []struct{ in, want int }{
		{1, 1},    // 0.65 -> 1
		{2, 1},    // 1.3  -> 1
		{26, 17},  // 16.9 -> 17
		{40, 26},  // 26.0 -> 26
		{100, 65}, //
	} {
		if got := Presented(c.in); got != c.want {
			t.Errorf("Presented(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestBucketForCVSSKeepsTheSpecificationBoundaries guards the split made
// when the presented scale diverged from the CVSS scale.
//
// BucketForCVSS is used to band raw CVSS v3 scores in drift and policy.
// Before the split, one function served both a 0-100 presented score and a
// 0-100 CVSS-times-ten, which only worked because the scales were equal.
// Reusing the 0-65 function for CVSS would report a 9.8 critical as "high"
// -- and those two call sites decide whether a pull request fails.
func TestBucketForCVSSKeepsTheSpecificationBoundaries(t *testing.T) {
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
	for cvss, want := range cases {
		if got := BucketForCVSS(cvss); got != want {
			t.Errorf("BucketForCVSS(%d) = %q, want %q", cvss, got, want)
		}
	}
	// The specific regression: a critical CVSS must not be banded with the
	// presented scale's threshold, which is 58 on a 0-65 range.
	if got := BucketForCVSS(90); got != model.BucketCritical {
		t.Errorf("BucketForCVSS(90) = %q, want critical", got)
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

	// Ten components that each land in the High bucket (score 70-89) but
	// none of which reaches Critical on its own. The repo must still escalate
	// to Critical, because ten separate High exposures is the aggregate risk
	// the PRD cares about.
	//
	// This test previously built ten CLEAN components and asserted only that
	// an all-clean repo stays clean. The name claimed count-based escalation
	// and the body never reached counts[BucketHigh] >= 10, so changing that
	// threshold to 99 left the suite green. Found by scripts/mutation_audit.py.
	//
	// A component scores High at ~72 via CVSS 9.5 + EPSS 0.95 + a large
	// major-version distance; the version gap is what supplies freshness
	// points, since maintenance is not implemented.
	comps := make([]model.Component, 10)
	for i := range comps {
		name := "high" + string(rune('a'+i))
		e.LatestVersions[model.EcoNPM+":"+name] = "99.0.0"
		comps[i] = model.Component{
			Purl: "pkg:npm/" + name + "@1.0.0", Name: name, Version: "1.0.0",
			Ecosystem: model.EcoNPM,
			Vulnerabilities: []model.Vuln{
				{ID: "CVE-HIGH-" + name, CVSSv3: 9.5, EPSS: 0.95},
			},
		}
	}
	s := e.Score(comps)
	if s.Counts[model.BucketHigh] != 10 {
		t.Fatalf("expected 10 high components, got counts %+v", s.Counts)
	}
	if s.Counts[model.BucketCritical] != 0 {
		t.Fatalf("no component should be critical on its own, got %+v", s.Counts)
	}
	if s.RepoBucket != model.BucketCritical {
		t.Errorf("ten high components must escalate the repo to critical: got %q",
			s.RepoBucket)
	}
}

// TestEscalationBelowThresholdDoesNotFire is the other half: nine high
// components must NOT reach the ten-component critical escalation, so the
// threshold itself is pinned from both sides rather than one.
func TestEscalationBelowThresholdDoesNotFire(t *testing.T) {
	e := New()
	comps := make([]model.Component, 9)
	for i := range comps {
		name := "high" + string(rune('a'+i))
		e.LatestVersions[model.EcoNPM+":"+name] = "99.0.0"
		comps[i] = model.Component{
			Purl: "pkg:npm/" + name + "@1.0.0", Name: name, Version: "1.0.0",
			Ecosystem: model.EcoNPM,
			Vulnerabilities: []model.Vuln{
				{ID: "CVE-HIGH-" + name, CVSSv3: 9.5, EPSS: 0.95},
			},
		}
	}
	s := e.Score(comps)
	if s.Counts[model.BucketHigh] != 9 {
		t.Fatalf("expected 9 high components, got counts %+v", s.Counts)
	}
	if s.RepoBucket == model.BucketCritical {
		t.Errorf("nine high components must not escalate to critical, got %q",
			s.RepoBucket)
	}
}

// TestEscalationAllCleanStaysClean keeps the original assertion the vacuous
// test made, now as its own correctly-named test rather than a side effect.
func TestEscalationAllCleanStaysClean(t *testing.T) {
	e := New()
	comps := make([]model.Component, 10)
	for i := range comps {
		name := "clean" + string(rune('a'+i))
		comps[i] = model.Component{
			Purl: "pkg:npm/" + name + "@1.0.0", Name: name, Version: "1.0.0",
			Ecosystem: model.EcoNPM,
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
	// The formula scores 9.0 CVSS as 9.0/10*40 = 36 of 100. RepoScore is
	// the PRESENTED figure, so it is 36 rescaled onto 0-65.
	want := Presented(36)
	if s.RepoScore != want {
		t.Errorf("repo score: got %d, want %d (Presented(36))", s.RepoScore, want)
	}
	// And the component's own Score.Total stays in formula units, which is
	// what --explain itemises.
	if got := comps[1].Score.Total; got != 36 {
		t.Errorf("component Score.Total = %d, want 36 in the formula's own 0-100 units", got)
	}
	// The worst component is the one that sets the repo score, on both
	// scales.
	if comps[0].Score.Total >= comps[1].Score.Total {
		t.Errorf("expected component b to outscore a: %d vs %d",
			comps[0].Score.Total, comps[1].Score.Total)
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

// TestPresentedClampIsLoadBearing pins the upper bound with the specific
// inputs that motivated it.
//
// The early return for total >= MaxScore and the clamp after the division
// are redundant with each other -- either alone holds the bound. That is
// fine; what matters is that the bound holds for every input, including
// ones a caller could plausibly produce. Removing one copy leaves the
// other, which is why the mutation audit reports this as a survivor and
// why the test is written against the property rather than the line: the
// guarantee must not depend on two implementations of it staying in sync.
func TestPresentedClampIsLoadBearing(t *testing.T) {
	for _, total := range []int{100, 101, 150, 200, 1000, 100000} {
		got := Presented(total)
		if got > model.PresentedMax {
			t.Errorf("Presented(%d) = %d, above the maximum %d", total, got, model.PresentedMax)
		}
		if got != model.PresentedMax {
			t.Errorf("Presented(%d) = %d, want the maximum %d: a score at or over the\n"+
				"formula maximum must present as the presented maximum", total, got, model.PresentedMax)
		}
	}
	// And below the range, the lower bound.
	for _, total := range []int{-100, -1, 0} {
		if got := Presented(total); got != 0 {
			t.Errorf("Presented(%d) = %d, want 0", total, got)
		}
	}
}

// TestRescalePromotesOnlyTheTwoBoundaryScores measures the exact blast
// radius of the rescale, because the first draft of the README claimed no
// component could be promoted by it and that claim was false.
//
// Dividing by 0.65 is monotonic -- a higher input always presents higher --
// but a monotonic map does not preserve bandings: a score just under an old
// threshold can land just over the new one. Exhaustive check over 0-100
// finds exactly two such inputs, 69 and 89, and no demotions at all.
//
// The claim this pins is the corrected one: at most these two values
// change bucket, and only upward. A future change to the thresholds must
// re-run this test, because a rounding direction that promotes a third
// value is a behaviour change that belongs in the changelog.
func TestRescalePromotesOnlyTheTwoBoundaryScores(t *testing.T) {
	// The old 0-100 boundaries, for comparison.
	oldBucket := func(v int) string {
		switch {
		case v >= 90:
			return model.BucketCritical
		case v >= 70:
			return model.BucketHigh
		case v >= 40:
			return model.BucketMedium
		case v >= 1:
			return model.BucketLow
		}
		return model.BucketClean
	}
	var promoted []int
	for total := 0; total <= model.MaxScore; total++ {
		was := oldBucket(total)
		now := BucketFor(Presented(total))
		switch {
		case model.SeverityRank[now] > model.SeverityRank[was]:
			promoted = append(promoted, total)
		case model.SeverityRank[now] < model.SeverityRank[was]:
			t.Errorf("score %d demoted: %s on the old scale, %s now",
				total, was, now)
		}
	}
	want := []int{69, 89}
	if len(promoted) != len(want) {
		t.Fatalf("promoted %v, want exactly %v; the rescale's blast radius changed", promoted, want)
	}
	for i, v := range want {
		if promoted[i] != v {
			t.Errorf("promoted %v, want %v", promoted, want)
		}
	}
	t.Logf("checked 0-100: %d promotions (%v), 0 demotions", len(promoted), promoted)
}
