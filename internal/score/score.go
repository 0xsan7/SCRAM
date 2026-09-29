// Package score implements SCRAM's risk scoring algorithm (§8 of the PRD).
//
// The design goal is auditability, not just a number: every score is broken
// into its four weighted components, and `scram scan --explain` prints the
// arithmetic. A security tool that can't explain its number gets ignored.
package score

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/0xsan7/scram/internal/model"
)

// Engine computes component and repo-level scores.
type Engine struct {
	// LatestVersions maps "ecosystem:name" to the newest published version.
	// Populated by a resolver that can reach a registry; when a component
	// isn't in the map, freshness falls back to release-date age from the
	// vuln data rather than being silently scored as "current".
	LatestVersions map[string]string
	// ReleaseDates maps "ecosystem:name@version" to that version's publish
	// date, when known.
	ReleaseDates map[string]time.Time
	// MaintenanceScore is the OpenSSF Scorecard aggregate for the scanned
	// repository, 0-10. It is set once per scan by the caller, from
	// internal/scorecard.
	//
	// A nil pointer means no Scorecard is available: the project is not on
	// the API, the network was unavailable, or the caller disabled it. Those
	// are three different situations and the distinction is kept in
	// scorecard.ErrNotScored rather than collapsed into a zero, because a
	// zero here would read as "this project is unmaintained", which is a
	// claim about a project no measurement was able to make.
	MaintenanceScore *float64
	// MaintenanceDate and MaintenanceCommit record which Scorecard run and
	// which commit produced the score, so a stale or mismatched score is
	// visible in --explain rather than being presented as current.
	MaintenanceDate   string
	MaintenanceCommit string
	// MaintenanceInapplicable counts the Scorecard checks that returned -1
	// ("no releases found", "packaging workflow not detected"). A high
	// score computed from half the checks is not the same claim as one
	// computed from all of them, and the count is reported so a reader can
	// tell.
	MaintenanceInapplicable int
	// maintenanceChecks is how many Scorecard checks actually produced a
	// score. It gates the conversion: a project where every check came back
	// inapplicable has an aggregate of 0 for want of data, and scaling that
	// 0 onto the budget would be inventing a measurement.
	maintenanceChecks int
	// Now is overridable for deterministic tests.
	Now time.Time
}

// New returns an Engine with sane defaults.
func New() *Engine {
	return &Engine{
		LatestVersions: map[string]string{},
		ReleaseDates:   map[string]time.Time{},
		Now:            time.Now(),
	}
}

// SetMaintenance records a fetched OpenSSF Scorecard.
//
// It takes a scorecard.Result rather than loose numbers so that the
// aggregate, the check count, and the inapplicable count cannot be set
// inconsistently -- the -1 checks have to be subtracted from the denominator
// at the same moment the score is recorded, and a caller that could set them
// independently would eventually set them differently.
func (e *Engine) SetMaintenance(score float64, usableChecks, inapplicable int, date, commit string) {
	e.MaintenanceScore = &score
	e.maintenanceChecks = usableChecks
	e.MaintenanceInapplicable = inapplicable
	e.MaintenanceDate = date
	e.MaintenanceCommit = commit
}

// HasMaintenance reports whether a Scorecard was actually available. Callers
// use it to distinguish "scored 0 maintenance points" from "no Scorecard
// exists", which are different facts and are presented differently.
func (e *Engine) HasMaintenance() bool {
	return e.MaintenanceScore != nil && e.maintenanceChecks > 0
}

// Score computes and attaches a score to every component, then returns the
// repo-level summary (FR-301, FR-302).
func (e *Engine) Score(comps []model.Component) model.Summary {
	counts := map[string]int{
		model.BucketCritical: 0,
		model.BucketHigh:     0,
		model.BucketMedium:   0,
		model.BucketLow:      0,
		model.BucketClean:    0,
	}
	maxScore := 0
	vulnTotal := 0

	for i := range comps {
		c := &comps[i]
		if e.Now.IsZero() {
			e.Now = time.Now()
		}
		s := e.scoreComponent(*c)
		c.Score = &s
		// BucketFor takes the PRESENTED scale, so the component is
		// rescaled before it is banded. The stored Score.Total stays in
		// the 0–100 formula units that `--explain` itemises, so the
		// arithmetic a reader checks still adds up to what is printed.
		presented := Presented(s.Total)
		c.Bucket = BucketFor(presented)
		counts[c.Bucket]++
		if presented > maxScore {
			maxScore = presented
		}
		vulnTotal += len(c.Vulnerabilities)
	}

	return model.Summary{
		RepoScore:       maxScore,
		RepoScoreMax:    model.PresentedMax,
		RepoBucket:      escalate(maxScore, counts),
		TotalComponents: len(comps),
		Counts:          counts,
		VulnTotal:       vulnTotal,
	}
}

// scoreComponent applies the §8 weighted sum. The order of operations is
// deliberately visible in the code so the formula can be checked against the
// spec line by line.
func (e *Engine) scoreComponent(c model.Component) model.Score {
	var s model.Score
	s.Severity = severityPoints(c.Vulnerabilities)
	s.Exploitability = exploitabilityPoints(c.Vulnerabilities)
	s.Maintenance = e.maintenancePoints(c)
	s.Freshness = e.freshnessPoints(c)

	s.Total = s.Severity + s.Exploitability + s.Maintenance + s.Freshness
	if s.Total > model.MaxScore {
		s.Total = model.MaxScore
	}
	if s.Total < 0 {
		s.Total = 0
	}
	return s
}

// severityPoints: max CVSS v3 across the component's vulns, scaled to 0–40.
// No known vulnerability means 0 points — a component with no vulns is not
// "safe", it is simply not contributing severity risk.
func severityPoints(vulns []model.Vuln) int {
	max := 0.0
	for _, v := range vulns {
		if v.CVSSv3 > max {
			max = v.CVSSv3
		}
	}
	if max <= 0 {
		return 0
	}
	return clamp(int(math.Round(max/10*float64(model.MaxSeverityPoints))), 0, model.MaxSeverityPoints)
}

// exploitabilityPoints: highest EPSS probability among the component's CVEs,
// scaled to 0–25.
func exploitabilityPoints(vulns []model.Vuln) int {
	max := 0.0
	for _, v := range vulns {
		if v.EPSS > max {
			max = v.EPSS
		}
	}
	if max <= 0 {
		return 0
	}
	return clamp(int(math.Round(max*float64(model.MaxExploitabilityPoints))), 0, model.MaxExploitabilityPoints)
}

// maintenancePoints maps the OpenSSF Scorecard (0-10) onto the 20-point
// maintenance budget.
//
// The Scorecard measures the scanned repository, not the individual
// dependency, so this is the same value for every component in a scan. That
// is deliberate and worth being explicit about: it is a property of the
// project you are standing in, and a transitive dependency of an
// unmaintained package does not inherit a different maintenance story from
// the package itself. Scorecard has no per-dependency view to draw on.
//
// Scaling is linear and clamped. A Scorecard of 10 is a full 20 points; 0 is
// none. A nil score means no Scorecard exists for the project, and yields 0
// points -- see the Engine.MaintenanceScore comment for why that is not
// treated as a measurement of zero.
func (e *Engine) maintenancePoints(c model.Component) int {
	_ = c
	if e.MaintenanceScore == nil {
		return 0
	}
	v := *e.MaintenanceScore
	if v < 0 {
		return 0
	}
	if v > 10 {
		v = 10
	}
	// A project where every check came back inapplicable has an aggregate
	// of 0 for want of data, not for want of maintenance. Scaling that 0
	// would invent a measurement.
	if e.maintenanceChecks == 0 {
		return 0
	}
	return clamp(int(math.Round(v/10*float64(model.MaxMaintenancePoints))), 0, model.MaxMaintenancePoints)
}

// freshnessPoints estimates staleness from two signals, in priority order:
// how many majors behind the newest release the component is, and how old the
// pinned version's release is. Both are capped at the 15-point budget.
func (e *Engine) freshnessPoints(c model.Component) int {
	const maxPts = model.MaxFreshnessPoints

	// Signal 1: major-version distance, when the resolver knew the latest.
	if latest, ok := e.LatestVersions[c.Ecosystem+":"+c.Name]; ok && latest != "" {
		behind := majorDistance(c.Version, latest)
		switch {
		case behind <= 1:
			// Current or one major behind: 0 points.
			return 0
		case behind == 2:
			return maxPts / 3
		default:
			return maxPts * 2 / 3
		}
	}

	// Signal 2: age of the pinned version's release.
	if rel, ok := e.ReleaseDates[c.Purl]; ok {
		years := e.Now.Sub(rel).Hours() / 24 / 365
		switch {
		case years <= 1:
			return 0
		case years <= 2:
			return maxPts / 3
		default:
			return maxPts * 2 / 3
		}
	}

	// No freshness signal available at all. This is 0, not "unknown" — a
	// missing signal must never manufacture risk, or every offline scan would
	// light up.
	return 0
}

// majorDistance counts how many major versions separate two versions. A
// version with no parseable major number yields 0.
func majorDistance(current, latest string) int {
	cm := majorOf(current)
	lm := majorOf(latest)
	if cm < 0 || lm < 0 {
		return 0
	}
	d := lm - cm
	if d < 0 {
		return 0
	}
	return d
}

func majorOf(v string) int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, ".-+"); i > 0 {
		v = v[:i]
	}
	parts := strings.SplitN(v, ".", 2)
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return -1
	}
	return n
}

// Bucket thresholds on the presented 0–65 scale.
//
// These are the previous 0–100 thresholds scaled by 65/100 and rounded
// down, so a component keeps the same bucket at the same underlying risk:
//
//	0–100   ->  0–65
//	>= 90   ->  >= 58   (0.90 x 65 = 58.5)
//	>= 70   ->  >= 45   (0.70 x 65 = 45.5)
//	>= 40   ->  >= 26   (0.40 x 65 = 26.0)
//	>= 1    ->  >= 1
//
// The boundaries are the old ones scaled by 65/100 and rounded down.
//
// This is a monotonic rescale, not a bucket-preserving one, and the
// difference is worth being exact about: dividing by 0.65 means a score
// just UNDER an old threshold can land just OVER the new one. Checked
// exhaustively over 0-100, exactly two inputs change bucket, both upward
// -- 69 (medium -> high) and 89 (high -> critical) -- and none are
// demoted. TestRescalePromotesOnlyTheTwoBoundaryScores pins that, and it
// is why a fifth digit in any threshold below is not a detail.
const (
	criticalBucketMin = 58
	highBucketMin     = 45
	mediumBucketMin   = 26
	lowBucketMin      = 1
)

// BucketForCVSS maps a raw CVSS v3 base score (0.0–10.0, times ten) to a
// severity bucket.
//
// This exists because BucketFor takes a PRESENTED score, not a CVSS. Before
// the rescale the two scales were both 0–100 and one function served both,
// so drift and policy passed `CVSSv3 * 10` straight in. Reusing a
// 0–65 function for a 0–100 input would score a critical CVSS 9.8 as
// "high" -- a silent under-report of exactly the findings the tool exists
// to catch, in the two code paths that decide whether a PR fails.
//
// CVSS severity boundaries are fixed by the specification and do not move
// with the presented scale.
func BucketForCVSS(cvssTimesTen int) string {
	switch {
	case cvssTimesTen >= 90:
		return model.BucketCritical
	case cvssTimesTen >= 70:
		return model.BucketHigh
	case cvssTimesTen >= 40:
		return model.BucketMedium
	case cvssTimesTen > 0:
		return model.BucketLow
	}
	return model.BucketClean
}

// BucketFor maps a presented 0–65 score to a severity bucket.
func BucketFor(score int) string {
	switch {
	case score >= criticalBucketMin:
		return model.BucketCritical
	case score >= highBucketMin:
		return model.BucketHigh
	case score >= mediumBucketMin:
		return model.BucketMedium
	case score >= lowBucketMin:
		return model.BucketLow
	}
	return model.BucketClean
}

// Presented rescales a 0–100 computed score onto the 0–65 scale that is
// presented to humans.
//
// The formula is untouched: severity, exploitability, maintenance and
// freshness are still summed in their own units with the same weights.
// This only changes which of those points are counted toward the displayed
// total, so the arithmetic a reader can check in `--explain` stays
// identical.
//
// Rounding is half-up, and the result is clamped into 0..PresentedMax so a
// score can never exceed the denominator it is printed against -- a badge
// reading "66/65" would be worse than the imprecision this change is
// correcting.
func Presented(total int) int {
	if total <= 0 {
		return 0
	}
	// (total/100)*65, half-up, in integer arithmetic: +50 before dividing
	// by 100 is the standard rounding trick and avoids float.
	//
	// The single clamp at the end covers BOTH ends, including totals at or
	// above the formula maximum. An early return for total >= MaxScore was
	// tried first and removed: it is redundant with this clamp, and two
	// implementations of one guarantee can drift apart while both tests
	// still pass -- which is exactly what the mutation audit reported.
	scaled := (total*model.PresentedMax + model.MaxScore/2) / model.MaxScore
	if scaled > model.PresentedMax {
		return model.PresentedMax
	}
	return scaled
}

// escalate applies the PRD's count-based escalation: a repo with many Highs
// is a High-or-worse repo even when no single component reaches 70, because
// the aggregate exposure is what actually matters.
//
// Thresholds are chosen so they sit just below the next bucket down, which is
// what makes "5 mediums" escalate to High rather than waiting for a Critical.
func escalate(maxScore int, counts map[string]int) string {
	bucket := BucketFor(maxScore)

	// Critical escalation.
	if counts[model.BucketCritical] >= 1 || counts[model.BucketHigh] >= 10 {
		return model.BucketCritical
	}
	// High escalation.
	if counts[model.BucketHigh] >= 1 || counts[model.BucketMedium] >= 25 {
		return model.BucketHigh
	}
	// Medium escalation.
	if counts[model.BucketMedium] >= 1 || counts[model.BucketLow] >= 50 {
		return model.BucketMedium
	}
	if counts[model.BucketLow] >= 1 {
		return model.BucketLow
	}
	_ = bucket
	return model.BucketClean
}

// MaintenanceProvenance describes where the maintenance term came from, for
// display. It is a value rather than a live *Engine so that Explain stays a
// pure function and remains trivially testable.
type MaintenanceProvenance struct {
	// Available is false when no Scorecard could be fetched. It is kept
	// distinct from a score of zero, which means the project scored zero.
	Available bool
	// Score is the Scorecard aggregate, 0-10.
	Score float64
	// Usable and Inapplicable count the Scorecard checks that did and did
	// not apply, so a score computed from half the checks is visible.
	Usable       int
	Inapplicable int
	// Date is when the Scorecard ran; Commit is the commit it evaluated.
	Date   string
	Commit string
}

// Provenance snapshots the Engine's maintenance state.
func (e *Engine) Provenance() MaintenanceProvenance {
	p := MaintenanceProvenance{
		Inapplicable: e.MaintenanceInapplicable,
		Date:         e.MaintenanceDate,
		Commit:       e.MaintenanceCommit,
	}
	if e.MaintenanceScore != nil {
		p.Score = *e.MaintenanceScore
	}
	p.Usable = e.maintenanceChecks
	p.Available = e.HasMaintenance()
	return p
}

// Explain renders a human-readable breakdown of one component's score. This
// is the output of `scram scan --explain` (FR-303) and is deliberately verbose:
// it is the trust-building surface of the tool.
func Explain(c model.Component) string {
	return ExplainWith(c, MaintenanceProvenance{})
}

// ExplainScored is the entry point callers should use when the Engine that
// produced the score is at hand. Explain is retained for callers that do not
// have it, and in that case it reports the maintenance term as unknown
// rather than asserting a Scorecard score it cannot see -- a number and an
// explanation that disagree is worse than a missing explanation.
func ExplainScored(c model.Component, e *Engine) string {
	if e == nil {
		return ExplainWith(c, MaintenanceProvenance{})
	}
	return ExplainWith(c, e.Provenance())
}

// ExplainWith is Explain plus the provenance of the maintenance term.
//
// The split exists because the provenance belongs to the scan, not to the
// component: every component in a scan shares it. "maintenance 0 / 20" on
// its own is ambiguous between "the Scorecard rated this project zero" and
// "there was no Scorecard", and those demand different reactions from a
// reader, so the line says which one it is.
func ExplainWith(c model.Component, prov MaintenanceProvenance) string {
	if c.Score == nil {
		return fmt.Sprintf("%s\n  not scored", c.Purl)
	}
	s := c.Score
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n", c.Purl)
	fmt.Fprintf(&b, "  ecosystem     %s\n", c.Ecosystem)
	fmt.Fprintf(&b, "  direct        %v\n", c.Direct)
	if c.License != "" {
		fmt.Fprintf(&b, "  license       %s\n", c.License)
	}

	fmt.Fprintf(&b, "\n  severity        %3d / %d   (max CVSS v3 across %d known vulns)\n",
		s.Severity, model.MaxSeverityPoints, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		cvss := "no CVSS"
		if v.CVSSv3 > 0 {
			cvss = fmt.Sprintf("CVSS %.1f", v.CVSSv3)
		}
		epss := "no EPSS"
		if v.EPSS > 0 {
			epss = fmt.Sprintf("EPSS %.4f", v.EPSS)
		}
		fmt.Fprintf(&b, "      %-18s %-12s %s\n", v.ID, cvss, epss)
	}

	// Whether any EPSS value was actually retrieved decides if the
	// exploitability line is a measurement or a non-measurement. Printing
	// "0 / 25" with no marker is the one presentation this tool cannot
	// afford: a reader cannot tell "not exploitable in the next month" from
	// "FIRST was unreachable", and those call for opposite conclusions.
	epssKnown := false
	for _, v := range c.Vulnerabilities {
		if v.EPSS > 0 {
			epssKnown = true
			break
		}
	}
	if epssKnown || len(c.Vulnerabilities) == 0 {
		fmt.Fprintf(&b, "\n  exploitability  %3d / %d   (EPSS probability x 25)\n",
			s.Exploitability, model.MaxExploitabilityPoints)
	} else {
		fmt.Fprintf(&b, "\n  exploitability  %3d / %d   (NO EPSS DATA: FIRST was not reachable for these %d\n",
			s.Exploitability, model.MaxExploitabilityPoints, len(c.Vulnerabilities))
		fmt.Fprintf(&b, "                                 advisories, so this term is unmeasured, not zero-risk;\n")
		fmt.Fprintf(&b, "                                 the presented total below divides by the full %d points)\n",
			model.PresentedMax)
	}
	if prov.Available {
		fmt.Fprintf(&b, "  maintenance     %3d / %d   (OpenSSF Scorecard %.1f/10, scored %s at %s)\n",
			s.Maintenance, model.MaxMaintenancePoints, prov.Score, shortCommit(prov.Commit), prov.Date)
		if prov.Inapplicable > 0 {
			fmt.Fprintf(&b, "                  %d of %d checks did not apply and were excluded from the average\n",
				prov.Inapplicable, prov.Usable+prov.Inapplicable)
		}
	} else {
		fmt.Fprintf(&b, "  maintenance     %3d / %d   (no OpenSSF Scorecard available for this project;\n",
			s.Maintenance, model.MaxMaintenancePoints)
		fmt.Fprintf(&b, "                             the term contributes nothing rather than scoring zero)\n")
	}
	fmt.Fprintf(&b, "  freshness       %3d / %d   (version distance behind latest)\n",
		s.Freshness, model.MaxFreshnessPoints)

	// Both scales, deliberately. The formula total is the arithmetic the
	// four lines above add up to, so hiding it would break the one check a
	// reader can perform; the presented total is the number the score is
	// reported against everywhere else, so showing only the formula total
	// would make `--explain` disagree with the badge and the scan table.
	fmt.Fprintf(&b, "\n  = total         %3d / %d   (formula; the four terms above sum to this)\n",
		s.Total, model.MaxScore)
	fmt.Fprintf(&b, "    presented     %3d / %d   bucket: %s\n",
		Presented(s.Total), model.PresentedMax, c.Bucket)
	fmt.Fprintf(&b, "\n  The presented scale is %d points, not %d. Exploitability needs EPSS and\n",
		model.PresentedMax, model.MaxScore)
	fmt.Fprintf(&b, "  freshness needs latest-version data this tool does not collect, so neither\n")
	fmt.Fprintf(&b, "  can usually be earned; dividing by %d would claim precision the inputs do\n", model.MaxScore)
	fmt.Fprintf(&b, "  not support. See ROADMAP.md for what a %d-point scale would require.\n", model.MaxScore)
	return b.String()
}

// shortCommit abbreviates a commit hash for display.
func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	if c == "" {
		return "an unknown commit"
	}
	return c
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
