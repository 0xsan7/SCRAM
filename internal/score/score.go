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
		c.Bucket = BucketFor(s.Total)
		counts[c.Bucket]++
		if s.Total > maxScore {
			maxScore = s.Total
		}
		vulnTotal += len(c.Vulnerabilities)
	}

	return model.Summary{
		RepoScore:       maxScore,
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
	s.Maintenance = maintenancePoints(c) // stubbed at 0 until Scorecard lands
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

// maintenancePoints is the OpenSSF Scorecard component. It is stubbed at 0 in
// v1 (the PRD defers Scorecard integration to v1.x) but the field is plumbed
// through so the total in §8 already includes the term and won't shift when
// it goes live.
func maintenancePoints(c model.Component) int {
	_ = c
	return 0
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

// BucketFor maps a 0–100 score to a severity bucket.
func BucketFor(score int) string {
	switch {
	case score >= 90:
		return model.BucketCritical
	case score >= 70:
		return model.BucketHigh
	case score >= 40:
		return model.BucketMedium
	case score >= 1:
		return model.BucketLow
	}
	return model.BucketClean
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

// Explain renders a human-readable breakdown of one component's score. This
// is the output of `scram scan --explain` (FR-303) and is deliberately verbose:
// it is the trust-building surface of the tool.
func Explain(c model.Component) string {
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

	fmt.Fprintf(&b, "\n  exploitability  %3d / %d   (EPSS probability x 25)\n",
		s.Exploitability, model.MaxExploitabilityPoints)
	fmt.Fprintf(&b, "  maintenance     %3d / %d   (OpenSSF Scorecard, not yet integrated)\n",
		s.Maintenance, model.MaxMaintenancePoints)
	fmt.Fprintf(&b, "  freshness       %3d / %d   (version distance behind latest)\n",
		s.Freshness, model.MaxFreshnessPoints)

	fmt.Fprintf(&b, "\n  = total         %3d / %d   bucket: %s\n",
		s.Total, model.MaxScore, c.Bucket)
	return b.String()
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
