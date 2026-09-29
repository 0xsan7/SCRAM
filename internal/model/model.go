// Package model defines SCRAM's internal data model (§9 of the PRD).
// Everything that flows between resolvers, the vuln matcher, the scoring
// engine, the drift engine and the report generators is one of these types.
// The JSON tags here are the stable, versioned public schema (FR-602).
package model

import "path/filepath"

// SchemaVersion is written into every JSON report so downstream tooling can
// detect breaking changes rather than silently mis-parsing.
//
//	1.0.0  initial
//	2.0.0  repo_score is a PRESENTED score out of 65, not a raw total out of
//	       100, and summary.repo_score_max was added to state the denominator.
//
// The minor version stayed at 0 and the major moved deliberately. The field
// NAMES did not change, which is exactly what makes this breaking: a consumer
// written against 1.0.0 keeps parsing `repo_score` successfully and keeps
// rendering it as "25/100", which is wrong by 35%, with nothing in the
// document to tell it. That is a semantic break, so it is a major bump, and
// the new field is the thing that makes it detectable without one.
const SchemaVersion = "2.0.0"

// Ecosystem names. Kept as string constants rather than an enum type so that
// unknown ecosystems parsed from a config file don't blow up unmarshalling.
const (
	EcoNPM   = "npm"
	EcoPyPI  = "pypi"
	EcoGo    = "go"
	EcoCargo = "cargo"
)

// LockfileFormat names a package manager's lockfile. It is NOT an
// ecosystem: yarn and pnpm produce npm packages, and they resolve under
// EcoNPM so their components match OSV records for npm rather than going
// unmatched under a name OSV has never heard of.
//
// The format is tracked separately because a yarn.lock, a pnpm-lock.yaml
// and a package-lock.json describe the same dependency graph three
// different ways, and silently treating them as one format is how a
// resolver ends up parsing a pnpm lockfile with an npm parser and
// reporting a parse error -- or worse, zero components and a clean scan.
const (
	FormatNPM       = "package-lock.json"
	FormatYarn      = "yarn.lock"
	FormatPnpm      = "pnpm-lock.yaml"
	FormatPyPI      = "requirements.txt"
	FormatPoetry    = "poetry.lock"
	FormatPyProject = "pyproject.toml"
	FormatGoSum     = "go.sum"
	FormatGoMod     = "go.mod"
	FormatCargo     = "Cargo.lock"
)

// EcoForFormat maps a lockfile name to the ecosystem its components belong
// to. Returning "" means the file is not a lockfile this build knows.
func EcoForFormat(name string) string {
	switch filepath.Base(name) {
	case FormatNPM, FormatYarn, FormatPnpm:
		return EcoNPM
	case FormatPyPI, FormatPoetry, FormatPyProject:
		return EcoPyPI
	case FormatGoSum, FormatGoMod:
		return EcoGo
	case FormatCargo:
		return EcoCargo
	}
	return ""
}

// Component is a single resolved dependency.
type Component struct {
	Purl      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Direct    bool   `json:"direct"`
	License   string `json:"license,omitempty"`
	// Hashes holds content hashes from the lockfile, keyed by algorithm.
	Hashes map[string]string `json:"hashes,omitempty"`
	// LatestVersion is filled in by the freshness scorer, not the resolver.
	LatestVersion string `json:"latest_version,omitempty"`

	Vulnerabilities []Vuln `json:"vulnerabilities"`
	Score           *Score `json:"score,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
}

// Vuln is the normalized vulnerability record that OSV, NVD and GHSA results
// all collapse into (FR-202).
type Vuln struct {
	ID           string   `json:"id"`
	Source       string   `json:"source"`
	CVSSv3       float64  `json:"cvss_v3"`
	CVSSVector   string   `json:"cvss_vector,omitempty"`
	EPSS         float64  `json:"epss"`
	Summary      string   `json:"summary,omitempty"`
	Aliases      []string `json:"aliases,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	// Introduced/LastAffected come from OSV range data and drive matching.
	Introduced   string `json:"introduced,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	// URL points at the advisory for humans.
	URL string `json:"url,omitempty"`
}

// Score is the per-component risk breakdown. Every field is kept so
// `scram scan --explain` can show the actual arithmetic (FR-303).
type Score struct {
	Total          int `json:"total"`
	Severity       int `json:"severity"`
	Exploitability int `json:"exploitability"`
	Maintenance    int `json:"maintenance"`
	Freshness      int `json:"freshness"`
}

// Component contributes a slice of the score's 100 points, so a component
// with only freshness problems lands much lower than one with a live CVE.
const (
	MaxSeverityPoints       = 40
	MaxExploitabilityPoints = 25
	MaxMaintenancePoints    = 20
	MaxFreshnessPoints      = 15
	MaxScore                = 100
)

// PresentedMax is the denominator every score shown to a human is divided
// by, and it is NOT MaxScore.
//
// The four terms are computed in MaxScore units and the formula is
// unchanged. What changed is the claim. Presenting "24/100" implies the
// remaining 76 points were lost to risk, when in the general case they
// were never available to earn:
//
//   - exploitability needs EPSS, which is a per-CVE fetch that returns
//     nothing offline or when FIRST is unreachable;
//   - maintenance needs an OpenSSF Scorecard for the repository, which
//     exists for some projects and not others; and
//   - freshness needs latest-version data, which this project does not
//     collect, so it is structurally 0 everywhere.
//
// Measured across six real projects (scripts/measure_score_terms.sh),
// severity is the only term that carried data without an opt-in flag, and
// exploitability is the only other term that can. A 100-point
// denominator therefore advertised signal the tool does not have.
//
// Presenting against 65 does not make exploitability's absence stop
// matter: `--explain` still prints its own "/25" line, and marks the term
// no-data rather than zero-risk. It stops the TOTAL from implying a
// precision that the inputs do not support.
//
// The trade is accepted knowingly. A project with no EPSS data will show a
// lower score against a smaller denominator, which is why a scan that
// cannot reach FIRST is called out in the output rather than silently
// scored.
const PresentedMax = MaxSeverityPoints + MaxExploitabilityPoints

// Bucket names, ordered by severity.
const (
	BucketCritical = "critical"
	BucketHigh     = "high"
	BucketMedium   = "medium"
	BucketLow      = "low"
	BucketClean    = "clean"
)

// SeverityRank maps a bucket to an integer for comparisons and for the
// `--fail-on` threshold check. Higher is worse.
var SeverityRank = map[string]int{
	BucketCritical: 5,
	BucketHigh:     4,
	BucketMedium:   3,
	BucketLow:      2,
	BucketClean:    1,
}

// AtLeast reports whether bucket is at least as severe as threshold.
func AtLeast(bucket, threshold string) bool {
	return SeverityRank[bucket] >= SeverityRank[threshold]
}

// Score is the result of one scan of one repository.
type Scan struct {
	SchemaVersion string      `json:"schema_version"`
	Repo          string      `json:"repo"`
	Commit        string      `json:"commit,omitempty"`
	Components    []Component `json:"components"`
	Summary       Summary     `json:"summary"`
	Warnings      []string    `json:"warnings,omitempty"`
}

// Summary is the repo-level rollup.
type Summary struct {
	RepoScore int `json:"repo_score"`
	// RepoScoreMax is the denominator for RepoScore.
	//
	// This is not a convenience field. RepoScore is a PRESENTED score, out
	// of 65, and the value is a bare integer in JSON. A consumer that reads
	// it as out of 100 -- which the previous schema_version implied -- is
	// wrong by 35%, silently, with no field to contradict it. Emitting the
	// denominator alongside the numerator makes the document self-describing,
	// so the scale is a fact in the data rather than something the reader has
	// to know.
	//
	// The raw formula total (0-100) is a different number and is NOT this
	// one; see --explain, which prints both.
	RepoScoreMax    int            `json:"repo_score_max"`
	RepoBucket      string         `json:"repo_bucket"`
	TotalComponents int            `json:"total_components"`
	Counts          map[string]int `json:"counts_by_bucket"`
	VulnTotal       int            `json:"vuln_total"`
	NewHigh         int            `json:"new_high_count"`
	NewCritical     int            `json:"new_critical_count"`
	// NewVulnIDs lists vulnerabilities present now but not in the baseline.
	NewVulnIDs []string `json:"new_vuln_ids,omitempty"`
}

// ChangeType categorizes a component's state between two scans (FR-402).
const (
	ChangeAdded          = "added"
	ChangeRemoved        = "removed"
	ChangeVersionChanged = "version_changed"
	ChangeUnchanged      = "unchanged"
)

// Drift is one component's diff between a baseline scan and a current scan.
type Drift struct {
	Purl                    string   `json:"purl"`
	Name                    string   `json:"name,omitempty"`
	Change                  string   `json:"change"`
	PreviousVersion         string   `json:"previous_version,omitempty"`
	NewVersion              string   `json:"new_version,omitempty"`
	NewVulnerabilities      []string `json:"new_vulnerabilities"`
	ResolvedVulnerabilities []string `json:"resolved_vulnerabilities"`
	ScoreDelta              int      `json:"score_delta"`
	ScoreBefore             int      `json:"score_before"`
	ScoreAfter              int      `json:"score_after"`
	// Bucket is the worse of before/after, so gating can look at one field.
	Bucket string `json:"bucket,omitempty"`
}

// DiffResult is a full drift comparison.
type DiffResult struct {
	SchemaVersion string  `json:"schema_version"`
	Base          string  `json:"base,omitempty"`
	Head          string  `json:"head,omitempty"`
	Drifts        []Drift `json:"drifts"`
	Summary       Summary `json:"summary"`
}

// Baseline is the on-disk snapshot format written by `scram baseline update`.
// Plain JSON with sorted keys so it diffs cleanly in a PR (FR-404).
type Baseline struct {
	SchemaVersion string      `json:"schema_version"`
	GeneratedAt   string      `json:"generated_at"`
	Repo          string      `json:"repo"`
	Commit        string      `json:"commit,omitempty"`
	Components    []Component `json:"components"`
	Summary       Summary     `json:"summary"`
}
