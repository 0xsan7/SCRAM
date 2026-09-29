// Package policy implements .scram.yml parsing and the CI gating decision
// (FR-5xx).
//
// The governing rule, and the reason this tool is adoptable: by default the
// fail-on threshold applies only to findings that are NEW relative to the
// baseline. A repo with 200 pre-existing medium-severity findings can adopt
// SCRAM on day one without every PR going red.
package policy

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/score"
	"gopkg.in/yaml.v3"
)

// ConfigName is the per-repo policy file.
const ConfigName = ".scram.yml"

// Config mirrors the §11 schema.
type Config struct {
	Version    int      `yaml:"version" json:"version"`
	Ecosystems []string `yaml:"ecosystems" json:"ecosystems,omitempty"`
	FailOn     string   `yaml:"fail_on" json:"fail_on"`
	// FailOnExisting additionally gates on pre-existing findings.
	FailOnExisting bool     `yaml:"fail_on_existing" json:"fail_on_existing"`
	SBOM           SBOMConf `yaml:"sbom" json:"sbom"`
	Sources        Sources  `yaml:"sources" json:"sources"`
	Waivers        []Waiver `yaml:"waivers" json:"waivers,omitempty"`
	Licenses       Licenses `yaml:"licenses" json:"licenses,omitempty"`
	IgnorePaths    []string `yaml:"ignore_paths" json:"ignore_paths,omitempty"`
	// AllowDegraded lets a user explicitly accept a scan that couldn't reach
	// its vulnerability sources. Off by default: a network outage must not
	// turn into a green build that asserts the repo is clean.
	AllowDegraded bool `yaml:"allow_degraded_scan" json:"allow_degraded_scan,omitempty"`

	// CacheTTLHours overrides the 6h vulnerability cache default.
	CacheTTLHours float64 `yaml:"cache_ttl_hours" json:"cache_ttl_hours,omitempty"`
	// Offline forces cache-only operation (NFR-6).
	Offline bool `yaml:"offline" json:"offline,omitempty"`
	// EPSS enables exploitability scoring. Off by default because it
	// roughly doubles outbound request count.
	EPSS bool `yaml:"epss" json:"epss,omitempty"`
}

type SBOMConf struct {
	Formats []string `yaml:"formats" json:"formats,omitempty"`
}

type Sources struct {
	OSV  bool `yaml:"osv" json:"osv"`
	NVD  bool `yaml:"nvd" json:"nvd"`
	GHSA bool `yaml:"ghsa" json:"ghsa"`
}

// Waiver suppresses a specific vulnerability for a bounded time (FR-503).
type Waiver struct {
	ID      string     `yaml:"id" json:"id"`
	Reason  string     `yaml:"reason" json:"reason"`
	Expires *time.Time `yaml:"expires" json:"expires,omitempty"`
}

type Licenses struct {
	Deny []string `yaml:"deny" json:"deny,omitempty"`
}

// Default returns the config used when no .scram.yml is present (FR-501).
func Default() *Config {
	return &Config{
		Version: 1,
		FailOn:  "high",
		SBOM:    SBOMConf{Formats: []string{"cyclonedx"}},
		Sources: Sources{OSV: true},
	}
}

// Load reads .scram.yml from root. A missing file is not an error — defaults
// apply (FR-501).
func Load(root string) (*Config, error) {
	cfg := Default()
	path := root + "/" + ConfigName
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	// Validate rather than trusting the file, since a typo in fail_on would
	// otherwise silently mean "never fail".
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) normalize() error {
	c.FailOn = strings.ToLower(strings.TrimSpace(c.FailOn))
	if _, ok := model.SeverityRank[c.FailOn]; !ok {
		return fmt.Errorf("fail_on: %q is not a severity (use clean, low, medium, high, or critical)", c.FailOn)
	}
	if c.SBOM.Formats == nil {
		c.SBOM.Formats = []string{"cyclonedx"}
	}
	valid := map[string]bool{"cyclonedx": true, "spdx": true}
	for _, f := range c.SBOM.Formats {
		f = strings.ToLower(strings.TrimSpace(f))
		if !valid[f] {
			return fmt.Errorf("sbom.formats: %q is not supported (use cyclonedx or spdx)", f)
		}
	}
	// No source enabled means the tool silently reports "clean", which is the
	// worst possible failure mode for a security scanner.
	if !c.Sources.OSV && !c.Sources.NVD && !c.Sources.GHSA {
		return fmt.Errorf("sources: at least one of osv, nvd, ghsa must be enabled")
	}
	if c.CacheTTLHours < 0 {
		return fmt.Errorf("cache_ttl_hours: must not be negative")
	}
	return nil
}

// FailOnBucket returns the effective threshold.
func (c *Config) FailOnBucket() string { return c.FailOn }

// CacheTTL returns the configured cache lifetime.
func (c *Config) CacheTTL() time.Duration {
	if c.CacheTTLHours <= 0 {
		return 0 // caller falls back to the vuln package default
	}
	return time.Duration(c.CacheTTLHours * float64(time.Hour))
}

// Decision is the outcome of evaluating policy against a scan.
type Decision struct {
	Pass    bool
	Reasons []string
	Waived  []string
	Expired []string
	// Degraded records that the scan could not fully check for
	// vulnerabilities, which is itself a failure unless explicitly allowed.
	Degraded bool
}

// Evaluate applies the policy to a scan and decides pass/fail (FR-502..505).
//
// diff may be nil (a plain `scram scan` with no baseline); in that case every
// finding counts as "new" only if FailOnExisting is set, otherwise nothing
// gates — because with no baseline there is no way to tell new from existing.
//
// degraded reports whether vulnerability data was incomplete. When it is, the
// decision fails unless the config opts in with allow_degraded_scan: a scan
// that could not reach OSV has not verified anything, and reporting that as
// "clean" is the single worst failure mode a security tool can have.
func Evaluate(cfg *Config, scan model.Scan, diff *model.DiffResult, degraded bool) Decision {
	d := Decision{Pass: true, Degraded: degraded}

	threshold := cfg.FailOn
	now := time.Now()

	// Collect the vulnerability ids that are subject to gating, plus the
	// waiver decision for each.
	waived, expired := partitionWaivers(cfg.Waivers, now)
	d.Waived = waived
	d.Expired = expired

	suppressed := map[string]bool{}
	for _, id := range waived {
		suppressed[id] = true
	}

	// Vulnerabilities present now.
	type finding struct {
		id     string
		purl   string
		bucket string
	}
	var newFindings []finding
	var allFindings []finding

	for _, c := range scan.Components {
		for _, v := range c.Vulnerabilities {
			// A finding's severity is the *worse* of the component's aggregate
			// bucket and the vulnerability's own CVSS severity.
			//
			// Using only the component bucket would be wrong in a way that
			// silently defeats the gate: a component can score medium overall
			// (41/100, dragged down by a low exploitability score) while
			// carrying a newly introduced CVSS 9.8. Gating on the component
			// alone would let that 9.8 through under `fail_on: high`.
			vulnBucket := score.BucketForCVSS(int(v.CVSSv3 * 10))
			f := finding{
				id:     v.ID,
				purl:   c.Purl,
				bucket: worseBucket(c.Bucket, vulnBucket),
			}
			allFindings = append(allFindings, f)
			// A vuln counts as new if the drift set says so.
			if isNewFinding(diff, v.ID) {
				newFindings = append(newFindings, f)
			}
		}
	}

	gateSet := newFindings
	if diff == nil {
		// No baseline: gate on everything only if explicitly asked.
		if cfg.FailOnExisting {
			gateSet = allFindings
		} else {
			gateSet = nil
		}
	} else if cfg.FailOnExisting {
		// Both new and pre-existing are in scope.
		gateSet = append(append([]finding{}, newFindings...), allFindings...)
	}

	for _, f := range gateSet {
		if suppressed[f.id] {
			continue
		}
		if !model.AtLeast(f.bucket, threshold) {
			continue
		}
		d.Reasons = append(d.Reasons, fmt.Sprintf(
			"%s affects %s (severity %s, at or above fail-on %s)",
			f.id, f.purl, f.bucket, threshold))
	}

	// License policy is an independent gate — a denied license fails even
	// with zero vulnerabilities (FR-505).
	denied := map[string]bool{}
	for _, l := range cfg.Licenses.Deny {
		denied[strings.ToLower(strings.TrimSpace(l))] = true
	}
	var licenseHits []string
	for _, c := range scan.Components {
		if c.License == "" {
			continue
		}
		if denied[strings.ToLower(c.License)] {
			licenseHits = append(licenseHits, fmt.Sprintf("%s (%s)", c.Purl, c.License))
		}
	}
	if len(licenseHits) > 0 {
		sort.Strings(licenseHits)
		// Report the count and a sample, not every hit — a single bad
		// transitive license can produce hundreds.
		shown := licenseHits
		if len(shown) > 5 {
			shown = shown[:5]
		}
		d.Reasons = append(d.Reasons, fmt.Sprintf(
			"%d component(s) use a denied license (showing %d): %s",
			len(licenseHits), len(shown), strings.Join(shown, ", ")))
	}

	// Expired waivers are re-surfaced even though the finding is suppressed,
	// so the reason for a still-red pipeline is visible.
	for _, e := range expired {
		d.Reasons = append(d.Reasons,
			fmt.Sprintf("waiver for %s has expired; re-evaluate or renew the waiver", e))
	}

	// Fail closed on an incomplete scan. A run that couldn't reach its
	// vulnerability sources has verified nothing, so "no findings" means
	// "no data" — and passing would assert a clean bill of health that was
	// never actually established.
	if degraded && !cfg.AllowDegraded {
		d.Reasons = append(d.Reasons,
			"vulnerability data incomplete (an upstream source was unreachable or rate-limited); "+
				"refusing to pass a scan that could not verify. "+
				"Set allow_degraded_scan: true in .scram.yml to accept this explicitly.")
	}

	// A scan that found no supported lockfiles also hasn't verified anything.
	// Reporting that as "clean" would be equally misleading.
	if len(scan.Components) == 0 {
		d.Reasons = append(d.Reasons,
			"no dependency lockfiles found, so nothing was scanned; "+
				"this is not a clean result")
	}

	d.Pass = len(d.Reasons) == 0
	return d
}

// worseBucket returns whichever of two buckets is more severe.
func worseBucket(a, b string) string {
	if model.SeverityRank[a] >= model.SeverityRank[b] {
		return a
	}
	return b
}

// isNewFinding reports whether a vuln id appears in the diff's new set.
func isNewFinding(diff *model.DiffResult, id string) bool {
	if diff == nil {
		return false
	}
	for _, n := range diff.Summary.NewVulnIDs {
		if n == id {
			return true
		}
	}
	return false
}

// partitionWaivers splits waivers into active and expired. An expired waiver
// does not suppress its finding — it re-triggers a fail (FR-503).
func partitionWaivers(ws []Waiver, now time.Time) (active, expired []string) {
	for _, w := range ws {
		if w.ID == "" {
			continue
		}
		if w.Expires == nil {
			// No expiry means permanent.
			active = append(active, w.ID)
			continue
		}
		if now.Before(*w.Expires) {
			active = append(active, w.ID)
		} else {
			expired = append(expired, w.ID)
		}
	}
	sort.Strings(active)
	sort.Strings(expired)
	return active, expired
}

// Explain renders a decision for the terminal, including the reason a waiver
// is or isn't in effect (FR-504).
func Explain(cfg *Config, d Decision) string {
	var b strings.Builder
	if d.Pass {
		b.WriteString("PASS")
	} else {
		b.WriteString("FAIL")
	}
	fmt.Fprintf(&b, "  (fail-on: %s, new findings only: %v)\n", cfg.FailOn, !cfg.FailOnExisting)
	if len(d.Reasons) == 0 {
		b.WriteString("  no findings at or above the threshold\n")
	}
	for _, r := range d.Reasons {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	for _, w := range d.Waived {
		fmt.Fprintf(&b, "  waived: %s\n", w)
	}
	return b.String()
}

// Starter is the generated .scram.yml from `scram init`.
const Starter = `version: 1

# Ecosystems to scan. Omit to auto-detect from lockfiles.
ecosystems: [npm, pypi, go]

# Severity threshold. Applied to findings NEW since the baseline, so
# pre-existing issues don't block every PR.
fail_on: high
fail_on_existing: false

sbom:
  formats: [cyclonedx, spdx]

sources:
  osv: true
  nvd: false   # requires NVD_API_KEY
  ghsa: false

# Suppress a specific vulnerability for a bounded time.
# waivers:
#   - id: CVE-2024-12345
#     reason: "Only used in build tooling, not reachable"
#     expires: 2026-12-31

# Optional license gate.
# licenses:
#   deny: [GPL-3.0-only]

# Enable EPSS exploitability scoring (adds ~2x outbound requests).
epss: false

# If a vulnerability source is unreachable, SCRAM fails the run rather than
# reporting a clean result it could not verify. Set this to true only if you
# accept that risk (e.g. a network-isolated runner).
allow_degraded_scan: false
`
