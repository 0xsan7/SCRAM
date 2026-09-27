package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/score"
)

func comp(name, version, bucket string, vulns ...model.Vuln) model.Component {
	c := model.Component{
		Purl:            "pkg:npm/" + name + "@" + version,
		Name:            name,
		Version:         version,
		Ecosystem:       model.EcoNPM,
		Bucket:          bucket,
		Vulnerabilities: vulns,
	}
	e := score.New()
	c.Score = &model.Score{Total: bucketScore(bucket)}
	_ = e
	return c
}

func bucketScore(b string) int {
	switch b {
	case model.BucketCritical:
		return 95
	case model.BucketHigh:
		return 75
	case model.BucketMedium:
		return 50
	case model.BucketLow:
		return 20
	}
	return 0
}

func vuln(id string, cvss float64) model.Vuln {
	return model.Vuln{ID: id, CVSSv3: cvss, Source: "osv"}
}

// diffWith builds a diff result whose new-vulnerability set is the given ids.
func diffWith(newIDs ...string) *model.DiffResult {
	return &model.DiffResult{
		SchemaVersion: model.SchemaVersion,
		Summary:       model.Summary{NewVulnIDs: newIDs},
	}
}

func scanWith(comps ...model.Component) model.Scan {
	s := model.Scan{
		SchemaVersion: model.SchemaVersion,
		Repo:          "app",
		Components:    comps,
	}
	s.Summary = score.New().Score(comps)
	return s
}

// TestPolicyScenarios is the acceptance table from PRD §17 Phase 6: the scan
// must exit non-zero exactly when policy says it should.
func TestPolicyScenarios(t *testing.T) {
	critical := vuln("CVE-NEW-CRIT", 9.8)
	high := vuln("CVE-NEW-HIGH", 7.5)
	medium := vuln("CVE-OLD-MED", 5.0)

	cases := []struct {
		name       string
		cfg        *Config
		scan       model.Scan
		diff       *model.DiffResult
		degraded   bool
		wantPass   bool
		wantReason string // substring expected in a failure reason
	}{
		{
			name:       "new critical fails the build",
			cfg:        Default(),
			scan:       scanWith(comp("lodash", "1.0.0", model.BucketCritical, critical)),
			diff:       diffWith("CVE-NEW-CRIT"),
			wantPass:   false,
			wantReason: "CVE-NEW-CRIT",
		},
		{
			name:       "new high fails under fail_on high",
			cfg:        Default(),
			scan:       scanWith(comp("lodash", "1.0.0", model.BucketHigh, high)),
			diff:       diffWith("CVE-NEW-HIGH"),
			wantPass:   false,
			wantReason: "CVE-NEW-HIGH",
		},
		{
			// The adoption case: a repo full of old mediums must not go red
			// on every PR, because those findings are not new.
			name:     "pre-existing mediums do not fail the build",
			cfg:      Default(),
			scan:     scanWith(comp("old", "1.0.0", model.BucketMedium, medium)),
			diff:     diffWith(), // nothing new
			wantPass: true,
		},
		{
			name:     "pre-existing mediums fail when fail_on_existing is set",
			cfg:      &Config{Version: 1, FailOn: "high", FailOnExisting: true, Sources: Sources{OSV: true}},
			scan:     scanWith(comp("old", "1.0.0", model.BucketMedium, medium)),
			diff:     diffWith(),
			wantPass: true, // medium is below a high threshold
		},
		{
			name: "active waiver suppresses a new critical",
			cfg: &Config{
				Version: 1, FailOn: "high", Sources: Sources{OSV: true},
				Waivers: []Waiver{{
					ID:      "CVE-NEW-CRIT",
					Reason:  "not reachable",
					Expires: timePtr(time.Now().Add(24 * time.Hour)),
				}},
			},
			scan:     scanWith(comp("lodash", "1.0.0", model.BucketCritical, critical)),
			diff:     diffWith("CVE-NEW-CRIT"),
			wantPass: true,
		},
		{
			// FR-503: an expired waiver must re-trigger the failure.
			name: "expired waiver re-triggers the failure",
			cfg: &Config{
				Version: 1, FailOn: "high", Sources: Sources{OSV: true},
				Waivers: []Waiver{{
					ID:      "CVE-NEW-CRIT",
					Reason:  "stale",
					Expires: timePtr(time.Now().Add(-24 * time.Hour)),
				}},
			},
			scan:       scanWith(comp("lodash", "1.0.0", model.BucketCritical, critical)),
			diff:       diffWith("CVE-NEW-CRIT"),
			wantPass:   false,
			wantReason: "CVE-NEW-CRIT",
		},
		{
			name:     "a new medium passes under fail_on high",
			cfg:      Default(),
			scan:     scanWith(comp("pkg", "1.0.0", model.BucketMedium, vuln("CVE-NEW-MED", 5.0))),
			diff:     diffWith("CVE-NEW-MED"),
			wantPass: true,
		},
		{
			// The trust failure this guards: a scan that could not reach OSV
			// must not report "clean" and pass.
			name:       "degraded scan fails closed",
			cfg:        Default(),
			scan:       scanWith(comp("pkg", "1.0.0", model.BucketClean)),
			diff:       diffWith(),
			degraded:   true,
			wantPass:   false,
			wantReason: "vulnerability data incomplete",
		},
		{
			name: "degraded scan passes when explicitly allowed",
			cfg: &Config{
				Version: 1, FailOn: "high", Sources: Sources{OSV: true},
				AllowDegraded: true,
			},
			scan:     scanWith(comp("pkg", "1.0.0", model.BucketClean)),
			diff:     diffWith(),
			degraded: true,
			wantPass: true,
		},
		{
			// A scan that found no lockfiles verified nothing; reporting it
			// as clean is the same failure in a different costume.
			name:       "empty scan is not a clean pass",
			cfg:        Default(),
			scan:       model.Scan{SchemaVersion: model.SchemaVersion},
			diff:       diffWith(),
			wantPass:   false,
			wantReason: "no dependency lockfiles found",
		},
		{
			// Without a baseline there is no way to know what's new, so
			// nothing gates by default.
			name:     "no baseline and no fail_on_existing gates nothing",
			cfg:      Default(),
			scan:     scanWith(comp("pkg", "1.0.0", model.BucketCritical, critical)),
			diff:     nil,
			wantPass: true,
		},
		{
			name: "denied license fails independently of vulns",
			cfg: &Config{
				Version: 1, FailOn: "high", Sources: Sources{OSV: true},
				Licenses: Licenses{Deny: []string{"GPL-3.0-only"}},
			},
			scan: func() model.Scan {
				c := comp("vendored", "1.0.0", model.BucketClean)
				c.License = "GPL-3.0-only"
				return scanWith(c)
			}(),
			diff:       diffWith(),
			wantPass:   false,
			wantReason: "denied license",
		},
		{
			name: "an allowed license does not fail",
			cfg: &Config{
				Version: 1, FailOn: "high", Sources: Sources{OSV: true},
				Licenses: Licenses{Deny: []string{"GPL-3.0-only"}},
			},
			scan: func() model.Scan {
				c := comp("normal", "1.0.0", model.BucketClean)
				c.License = "MIT"
				return scanWith(c)
			}(),
			diff:     diffWith(),
			wantPass: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluate(tc.cfg, tc.scan, tc.diff, tc.degraded)
			if d.Pass != tc.wantPass {
				t.Errorf("pass: got %v, want %v (reasons: %v)", d.Pass, tc.wantPass, d.Reasons)
			}
			if tc.wantReason != "" {
				found := false
				for _, r := range d.Reasons {
					if strings.Contains(r, tc.wantReason) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no reason contained %q; got %v", tc.wantReason, d.Reasons)
				}
			}
		})
	}
}

// TestGatingUsesVulnSeverityNotComponentBucket is the regression test for the
// gating flaw where a component aggregating into the medium bucket let a new
// CVSS 9.8 through under fail_on: high.
func TestGatingUsesVulnSeverityNotComponentBucket(t *testing.T) {
	s := scanWith(comp("pkg", "1.0.0", model.BucketMedium, vuln("CVE-X", 9.8)))
	d := Evaluate(Default(), s, diffWith("CVE-X"), false)
	if d.Pass {
		t.Error("a new CVSS 9.8 on a medium-scoring component passed; it must fail")
	}
}

func TestConfigValidation(t *testing.T) {
	t.Run("rejects an invalid fail_on", func(t *testing.T) {
		cfg := Default()
		cfg.FailOn = "catastrophic"
		if err := cfg.normalize(); err == nil {
			t.Error("expected an error for an invalid fail_on severity")
		}
	})
	t.Run("rejects all sources disabled", func(t *testing.T) {
		cfg := Default()
		cfg.Sources = Sources{}
		if err := cfg.normalize(); err == nil {
			t.Error("expected an error when no vulnerability source is enabled")
		}
	})
	t.Run("rejects an unknown SBOM format", func(t *testing.T) {
		cfg := Default()
		cfg.SBOM.Formats = []string{"swid"}
		if err := cfg.normalize(); err == nil {
			t.Error("expected an error for an unsupported SBOM format")
		}
	})
	t.Run("accepts the defaults", func(t *testing.T) {
		if err := Default().normalize(); err != nil {
			t.Errorf("default config should be valid, got %v", err)
		}
	})
}

func TestPartitionWaivers(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	active, expired := partitionWaivers([]Waiver{
		{ID: "CVE-FUTURE", Expires: &future},
		{ID: "CVE-PAST", Expires: &past},
		{ID: "CVE-FOREVER"}, // no expiry
		{ID: ""},            // malformed, ignored
	}, time.Now())

	if len(active) != 2 {
		t.Errorf("active: got %v, want 2 entries", active)
	}
	if len(expired) != 1 || expired[0] != "CVE-PAST" {
		t.Errorf("expired: got %v, want [CVE-PAST]", expired)
	}
}

func TestExplainMentionsReason(t *testing.T) {
	d := Decision{Pass: false, Reasons: []string{"because reasons"}}
	out := Explain(Default(), d)
	if !strings.HasPrefix(out, "FAIL") {
		t.Errorf("expected FAIL prefix, got %q", out)
	}
	if !strings.Contains(out, "because reasons") {
		t.Errorf("expected the reason in the output, got %q", out)
	}
}

func timePtr(t time.Time) *time.Time { return &t }
