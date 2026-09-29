// Package drift compares two scans and reports what changed (FR-4xx). This
// is SCRAM's differentiator: not "what is broken now" but "what did this PR
// change".
package drift

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/score"
)

// DefaultBaselinePath is where `scram baseline update` writes by default.
const DefaultBaselinePath = ".scram/baseline.json"

// Diff categorizes every component between a baseline and a current scan.
func Diff(base, head model.Scan) model.DiffResult {
	baseComps := indexByName(base.Components)
	headComps := indexByName(head.Components)

	// Union of every component seen on either side, in a stable order.
	names := map[string]bool{}
	for k := range baseComps {
		names[k] = true
	}
	for k := range headComps {
		names[k] = true
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := model.DiffResult{
		SchemaVersion: model.SchemaVersion,
		Base:          base.Repo + "@" + base.Commit,
		Head:          head.Repo + "@" + head.Commit,
		Drifts:        []model.Drift{},
	}

	// Aggregate new vulnerabilities across the whole diff, so the summary can
	// report counts without walking the drift list.
	newVulnSet := map[string]bool{}
	var newHigh, newCritical int

	for _, k := range keys {
		b, hasBase := baseComps[k]
		h, hasHead := headComps[k]

		switch {
		case !hasBase && hasHead:
			// Entirely new component. Every vuln it brings is a new vuln,
			// including vulns that were already in the baseline under a
			// different component — a new copy of a vulnerable package is
			// still new exposure.
			d := model.Drift{
				Purl:       h.Purl,
				Name:       h.Name,
				Change:     model.ChangeAdded,
				NewVersion: h.Version,
				ScoreAfter: scoreOf(h),
				Bucket:     h.Bucket,
			}
			for _, v := range h.Vulnerabilities {
				d.NewVulnerabilities = append(d.NewVulnerabilities, v.ID)
				newVulnSet[v.ID] = true
				// Rate by the vulnerability's own CVSS, for the same reason
				// as the version-changed branch: a brand-new component can
				// aggregate into the medium bucket while carrying a 9.8.
				vb := score.BucketForCVSS(int(v.CVSSv3 * 10))
				if model.AtLeast(vb, model.BucketHigh) {
					newHigh++
				}
				if vb == model.BucketCritical {
					newCritical++
				}
			}
			out.Drifts = append(out.Drifts, d)

		case hasBase && !hasHead:
			d := model.Drift{
				Purl:            b.Purl,
				Name:            b.Name,
				Change:          model.ChangeRemoved,
				PreviousVersion: b.Version,
				ScoreBefore:     scoreOf(b),
				Bucket:          b.Bucket,
			}
			for _, v := range b.Vulnerabilities {
				d.ResolvedVulnerabilities = append(d.ResolvedVulnerabilities, v.ID)
			}
			out.Drifts = append(out.Drifts, d)

		default:
			// Present on both sides. The ecosystem and name match, so the
			// only real change possible is a version bump (a monorepo with
			// two copies of one dep is keyed apart by version).
			d := model.Drift{
				Purl:            h.Purl,
				Name:            h.Name,
				PreviousVersion: b.Version,
				NewVersion:      h.Version,
				ScoreBefore:     scoreOf(b),
				ScoreAfter:      scoreOf(h),
				ScoreDelta:      scoreOf(h) - scoreOf(b),
				Bucket:          worseBucket(b.Bucket, h.Bucket),
			}
			if b.Version != h.Version {
				d.Change = model.ChangeVersionChanged
			} else {
				d.Change = model.ChangeUnchanged
			}

			baseVulns := vulnSet(b)
			headVulns := vulnSet(h)
			for id := range headVulns {
				if !baseVulns[id] {
					d.NewVulnerabilities = append(d.NewVulnerabilities, id)
					newVulnSet[id] = true
				}
			}
			for id := range baseVulns {
				if !headVulns[id] {
					d.ResolvedVulnerabilities = append(d.ResolvedVulnerabilities, id)
				}
			}
			sort.Strings(d.NewVulnerabilities)
			sort.Strings(d.ResolvedVulnerabilities)

			// Count new findings toward gating only when the component
			// actually changed, and rate each new vulnerability by its OWN
			// CVSS rather than the component's aggregate score. A component
			// can sit in the medium bucket overall while a newly introduced
			// CVE in it is a 9.8, and reporting "new high: 0" for that
			// would be actively misleading.
			if d.Change == model.ChangeVersionChanged {
				for _, nv := range h.Vulnerabilities {
					if !baseVulns[nv.ID] {
						vb := score.BucketForCVSS(int(nv.CVSSv3 * 10))
						if model.AtLeast(vb, model.BucketHigh) {
							newHigh++
						}
						if vb == model.BucketCritical {
							newCritical++
						}
					}
				}
			}
			out.Drifts = append(out.Drifts, d)
		}
	}

	out.Summary = head.Summary
	out.Summary.NewVulnIDs = sortedKeys(newVulnSet)
	out.Summary.NewHigh = newHigh
	out.Summary.NewCritical = newCritical
	return out
}

// indexByName keys components by ecosystem+name, keeping the highest version
// when a repo contains multiple copies of the same dependency (common in
// monorepos with conflicting transitive requirements).
func indexByName(comps []model.Component) map[string]model.Component {
	out := map[string]model.Component{}
	for _, c := range comps {
		key := c.Ecosystem + ":" + c.Name
		if prev, ok := out[key]; !ok || c.Version > prev.Version {
			out[key] = c
		}
	}
	return out
}

func vulnSet(c model.Component) map[string]bool {
	out := map[string]bool{}
	for _, v := range c.Vulnerabilities {
		out[v.ID] = true
	}
	return out
}

func scoreOf(c model.Component) int {
	if c.Score == nil {
		return 0
	}
	return c.Score.Total
}

func worseBucket(a, b string) string {
	if model.SeverityRank[a] >= model.SeverityRank[b] {
		return a
	}
	return b
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// WriteBaseline serializes a scan as a baseline (FR-401). Output is indented
// with sorted keys and a trailing newline so it diffs cleanly in a PR (FR-404).
func WriteBaseline(path string, scan model.Scan) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b := model.Baseline{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Repo:          scan.Repo,
		Commit:        scan.Commit,
		Components:    scan.Components,
		Summary:       scan.Summary,
	}
	// Components are already sorted by resolve.Dedupe, but a scan assembled
	// some other way might not be; sort here so the on-disk file is stable.
	sort.Slice(b.Components, func(i, j int) bool {
		if b.Components[i].Ecosystem != b.Components[j].Ecosystem {
			return b.Components[i].Ecosystem < b.Components[j].Ecosystem
		}
		if b.Components[i].Name != b.Components[j].Name {
			return b.Components[i].Name < b.Components[j].Name
		}
		return b.Components[i].Version < b.Components[j].Version
	})

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ReadBaseline loads a baseline file written by WriteBaseline.
func ReadBaseline(path string) (model.Scan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return model.Scan{}, err
	}
	var bl model.Baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		return model.Scan{}, err
	}
	if bl.SchemaVersion == "" {
		// A baseline written before schema versioning existed.
		bl.SchemaVersion = model.SchemaVersion
	}
	return model.Scan{
		SchemaVersion: bl.SchemaVersion,
		Repo:          bl.Repo,
		Commit:        bl.Commit,
		Components:    bl.Components,
		Summary:       bl.Summary,
	}, nil
}

// Load reads a baseline, returning an empty scan if the file doesn't exist.
// A missing baseline is a normal state (first run), not an error.
func Load(path string) (model.Scan, error) {
	if _, err := os.Stat(path); err != nil {
		return model.Scan{
			SchemaVersion: model.SchemaVersion,
			Components:    []model.Component{},
		}, nil
	}
	return ReadBaseline(path)
}
