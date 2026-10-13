// Package drift compares two scans and reports what changed (FR-4xx). This
// is SCRAM's differentiator: not "what is broken now" but "what did this PR
// change".
package drift

import (
	"encoding/json"
	"fmt"
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
	out := model.DiffResult{SchemaVersion: model.SchemaVersion, Base: base.Repo + "@" + base.Commit, Head: head.Repo + "@" + head.Commit, Drifts: []model.Drift{}, Summary: head.Summary}
	before, after := groupComponents(base.Components), groupComponents(head.Components)
	groups := map[string]bool{}
	for k := range before {
		groups[k] = true
	}
	for k := range after {
		groups[k] = true
	}
	newIDs := map[string]bool{}
	out.Summary.NewHigh, out.Summary.NewCritical = 0, 0
	for _, key := range sortedKeys(groups) {
		bs, hs := before[key], after[key]
		usedB, usedH := make([]bool, len(bs)), make([]bool, len(hs))
		appendPair := func(b, h *model.Component) {
			d := componentDrift(b, h)
			out.Drifts = append(out.Drifts, d)
			if h == nil {
				return
			}
			fresh := map[string]bool{}
			for _, id := range d.NewVulnerabilities {
				newIDs[id] = true
				fresh[id] = true
			}
			for _, v := range h.Vulnerabilities {
				if !fresh[v.ID] {
					continue
				}
				vb := score.BucketForCVSS(int(v.CVSSv3 * 10))
				if model.AtLeast(vb, model.BucketHigh) {
					out.Summary.NewHigh++
				}
				if vb == model.BucketCritical {
					out.Summary.NewCritical++
				}
			}
		}
		// Preserve exact identities before considering version replacements.
		for i := range bs {
			for j := range hs {
				if !usedH[j] && componentIdentity(bs[i]) == componentIdentity(hs[j]) {
					usedB[i], usedH[j] = true, true
					appendPair(&bs[i], &hs[j])
					break
				}
			}
		}
		var leftB, leftH []int
		for i := range bs {
			if !usedB[i] {
				leftB = append(leftB, i)
			}
		}
		for j := range hs {
			if !usedH[j] {
				leftH = append(leftH, j)
			}
		}
		// Only a unique unmatched version pair has unambiguous replacement
		// semantics. Multiple unmatched versions remain explicit adds/removals.
		if len(leftB) == 1 && len(leftH) == 1 && bs[leftB[0]].Version != hs[leftH[0]].Version {
			appendPair(&bs[leftB[0]], &hs[leftH[0]])
		} else {
			for _, i := range leftB {
				appendPair(&bs[i], nil)
			}
			for _, j := range leftH {
				appendPair(nil, &hs[j])
			}
		}
	}
	sort.SliceStable(out.Drifts, func(i, j int) bool {
		if out.Drifts[i].Purl != out.Drifts[j].Purl {
			return out.Drifts[i].Purl < out.Drifts[j].Purl
		}
		return out.Drifts[i].Change < out.Drifts[j].Change
	})
	out.Summary.NewVulnIDs = sortedKeys(newIDs)
	return out
}

func componentIdentity(c model.Component) string {
	if c.Purl != "" {
		return c.Purl
	}
	return c.Ecosystem + ":" + c.Name + "@" + c.Version
}

func groupComponents(comps []model.Component) map[string][]model.Component {
	out := map[string][]model.Component{}
	for _, c := range comps {
		key := c.Ecosystem + ":" + c.Name
		out[key] = append(out[key], c)
	}
	for key := range out {
		sort.Slice(out[key], func(i, j int) bool { return componentIdentity(out[key][i]) < componentIdentity(out[key][j]) })
	}
	return out
}

func componentDrift(b, h *model.Component) model.Drift {
	d := model.Drift{}
	if b != nil {
		d.Purl = b.Purl
		d.Name = b.Name
		d.PreviousVersion = b.Version
		d.ScoreBefore = scoreOf(*b)
		d.Bucket = b.Bucket
	}
	if h != nil {
		d.Purl = h.Purl
		d.Name = h.Name
		d.NewVersion = h.Version
		d.ScoreAfter = scoreOf(*h)
		d.Bucket = worseBucket(d.Bucket, h.Bucket)
	}
	switch {
	case b == nil:
		d.Change = model.ChangeAdded
	case h == nil:
		d.Change = model.ChangeRemoved
	case b.Version != h.Version:
		d.Change = model.ChangeVersionChanged
	default:
		d.Change = model.ChangeUnchanged
	}
	d.ScoreDelta = d.ScoreAfter - d.ScoreBefore
	var bv, hv []model.Vuln
	if b != nil {
		bv = b.Vulnerabilities
	}
	if h != nil {
		hv = h.Vulnerabilities
	}
	for _, v := range hv {
		if !hasEquivalent(bv, v) {
			d.NewVulnerabilities = append(d.NewVulnerabilities, v.ID)
		}
	}
	for _, v := range bv {
		if !hasEquivalent(hv, v) {
			d.ResolvedVulnerabilities = append(d.ResolvedVulnerabilities, v.ID)
		}
	}
	sort.Strings(d.NewVulnerabilities)
	sort.Strings(d.ResolvedVulnerabilities)
	return d
}

// Primary IDs can change when upstream metadata or representative selection
// changes. Shared aliases keep the same advisory from looking newly disclosed.
func hasEquivalent(vs []model.Vuln, target model.Vuln) bool {
	ids := map[string]bool{}
	if target.ID != "" {
		ids[target.ID] = true
	}
	for _, a := range target.Aliases {
		if a != "" {
			ids[a] = true
		}
	}
	for _, v := range vs {
		if ids[v.ID] {
			return true
		}
		for _, a := range v.Aliases {
			if ids[a] {
				return true
			}
		}
	}
	return false
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
		Components:    append([]model.Component(nil), scan.Components...),
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
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(b, &shape); err != nil {
		return model.Scan{}, err
	}
	if _, ok := shape["scan"]; ok {
		return model.Scan{}, fmt.Errorf("%s is a scan report, not a baseline; use scram baseline update", path)
	}
	if _, ok := shape["components"]; !ok {
		return model.Scan{}, fmt.Errorf("%s is not a baseline: missing components", path)
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
		if !os.IsNotExist(err) {
			return model.Scan{}, err
		}
		return model.Scan{
			SchemaVersion: model.SchemaVersion,
			Components:    []model.Component{},
		}, nil
	}
	return ReadBaseline(path)
}
