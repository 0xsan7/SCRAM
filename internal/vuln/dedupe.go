package vuln

import (
	"sort"

	"github.com/0xsan7/scram/internal/model"
)

// Dedupe merges vulnerabilities that are the same issue reported by more than
// one source (FR-203).
//
// The same bug is often reachable under both a CVE id and a GHSA id, so
// GHSA-primary results and CVE-primary results get matched through the alias
// graph. When two records collapse into one, the one with the most complete
// CVSS data wins, per FR-203.
func Dedupe(vulns []model.Vuln) []model.Vuln {
	if len(vulns) <= 1 {
		return vulns
	}

	// Union-find over records, linked whenever two records share any id
	// (primary id or alias). Two records are the same issue if their id sets
	// intersect.
	parent := make([]int, len(vulns))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	idOwner := map[string]int{}
	for i, v := range vulns {
		for _, id := range aliasSet(v) {
			if prev, ok := idOwner[id]; ok {
				union(prev, i)
			} else {
				idOwner[id] = i
			}
		}
	}

	groups := map[int][]int{}
	for i := range vulns {
		r := find(i)
		groups[r] = append(groups[r], i)
	}

	out := make([]model.Vuln, 0, len(groups))
	for _, members := range groups {
		best := vulns[members[0]]
		for _, idx := range members[1:] {
			if completeness(vulns[idx]) > completeness(best) {
				best = vulns[idx]
			}
		}
		// Merge aliases from every member so a consumer searching by any
		// known id finds this record.
		merged := map[string]bool{}
		for _, id := range aliasSet(best) {
			merged[id] = true
		}
		for _, idx := range members {
			for _, id := range aliasSet(vulns[idx]) {
				if id != best.ID {
					merged[id] = true
				}
			}
		}
		delete(merged, best.ID)
		best.Aliases = sortedKeys(merged)

		// Backfill every field from any member that has it. Selecting the
		// single richest record is not enough on its own: OSV and NVD
		// routinely disagree about which fields they populate, so a record
		// that wins on CVSS may carry no summary while a sibling in the same
		// group has a good one. Dropping it would leave a finding with a
		// severity and no explanation.
		for _, idx := range members {
			v := vulns[idx]
			if v.CVSSv3 > best.CVSSv3 {
				best.CVSSv3 = v.CVSSv3
				best.CVSSVector = v.CVSSVector
			}
			if v.EPSS > best.EPSS {
				best.EPSS = v.EPSS
			}
			if best.Summary == "" {
				best.Summary = v.Summary
			}
			if best.URL == "" {
				best.URL = v.URL
			}
			if best.FixedVersion == "" {
				best.FixedVersion = v.FixedVersion
			}
			if best.Introduced == "" {
				best.Introduced = v.Introduced
			}
			if best.LastAffected == "" {
				best.LastAffected = v.LastAffected
			}
			if best.CVSSVector == "" {
				best.CVSSVector = v.CVSSVector
			}
		}
		out = append(out, best)
	}

	// Stable ordering: worst first, so reports and SARIF files lead with the
	// findings that matter.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVSSv3 != out[j].CVSSv3 {
			return out[i].CVSSv3 > out[j].CVSSv3
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// aliasSet returns the primary id plus every alias. It's a free function
// rather than a method because model.Vuln lives in another package.
func aliasSet(v model.Vuln) []string {
	ids := make([]string, 0, len(v.Aliases)+1)
	ids = append(ids, v.ID)
	for _, a := range v.Aliases {
		if a != "" && a != v.ID {
			ids = append(ids, a)
		}
	}
	return ids
}

// completeness ranks how much usable data a record carries, so the richest
// record survives a merge. CVSS presence dominates because it's what feeds
// the score; EPSS and a fixed version break the tie.
func completeness(v model.Vuln) int {
	n := 0
	if v.CVSSv3 > 0 {
		n += 100
	}
	if v.CVSSVector != "" {
		n += 10
	}
	if v.EPSS > 0 {
		n += 40
	}
	if v.FixedVersion != "" {
		n += 20
	}
	if v.Summary != "" {
		n += 5
	}
	if v.URL != "" {
		n += 2
	}
	return n
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DedupeComponents applies Dedupe to every component in place.
func DedupeComponents(comps []model.Component) {
	for i := range comps {
		if len(comps[i].Vulnerabilities) > 1 {
			comps[i].Vulnerabilities = Dedupe(comps[i].Vulnerabilities)
		}
	}
}
