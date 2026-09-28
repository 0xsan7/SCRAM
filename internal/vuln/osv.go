// Package vuln queries upstream vulnerability databases and normalizes the
// results into model.Vuln (FR-2xx).
//
// OSV.dev is the primary source. NVD and GHSA are optional enrichments. Every
// client degrades gracefully: a downed or rate-limited upstream must never
// fail a scan, it must produce a warning and continue (NFR-3).
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0xsan7/scram/internal/model"
)

// OSVBaseURL is the public OSV API. Overridable so tests can point at a
// local fixture server.
var OSVBaseURL = "https://api.osv.dev"

// DefaultTimeout is the per-request timeout. Kept short: a slow upstream
// should not hold a PR check open.
const DefaultTimeout = 20 * time.Second

// Client queries OSV and enriches with EPSS.
type Client struct {
	HTTP    *http.Client
	Cache   Cache
	Offline bool
	// CacheTTL is how long fetched vulnerability records stay valid. It is
	// applied to every Cache.Set, so a record fetched today is not re-fetched
	// on every subsequent run in the same afternoon.
	CacheTTL time.Duration
	// Warn collects degradation messages rather than failing (NFR-3).
	Warn func(string)
	// EPSS disabled by default because it doubles request count; enable with
	// the epss config flag.
	UseEPSS bool
}

// NewClient builds a Client with sane defaults.
func NewClient(cache Cache) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: DefaultTimeout},
		Cache:    cache,
		CacheTTL: DefaultCacheTTL,
		Warn:     func(string) {},
	}
}

func (c *Client) warn(format string, args ...any) {
	if c.Warn != nil {
		c.Warn(fmt.Sprintf(format, args...))
	}
}

// --- OSV request/response shapes -------------------------------------------

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	// Version is optional; when set OSV returns only vulns affecting it.
	Version string `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvBatchResponse is a list positionally aligned with the request queries.
type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID         string        `json:"id"`
	Aliases    []string      `json:"aliases,omitempty"`
	Summary    string        `json:"summary"`
	Details    string        `json:"details,omitempty"`
	Severity   []osvSeverity `json:"severity,omitempty"`
	Affected   []osvAffected `json:"affected,omitempty"`
	References []osvRef      `json:"references,omitempty"`
	Modified   string        `json:"modified,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package           osvPackage      `json:"package"`
	Ranges            []osvRange      `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type osvRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// OSVBatch is the maximum number of queries allowed in one /v1/querybatch
// call. The API rejects larger batches.
const OSVBatch = 1000

// QueryOSV batch-queries OSV for every component and attaches the results.
//
// It mutates the components in place so callers keep working with one slice.
// FR-201 requires a single batched call per scan, not N sequential requests.
func (c *Client) QueryOSV(ctx context.Context, comps []model.Component) error {
	if c.Offline {
		return fmt.Errorf("--offline set but vulnerability data is not cached for this scan; refusing to report a clean result (NFR-6)")
	}
	if len(comps) == 0 {
		return nil
	}

	// Only ask about components whose ecosystem OSV actually indexes.
	queryable := make([]int, 0, len(comps))
	req := osvBatchRequest{Queries: []osvQuery{}}
	for i, comp := range comps {
		eco, ok := osvEcosystem(comp.Ecosystem)
		if !ok {
			continue
		}
		queryable = append(queryable, i)
		req.Queries = append(req.Queries, osvQuery{
			Package: osvPackage{Name: comp.Name, Ecosystem: eco},
			Version: comp.Version,
		})
	}
	if len(req.Queries) == 0 {
		c.warn("no components matched an OSV-supported ecosystem; skipping OSV")
		return nil
	}

	results, err := c.batchQuery(ctx, req)
	if err != nil {
		// Upstream outage degrades, never hard-fails (NFR-3).
		c.warn("OSV query failed, vulnerability data incomplete: %v", err)
		return nil
	}

	for qi, compIdx := range queryable {
		if qi >= len(results) {
			break
		}
		comps[compIdx].Vulnerabilities = normalizeOSV(results[qi].Vulns)
	}

	// querybatch returns ids only; fetch the full records. Without this step
	// every finding would have no CVSS and score 0, which is the difference
	// between a working scanner and a decorative one.
	if failed := c.Hydrate(ctx, comps); failed > 0 {
		c.warn("%d vulnerability record(s) could not be enriched; "+
			"their severity is unknown and they are scored as 0", failed)
	}

	if c.UseEPSS {
		if err := c.enrichEPSS(ctx, comps); err != nil {
			c.warn("EPSS enrichment failed, exploitability scored as 0: %v", err)
		}
	}

	// FR-203: collapse findings that are the same issue reported under
	// different ids (CVE vs GHSA vs PYSEC). This must run after hydration and
	// EPSS, because the alias graph only becomes complete once the full
	// records are fetched — before hydration, querybatch returns bare ids with
	// no aliases and nothing can be linked.
	DedupeComponents(comps)

	return nil
}

func (c *Client) batchQuery(ctx context.Context, req osvBatchRequest) ([]osvResult, error) {
	var out []osvResult
	// OSV caps querybatch payloads, so long dependency lists are chunked.
	for start := 0; start < len(req.Queries); start += OSVBatch {
		end := start + OSVBatch
		if end > len(req.Queries) {
			end = len(req.Queries)
		}
		chunk := osvBatchRequest{Queries: req.Queries[start:end]}

		body, err := json.Marshal(chunk)
		if err != nil {
			return nil, err
		}

		url := OSVBaseURL + "/v1/querybatch"
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := c.HTTP.Do(httpReq)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("OSV API returned %s", resp.Status)
		}
		var batch osvBatchResponse
		decErr := json.NewDecoder(resp.Body).Decode(&batch)
		resp.Body.Close()
		if decErr != nil {
			return nil, decErr
		}
		out = append(out, batch.Results...)
	}
	return out, nil
}

// osvEcosystem maps our ecosystem names onto OSV's, which are capitalized
// ("PyPI", "Go", "npm") and differ from ours.
func osvEcosystem(eco string) (string, bool) {
	switch eco {
	case model.EcoNPM:
		return "npm", true
	case model.EcoPyPI:
		return "PyPI", true
	case model.EcoGo:
		return "Go", true
	}
	return "", false
}

// normalizeOSV converts raw OSV vulns into the internal schema (FR-202),
// pulling the max CVSS v3 score out of OSV's severity array and the fixed
// version out of the affected ranges.
func normalizeOSV(vulns []osvVuln) []model.Vuln {
	out := make([]model.Vuln, 0, len(vulns))
	for _, v := range vulns {
		rec := model.Vuln{
			ID:      v.ID,
			Source:  "osv",
			Summary: firstNonEmpty(v.Summary, v.Details),
			Aliases: v.Aliases,
			URL:     advisoryURL(v),
		}
		rec.CVSSv3, rec.CVSSVector = maxCVSS(v.Severity)
		rec.FixedVersion, rec.Introduced, rec.LastAffected = rangeSummary(v.Affected)
		out = append(out, rec)
	}
	return out
}

// maxCVSS picks the highest CVSS v3 base score from OSV's severity list.
// OSV may carry several entries (CVSS_V2, CVSS_V3, CVSS_V4) for the same
// vuln; only v3 is used because that is what the scoring algorithm is
// specified against.
func maxCVSS(sevs []osvSeverity) (float64, string) {
	var best float64
	var bestVec string
	for _, s := range sevs {
		if !strings.EqualFold(s.Type, "CVSS_V3") {
			continue
		}
		score, vec := parseCVSSVector(s.Score)
		if score > best {
			best, bestVec = score, vec
		}
	}
	return best, bestVec
}

// parseCVSSVector extracts the base score and the vector string from an OSV
// CVSS_V3 score, which is normally a full vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
func parseCVSSVector(s string) (float64, string) {
	if s == "" {
		return 0, ""
	}
	// Some feeds give a bare number instead of a vector.
	if n := parseFloat(s); n > 0 && !strings.Contains(s, ":") {
		return n, ""
	}
	if !strings.HasPrefix(s, "CVSS:3") {
		return 0, ""
	}
	// Reconstruct the base score from the metric values, since OSV gives us
	// the vector rather than the score.
	return cvssBaseFromVector(s), s
}

// vectorMetrics are the CVSS v3.1 base-metric weights, as defined in
// section 8.1 of the CVSS v3.1 specification.
//
// The scope-changed weights are genuinely different from the scope-unchanged
// ones for Privileges Required; the Confidentiality/Integrity/Availability
// weights are the same in both cases.
var (
	avVals      = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acVals      = map[string]float64{"L": 0.77, "H": 0.44}
	prUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	uiVals      = map[string]float64{"N": 0.85, "R": 0.62}
	ciaVals     = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	// scopeModifier is applied to the final sum only when Scope is Changed.
	scopeModifier = 1.08
	// scopeWeight is the multiplier on each CIA value when Scope is Changed.
	scopeWeight = 0.914
)

// cvssBaseFromVector implements the CVSS v3.1 base score equation:
//
//	ISCBase = 1 - (1-C)*(1-I)*(1-A)          [each C/I/A x 0.914 if S:C]
//	Impact  = 6.42 * ISCBase                  [S:U]
//	Impact  = 7.52*(ISC-0.029) - 3.25*(ISC-0.02)^15   [S:C]
//	Exploit = 8.22 * AV * AC * PR * UI
//	Base    = Roundup(min(Impact + Exploit, 10))       [S:U]
//	Base    = Roundup(min(1.08*(Impact + Exploit), 10)) [S:C]
//
// Verified against the worked examples in the specification; see
// cvss_test.go.
func cvssBaseFromVector(vec string) float64 {
	// metricValue pulls a single "XX:value" pair out of the vector.
	metricValue := func(short string) (string, bool) {
		for _, part := range strings.Split(vec, "/") {
			if strings.HasPrefix(part, short+":") {
				return strings.TrimPrefix(part, short+":"), true
			}
		}
		return "", false
	}
	num := func(short string) (float64, bool) {
		s, ok := metricValue(short)
		if !ok {
			return 0, false
		}
		v, ok := lookup(short, s)
		return v, ok
	}

	av, okAV := num("AV")
	ac, okAC := num("AC")
	ui, okUI := num("UI")
	scope, okScope := metricValue("S")
	// A vector missing a required base metric cannot be scored; returning 0
	// is correct because an unscorable vector is not a low score, it is an
	// unknown one, and the caller must not invent a number.
	if !okAV || !okAC || !okUI || !okScope {
		return 0
	}

	changed := scope == "C"
	prVals := prUnchanged
	if changed {
		prVals = prChanged
	}
	prStr, okPR := metricValue("PR")
	if !okPR {
		return 0
	}
	pr, ok := lookup2(prVals, prStr)
	if !ok {
		return 0
	}

	c, okC := num("C")
	i, okI := num("I")
	a, okA := num("A")
	if !okC || !okI || !okA {
		return 0
	}

	if changed {
		c *= scopeWeight
		i *= scopeWeight
		a *= scopeWeight
	}
	isc := 1 - (1-c)*(1-i)*(1-a)

	var impact float64
	if changed {
		impact = 7.52*(isc-0.029) - 3.25*pow(isc-0.02, 15)
	} else {
		impact = 6.42 * isc
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui
	sum := impact + exploitability
	if changed {
		sum *= scopeModifier
	}
	if sum > 10 {
		sum = 10
	}
	return roundUp1(sum)
}

func lookup(short, val string) (float64, bool) {
	switch short {
	case "AV":
		v, ok := avVals[val]
		return v, ok
	case "AC":
		v, ok := acVals[val]
		return v, ok
	case "UI":
		v, ok := uiVals[val]
		return v, ok
	case "C", "I", "A":
		v, ok := ciaVals[val]
		return v, ok
	}
	return 0, false
}

// lookup2 reads a weight out of one of the scope-specific PR tables.
func lookup2(m map[string]float64, val string) (float64, bool) {
	v, ok := m[val]
	return v, ok
}

// roundUp1 implements the CVSS v3.1 Roundup function: round *up* to one
// decimal place, so 9.76 becomes 9.8 and 5.30 stays 5.3. Plain rounding would
// give 9.8 for 9.75 but 5.3 for 5.26, which does not match the spec.
func roundUp1(x float64) float64 {
	// Work in integer ten-thousandths to avoid float comparison surprises.
	i := int64(x*100000 + 0.5)
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (float64(i/10000) + 1) / 10
}

// pow raises base to an integer exponent, used for the (ISC-0.02)^15 term.
func pow(base float64, exp int) float64 {
	r := 1.0
	for i := 0; i < exp; i++ {
		r *= base
	}
	return r
}

// rangeSummary extracts the earliest "introduced" version, the fix version,
// and the last affected version from OSV's affected ranges.
func rangeSummary(affected []osvAffected) (fixed, introduced, lastAffected string) {
	for _, a := range affected {
		for _, rg := range a.Ranges {
			for _, ev := range rg.Events {
				if ev.Fixed != "" && fixed == "" {
					fixed = ev.Fixed
				}
				if ev.Introduced != "" && introduced == "" {
					introduced = ev.Introduced
				}
				if ev.LastAffected != "" {
					lastAffected = ev.LastAffected
				}
			}
		}
	}
	return
}

func advisoryURL(v osvVuln) string {
	for _, r := range v.References {
		if r.Type == "ADVISORY" || r.Type == "FIX" || r.Type == "REPORT" {
			return r.URL
		}
	}
	// OSV always has a canonical detail page even when references are empty.
	return "https://osv.dev/vulnerability/" + v.ID
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func parseFloat(s string) float64 {
	var f float64
	// Sscanf returns io.EOF when it hits end-of-input before a verb. That
	// is an error like any other here, and `err != nil` already covers it;
	// an explicit `|| err == io.EOF` would be a second clause on a path
	// that cannot be reached.
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return 0
	}
	return f
}
