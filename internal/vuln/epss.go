package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/0xsan7/scram/internal/model"
)

// EPSSBaseURL is the FIRST.org Exploit Prediction Scoring System API.
var EPSSBaseURL = "https://api.first.org/data/v1/epss"

// enrichEPSS fills in the EPSS probability for every CVE found.
//
// EPSS is queried per-CVE, so requests are bounded-concurrency rather than
// sequential — a repo with 40 distinct CVEs shouldn't take 40 round trips.
// Results are shared across components, since the same CVE often affects
// several components in one repo.
func (c *Client) enrichEPSS(ctx context.Context, comps []model.Component) error {
	// Collect the distinct CVE set once.
	needed := map[string]bool{}
	for _, comp := range comps {
		for _, v := range comp.Vulnerabilities {
			if cve, ok := asCVE(v); ok {
				needed[cve] = true
			}
		}
	}
	if len(needed) == 0 {
		return nil
	}

	scores, err := c.fetchEPSS(ctx, keysOf(needed))
	if err != nil {
		return err
	}

	for i := range comps {
		for j := range comps[i].Vulnerabilities {
			if cve, ok := asCVE(comps[i].Vulnerabilities[j]); ok {
				comps[i].Vulnerabilities[j].EPSS = scores[cve]
			}
		}
	}
	return nil
}

// asCVE returns the CVE id for a vulnerability record, checking both the
// primary ID and the aliases. GHSA-primary records carry the CVE as an
// alias, so the alias check is what makes EPSS coverage complete.
func asCVE(v model.Vuln) (string, bool) {
	if isCVEID(v.ID) {
		return v.ID, true
	}
	for _, a := range v.Aliases {
		if isCVEID(a) {
			return a, true
		}
	}
	return "", false
}

func isCVEID(s string) bool {
	return len(s) > 4 && s[:4] == "CVE-"
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// epssResponse mirrors the FIRST.org EPSS API payload.
//
// The numeric fields arrive as JSON *strings* ("0.073360000"), not numbers.
// Decoding them into float64 directly fails on every response, which is why
// they are flexString here and parsed explicitly.
type epssResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string      `json:"cve"`
		EPSS       flexFloat64 `json:"epss"`
		Percentile flexFloat64 `json:"percentile"`
		Date       string      `json:"date"`
	} `json:"data"`
}

// flexFloat64 unmarshals a number that may arrive as either a JSON number or
// a JSON string.
type flexFloat64 float64

func (f *flexFloat64) UnmarshalJSON(b []byte) error {
	s := string(b)
	// Trim surrounding quotes if the value is a JSON string.
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("parsing EPSS value %q: %w", s, err)
	}
	*f = flexFloat64(v)
	return nil
}

// fetchEPSS queries EPSS for the given CVE ids, chunked to stay under the
// API's URL length limits and run with bounded concurrency.
func (c *Client) fetchEPSS(ctx context.Context, cves []string) (map[string]float64, error) {
	const chunkSize = 50
	const maxConcurrent = 4

	out := make(map[string]float64, len(cves))
	var (
		mu   sync.Mutex
		errs []error
	)
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for start := 0; start < len(cves); start += chunkSize {
		end := start + chunkSize
		if end > len(cves) {
			end = len(cves)
		}
		chunk := cves[start:end]

		wg.Add(1)
		sem <- struct{}{}
		go func(chunk []string) {
			defer wg.Done()
			defer func() { <-sem }()

			scores, err := c.epssChunk(ctx, chunk)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// A failed chunk is recorded but doesn't abort the others.
				errs = append(errs, err)
				return
			}
			for k, v := range scores {
				out[k] = v
			}
		}(chunk)
	}
	wg.Wait()

	if len(errs) > 0 && len(out) == 0 {
		// Every chunk failed — report it so the caller can warn.
		return out, fmt.Errorf("all %d EPSS request(s) failed: %v", len(errs), errs[0])
	}
	return out, nil
}

func (c *Client) epssChunk(ctx context.Context, cves []string) (map[string]float64, error) {
	q := url.Values{}
	q.Set("cve", joinComma(cves))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, EPSSBaseURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned %s", resp.Status)
	}

	var parsed epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(parsed.Data))
	for _, d := range parsed.Data {
		out[d.CVE] = float64(d.EPSS)
	}
	return out, nil
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
