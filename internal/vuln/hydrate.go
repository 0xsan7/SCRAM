package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/0xsan7/scram/internal/model"
)

// The OSV /v1/querybatch endpoint returns only vulnerability IDs — no CVSS,
// no aliases, no summary. Full records must be fetched one at a time from
// /v1/vulns/{id}.
//
// That turns a single batched call into N additional requests, so hydration
// is:
//   - cached per vulnerability id, so re-scans and repeated CVEs are free
//   - bounded-concurrency, so a repo with 200 findings doesn't open 200
//     sockets or trip OSV's rate limiter
//   - tolerant of per-vuln failures: one 404 must not sink the whole scan,
//     it just means that finding keeps id-only data (FR/NFR-3)

// MaxHydrateConcurrency bounds simultaneous /v1/vulns requests.
const MaxHydrateConcurrency = 8

// vulnDetail is the full OSV vulnerability record.
type vulnDetail struct {
	osvVuln
	// Aliases and severity live in the embedded struct; this adds the fields
	// needed for the advisory link.
	Published string `json:"published,omitempty"`
}

// Hydrate fetches full records for every vulnerability id in comps that is
// missing severity data, then replaces the placeholder records in place.
//
// It returns the number of records it could not fetch, so the caller can mark
// the scan as degraded rather than presenting id-only findings as complete.
func (c *Client) Hydrate(ctx context.Context, comps []model.Component) (failed int) {
	// Collect the distinct ids needing hydration, and remember which comps
	// hold them so the fetched data can be written back.
	needed := map[string]bool{}
	for _, comp := range comps {
		for _, v := range comp.Vulnerabilities {
			// A record with a CVSS score is already hydrated.
			if v.CVSSv3 > 0 || v.Summary != "" {
				continue
			}
			needed[v.ID] = true
		}
	}
	if len(needed) == 0 {
		return 0
	}

	ids := make([]string, 0, len(needed))
	for id := range needed {
		ids = append(ids, id)
	}
	// Sort so the fetch order is deterministic, which makes the cache
	// population pattern reproducible and easier to debug.
	sortStrings(ids)

	details := c.fetchDetails(ctx, ids)

	// Write the hydrated fields back onto every matching record.
	for ci := range comps {
		for vi := range comps[ci].Vulnerabilities {
			d, ok := details[comps[ci].Vulnerabilities[vi].ID]
			if !ok {
				continue
			}
			v := &comps[ci].Vulnerabilities[vi]
			if d.CVSSv3 > v.CVSSv3 {
				v.CVSSv3 = d.CVSSv3
			}
			if d.CVSSVector != "" {
				v.CVSSVector = d.CVSSVector
			}
			if d.Summary != "" {
				v.Summary = d.Summary
			}
			if d.FixedVersion != "" {
				v.FixedVersion = d.FixedVersion
			}
			if d.Introduced != "" {
				v.Introduced = d.Introduced
			}
			if d.LastAffected != "" {
				v.LastAffected = d.LastAffected
			}
			if d.URL != "" {
				v.URL = d.URL
			}
			// Merge aliases rather than replacing, so an id-only record that
			// already carried aliases keeps them.
			v.Aliases = mergeAliases(v.Aliases, d.Aliases, v.ID)
		}
	}

	return len(ids) - len(details)
}

// fetchDetails retrieves full records with bounded concurrency, using the
// cache to skip anything already fetched.
func (c *Client) fetchDetails(ctx context.Context, ids []string) map[string]model.Vuln {
	out := make(map[string]model.Vuln, len(ids))

	// A job is one id still needing a network fetch, plus the cache key its
	// result should be stored under.
	type job struct {
		id       string
		cacheKey string
	}
	jobs := make([]job, 0, len(ids))
	for _, id := range ids {
		key := CacheKey("vuln-detail", "osv", id)
		if c.Cache != nil {
			if b, ok := c.Cache.Get(key); ok {
				var v model.Vuln
				if json.Unmarshal(b, &v) == nil {
					out[id] = v
					continue
				}
			}
		}
		jobs = append(jobs, job{id: id, cacheKey: key})
	}

	sem := make(chan struct{}, MaxHydrateConcurrency)
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed int
	)

	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(id, cacheKey string) {
			defer wg.Done()
			defer func() { <-sem }()

			v, err := c.fetchOne(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// Track but don't abort: a partial scan that shows most
				// findings beats a failed one (NFR-3).
				failed++
				return
			}
			out[id] = v
			if c.Cache != nil {
				ttl := c.CacheTTL
				if ttl <= 0 {
					ttl = DefaultCacheTTL
				}
				if b, err := json.Marshal(v); err == nil {
					c.Cache.Set(cacheKey, b, ttl)
				}
			}
		}(j.id, j.cacheKey)
	}
	wg.Wait()

	if failed > 0 {
		c.warn("%d of %d vulnerability records could not be fetched from OSV; "+
			"those findings are listed by ID without severity detail", failed, len(ids))
	}
	return out
}

// fetchOne retrieves and normalizes a single OSV vulnerability record.
func (c *Client) fetchOne(ctx context.Context, id string) (model.Vuln, error) {
	url := OSVBaseURL + "/v1/vulns/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return model.Vuln{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return model.Vuln{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// The advisory was withdrawn between the batch query and now.
		return model.Vuln{}, fmt.Errorf("OSV has no record %s (withdrawn?)", id)
	}
	if resp.StatusCode != http.StatusOK {
		return model.Vuln{}, fmt.Errorf("OSV returned %s for %s", resp.Status, id)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return model.Vuln{}, err
	}
	var detail vulnDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return model.Vuln{}, err
	}

	records := normalizeOSV([]osvVuln{detail.osvVuln})
	if len(records) == 0 {
		return model.Vuln{}, fmt.Errorf("OSV record %s normalized to nothing", id)
	}
	return records[0], nil
}

// mergeAliases combines alias lists, dropping the record's own ID and any
// duplicates, and returns them sorted so output is reproducible.
func mergeAliases(existing, incoming []string, selfID string) []string {
	set := map[string]bool{}
	for _, a := range append(append([]string{}, existing...), incoming...) {
		if a == "" || a == selfID {
			continue
		}
		set[a] = true
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sortStrings(out)
	return out
}

// sortStrings is a tiny insertion sort. The slices here are small (one entry
// per distinct finding) and this keeps the package dependency-free.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// dedupeDetailsTimeout bounds how long hydration will spend retrying a single
// slow upstream, so a hung OSV cannot hang a PR check indefinitely.
const dedupeDetailsTimeout = 60 * time.Second
