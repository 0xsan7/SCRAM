package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xsan7/scram/internal/model"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAuditTruncatedBatchIsDegraded(t *testing.T) {
	for _, body := range []string{`{"results":[]}`, `{"results":[{},{}]}`, `{"results":[{"next_page_token":"more"}]}`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer s.Close()
			old := OSVBaseURL
			OSVBaseURL = s.URL
			defer func() { OSVBaseURL = old }()
			c := NewClient(NewMemoryCache())
			warned := false
			c.Warn = func(string) { warned = true }
			err := c.QueryOSV(context.Background(), []model.Component{{Name: "a", Version: "1", Ecosystem: "npm"}})
			if err == nil && !warned {
				t.Fatal("misaligned batch accepted as a complete clean scan")
			}
		})
	}
}

func TestAuditEPSSPartialFailureIsVisible(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") == "CVE-LAST" {
			http.Error(w, "unavailable", 503)
			return
		}
		fmt.Fprint(w, `{"status":"OK","data":[{"cve":"CVE-ONE","epss":"0.5"}]}`)
	}))
	defer s.Close()
	old := EPSSBaseURL
	EPSSBaseURL = s.URL
	defer func() { EPSSBaseURL = old }()
	ids := make([]string, 51)
	for i := 0; i < 50; i++ {
		ids[i] = fmt.Sprintf("CVE-%d", i)
	}
	ids[50] = "CVE-LAST"
	scores, err := NewClient(NewMemoryCache()).fetchEPSS(context.Background(), ids)
	if scores["CVE-ONE"] != 0.5 {
		t.Fatal("successful scores were lost")
	}
	if err == nil {
		t.Fatal("one failed chunk was hidden by another successful chunk")
	}
}

// FIRST CVSS v3.1 section 7.1 applies unchanged CIA weights to ISS.
func TestAuditCVSSScopeChangedUsesBaseEquation(t *testing.T) {
	vec := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"
	if got := cvssBaseFromVector(vec); got != 3.7 {
		t.Fatalf("scope-changed base=%.1f, want 3.7 per FIRST equation", got)
	}
}

func TestAuditCVSSRejectsMalformedValues(t *testing.T) {
	for _, vec := range []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.99/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"7.5garbage", "11.0", "+Inf",
	} {
		if got, _ := parseCVSSVector(vec); got != 0 {
			t.Errorf("malformed %q scored %.1f", vec, got)
		}
	}
}

func TestAuditHydrationRejectsWrongAdvisoryIdentity(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"CVE-OTHER","severity":[{"type":"CVSS_V3","score":"9.8"}]}`)
	}))
	defer s.Close()
	old := OSVBaseURL
	OSVBaseURL = s.URL
	defer func() { OSVBaseURL = old }()
	if _, err := NewClient(NewMemoryCache()).fetchOne(context.Background(), "CVE-EXPECTED"); err == nil {
		t.Fatal("wrong advisory's metadata attached under requested ID")
	}
}

func TestAuditCacheOwnsItsPayload(t *testing.T) {
	c := NewMemoryCache()
	input := []byte("original")
	c.Set("key", input, time.Hour)
	input[0] = 'X'
	got, ok := c.Get("key")
	if !ok || string(got) != "original" {
		t.Fatalf("caller mutated cached payload: %q", got)
	}
	got[0] = 'Y'
	again, _ := c.Get("key")
	if string(again) != "original" {
		t.Fatalf("cache reader mutated shared payload: %q", again)
	}
}

func TestAuditMemoryCacheConcurrentUse(t *testing.T) {
	c := NewMemoryCache()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c.Set("key", []byte("value"), time.Hour)
				c.Get("key")
			}
		}()
	}
	wg.Wait()
}

func TestAuditEPSSRejectsNonProbabilities(t *testing.T) {
	for _, s := range []string{`"NaN"`, `"+Inf"`, `"-0.1"`, `"1.1"`} {
		var v flexFloat64
		if err := json.Unmarshal([]byte(s), &v); err == nil {
			t.Errorf("accepted invalid probability %s", s)
		}
	}
}

func FuzzAuditCVSS(f *testing.F) {
	for _, s := range []string{"7.5", "+Inf", "11.0", "7.5garbage", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		score, _ := parseCVSSVector(s)
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 10 {
			t.Fatalf("invalid score %v from %q", score, s)
		}
	})
}

func TestAuditFixedVersionBelongsToAffectedPackage(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"CVE-SCOPE","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],"affected":[{"package":{"name":"b","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"99.0.0"}]}]},{"package":{"name":"a","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}`)
	}))
	defer s.Close()
	old := OSVBaseURL
	OSVBaseURL = s.URL
	defer func() { OSVBaseURL = old }()
	cache := NewMemoryCache()
	for attempt := 0; attempt < 2; attempt++ {
		comps := []model.Component{{Name: "a", Ecosystem: "npm", Vulnerabilities: []model.Vuln{{ID: "CVE-SCOPE"}}}, {Name: "b", Ecosystem: "npm", Vulnerabilities: []model.Vuln{{ID: "CVE-SCOPE"}}}}
		comps[0].Vulnerabilities[0].CVSSv3 = 9.8
		comps[0].Vulnerabilities[0].CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		c := NewClient(cache)
		if n := c.Hydrate(context.Background(), comps); n != 0 {
			t.Fatalf("attempt %d: hydration failures %d", attempt, n)
		}
		v := comps[0].Vulnerabilities[0]
		if calculated, _ := parseCVSSVector(v.CVSSVector); calculated != v.CVSSv3 {
			t.Fatalf("hydration paired score %v with vector score %v", v.CVSSv3, calculated)
		}
		if got := comps[0].Vulnerabilities[0].FixedVersion; got != "2.0.0" {
			t.Fatalf("a inherited b's fixed version: %q", got)
		}
		if got := comps[1].Vulnerabilities[0].FixedVersion; got != "99.0.0" {
			t.Fatalf("b fix=%q", got)
		}
		s.Close()
	}
}
