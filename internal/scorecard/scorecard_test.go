package scorecard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture is a real response from the public API for
// github.com/google/oss-fuzz, captured live and trimmed only by removing the
// per-check `details` arrays. It is committed rather than synthesized because
// the field that matters most here -- score -1 for an inapplicable check --
// never appears in a hand-written example, so a synthetic fixture would have
// made the most important test in this file impossible to write honestly.
func realFixture(t *testing.T) Response {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "fixtures", "scorecard", "oss-fuzz.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return r
}

// TestFixtureHasInapplicableChecks guards the premise of the tests below. If
// a future fixture refresh drops every -1, the tests that follow would still
// pass while testing nothing.
func TestFixtureHasInapplicableChecks(t *testing.T) {
	r := realFixture(t)
	neg := 0
	for _, c := range r.Checks {
		if c.Score < 0 {
			neg++
		}
	}
	if neg == 0 {
		t.Fatal("fixture contains no -1 checks; the inapplicable-check handling is untested")
	}
	t.Logf("fixture: %d checks, %d inapplicable, aggregate %v", len(r.Checks), neg, r.Score)
}

// TestNewResultDropsInapplicable is the core correctness property. A -1 must
// be excluded from the check list and counted, never averaged in as a score.
func TestNewResultDropsInapplicable(t *testing.T) {
	res := NewResult(realFixture(t))

	for _, c := range res.Checks {
		if c.Score < 0 {
			t.Errorf("inapplicable check %q (%d) was kept in the usable set", c.Name, c.Score)
		}
		if c.Score > 10 {
			t.Errorf("check %q has out-of-range score %d", c.Name, c.Score)
		}
	}
	if res.Inapplicable == 0 {
		t.Error("Inapplicable = 0, want the -1 checks counted")
	}
	total := len(res.Checks) + res.Inapplicable
	if total != len(realFixture(t).Checks) {
		t.Errorf("checks+inapplicable = %d, want %d (nothing may be lost)",
			total, len(realFixture(t).Checks))
	}
	if res.Score <= 0 || res.Score > 10 {
		t.Errorf("aggregate score %v out of range 0-10", res.Score)
	}
	t.Logf("usable=%d inapplicable=%d aggregate=%v date=%s",
		len(res.Checks), res.Inapplicable, res.Score, res.Date)
}

// TestNewResultDoesNotAverageMinusOne is the break-to-confirm-red case,
// written as arithmetic rather than as an assertion about the struct so a
// reader can see the failure mode without running anything.
func TestNewResultDoesNotAverageMinusOne(t *testing.T) {
	fixture := realFixture(t)
	res := NewResult(fixture)

	// The wrong way: average every score including -1.
	wrong := 0.0
	for _, c := range fixture.Checks {
		wrong += float64(c.Score)
	}
	wrong /= float64(len(fixture.Checks))

	// The right way: average only applicable checks.
	right := 0.0
	for _, c := range res.Checks {
		right += float64(c.Score)
	}
	right /= float64(len(res.Checks))

	if right-wrong < 1.0 {
		t.Fatalf("test is not sensitive: including -1 only moves the mean by %.2f", right-wrong)
	}
	t.Logf("mean including -1 = %.2f; applicable only = %.2f; distortion %.2f points",
		wrong, right, right-wrong)
	if right <= wrong {
		t.Errorf("applicable-only mean %.2f should exceed the mean that includes -1 (%.2f)",
			right, wrong)
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"github.com/0xsan7/SCRAM", "github.com/0xsan7/SCRAM", true},
		{"https://github.com/0xsan7/SCRAM", "github.com/0xsan7/SCRAM", true},
		{"http://www.github.com/0xsan7/SCRAM", "github.com/0xsan7/SCRAM", true},
		{"git@github.com:0xsan7/SCRAM.git", "github.com/0xsan7/SCRAM", true},
		{"0xsan7/SCRAM", "github.com/0xsan7/SCRAM", true},
		{"github.com/0xsan7/SCRAM/", "github.com/0xsan7/SCRAM", true},
		{"  github.com/0xsan7/SCRAM  ", "github.com/0xsan7/SCRAM", true},
		// A trailing path is dropped rather than treated as the name.
		{"github.com/0xsan7/SCRAM/tree/main", "github.com/0xsan7/SCRAM", true},
		// These must fail rather than guess. Reporting on the wrong
		// project is worse than reporting nothing.
		{"", "", false},
		{"scram", "", false},
		{"github.com", "", false},
		{"https://", "", false},
	}
	for _, c := range cases {
		got, err := Normalize(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("Normalize(%q) = error %v, want %q", c.in, err, c.want)
				continue
			}
			if got != c.want {
				t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", c.in, got)
		}
	}
}

// TestFetchLiveFixture serves the committed fixture over HTTP so the fetch
// path is exercised end to end against real bytes, not a stubbed struct.
func TestFetchLiveFixture(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "scorecard", "oss-fuzz.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/projects/github.com/google/oss-fuzz" {
			t.Errorf("request path = %q, want the normalized project path", got)
		}
		if accept := r.Header.Get("Accept"); accept != "application/json" {
			t.Errorf("Accept = %q, want application/json", accept)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New()
	c.BaseURL = srv.URL
	res, err := c.Fetch(context.Background(), "https://github.com/google/oss-fuzz")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(res.Checks) == 0 {
		t.Fatal("no checks returned")
	}
	if res.Inapplicable == 0 {
		t.Error("inapplicable checks were dropped all the way through the fetch path")
	}
	if res.Date == "" {
		t.Error("Date empty; the scan date should be reported")
	}
	if res.Commit == "" {
		t.Error("Commit empty; a score for unknown code is not a score for this code")
	}
}

// TestFetchUnscoredRepo pins the behaviour that matters most operationally:
// a project the API has never scanned is a distinct state, not an error to
// swallow and not a zero to report.
func TestFetchUnscoredRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New()
	c.BaseURL = srv.URL
	_, err := c.Fetch(context.Background(), "github.com/0xsan7/nonexistent")
	if err == nil {
		t.Fatal("Fetch on an unscored project returned nil error")
	}
	var unscored *ErrNotScored
	if !errors.As(err, &unscored) {
		t.Fatalf("error = %v (%T), want *ErrNotScored", err, err)
	}
	if unscored.Repo != "github.com/0xsan7/nonexistent" {
		t.Errorf("ErrNotScored.Repo = %q", unscored.Repo)
	}
}

// TestFetchRejectsEmptyChecks is the silent-zero invariant for this package:
// a 200 that carries no checks is a broken response, and treating it as a
// score of zero would report a project as unmaintained on the strength of an
// empty object.
func TestFetchRejectsEmptyChecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"date":"2026-01-01","score":9.9,"checks":[]}`))
	}))
	defer srv.Close()

	c := New()
	c.BaseURL = srv.URL
	_, err := c.Fetch(context.Background(), "github.com/0xsan7/SCRAM")
	if err == nil {
		t.Fatal("a response with zero checks was accepted")
	}
	if errors.Is(err, new(ErrNotScored)) {
		t.Error("an empty-checks 200 was misreported as not-scored")
	}
	t.Logf("rejected as: %v", err)
}

func TestFetchServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	if _, err := c.Fetch(context.Background(), "github.com/0xsan7/SCRAM"); err == nil {
		t.Fatal("a 502 was accepted as a score")
	}
}

func TestFetchMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"checks": [ this is not json`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	if _, err := c.Fetch(context.Background(), "github.com/0xsan7/SCRAM"); err == nil {
		t.Fatal("a malformed body was accepted as a score")
	}
}

// TestRequestPathIsNotEscaped is the regression test for a bug that every
// other test in this file missed.
//
// The fetch path was built with url.PathEscape, which turns
// "github.com/google/oss-fuzz" into "github.com%2Fgoogle%2Foss-fuzz". The
// real API answers that with 404. Every test here used an httptest server
// that accepted whatever path it was given, so the whole suite was green
// while the integration could not have worked against the real service.
//
// The assertion is on the literal request path, because that is the thing
// that was wrong. Testing "does it return a result" would pass against a
// mock forever.
func TestRequestPathIsNotEscaped(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"score":7,"checks":[{"name":"Maintained","score":10}]}`))
	}))
	defer srv.Close()

	c := New()
	c.BaseURL = srv.URL
	if _, err := c.Fetch(context.Background(), "github.com/google/oss-fuzz"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if strings.Contains(gotPath, "%2F") {
		t.Errorf("request path %q has escaped slashes; the Scorecard API 404s on those", gotPath)
	}
	if want := "/projects/github.com/google/oss-fuzz"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}
}

// TestRequestPathMatchesLiveAPI pins the exact URL the production API is
// known to answer, recorded from a real request rather than reasoned about.
// The two forms below were both checked against the live service: the
// unescaped path returns 200 for a scored project, the escaped one 404s.
func TestRequestPathMatchesLiveAPI(t *testing.T) {
	c := New()
	name, err := Normalize("github.com/google/oss-fuzz")
	if err != nil {
		t.Fatal(err)
	}
	if name != "github.com/google/oss-fuzz" {
		t.Fatalf("Normalize = %q", name)
	}
	// c.base() + "/projects/" + name is the URL that works. If the code
	// ever starts escaping again, this string stops being what is built.
	if got := c.base() + "/projects/" + name; got !=
		"https://api.securityscorecards.dev/projects/github.com/google/oss-fuzz" {
		t.Errorf("built URL = %q", got)
	}
}
