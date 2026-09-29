// Package scorecard fetches the OpenSSF Scorecard for a repository.
//
// The Scorecard measures how a *project* is maintained, not how a
// *dependency* is risky. That distinction is why this lives in its own
// package rather than in internal/vuln: it is a property of the scanned
// repository, and it feeds one term of the score (maintenance) rather than
// any individual vulnerability.
//
// The API is public and needs no authentication. It is queried once per
// scan, never per component, so a repository costs exactly one request
// however many dependencies it has.
package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// BaseURL is the public Scorecard API. It is a variable so tests can point
// it at an httptest server; nothing in this package writes to it.
var BaseURL = "https://api.securityscorecards.dev"

// DefaultTimeout matches the rest of SCRAM's network clients.
const DefaultTimeout = 30 * time.Second

// Client fetches Scorecard results.
type Client struct {
	HTTP    *http.Client
	BaseURL string
}

// New returns a Client with sane defaults.
func New() *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: DefaultTimeout},
		BaseURL: BaseURL,
	}
}

// Response is the subset of the Scorecard API payload SCRAM reads.
//
// Only the fields that affect a number are modelled. The API also returns a
// per-check `details` array, which is megabytes for a large project and is
// evidence for a human reading the Scorecard website, not an input to a
// calculation. Decoding it into memory on every scan would be a large,
// pointless cost.
type Response struct {
	Date string `json:"date"`
	Repo struct {
		Name   string `json:"name"`
		Commit string `json:"commit"`
	} `json:"repo"`
	// Score is the project's aggregate, 0-10.
	Score  float64 `json:"score"`
	Checks []Check `json:"checks"`
}

// Check is one Scorecard check.
//
// Score is -1 when the check does not apply to the project ("packaging
// workflow not detected", "no releases found", "internal error" from the
// scanner). That is the single most important detail in this file: -1 is
// not a low score, it is the absence of one, and averaging it in as a
// number would drag every real project down by a few points for reasons
// that have nothing to do with its supply chain risk.
type Check struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

// Result is what the rest of SCRAM consumes: an overall maintenance score
// on a 0-10 scale, plus the checks that produced it.
type Result struct {
	// Score is the Scorecard's own aggregate, 0-10. It is the value SCRAM
	// scales onto its 20-point maintenance budget.
	Score float64
	// Date is when the Scorecard ran, not when this scan ran. A stale
	// scorecard is a fact about the project worth surfacing.
	Date string
	// Commit is the commit the Scorecard evaluated. If it differs from the
	// scanned commit, the score describes different code.
	Commit string
	// Checks is the per-check breakdown, with inapplicable checks removed.
	Checks []Check
	// Inapplicable counts the checks that returned -1. Reported so that a
	// high maintenance score on a project where half the checks could not
	// run is visible rather than implied.
	Inapplicable int
}

// Normalize turns a repo identifier into the "host/owner/name" form the API
// requires.
//
// Accepts github.com/org/repo, https://github.com/org/repo,
// git@github.com:org/repo.git, and a bare org/repo. The host is significant:
// the live API returns 404 for /projects/google/oss-fuzz and 200 for
// /projects/github.com/google/oss-fuzz, so a bare owner/name is assumed to be
// GitHub rather than passed through.
//
// A bare "scram" is rejected. There is no correct guess for what a
// one-segment string refers to, and guessing is how a scanner ends up
// reporting a maintenance score for the wrong project.
func Normalize(repo string) (string, error) {
	s := strings.TrimSpace(repo)
	if s == "" {
		return "", fmt.Errorf("empty repository identifier")
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "www.")
	// scp-style remote: git@github.com:org/repo.git
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return "", fmt.Errorf("repository identifier %q has no owner or name", repo)
	}
	parts := strings.Split(s, "/")
	// A repository is at most host/owner/name. Anything further is a
	// tree/branch/blob path and must be discarded, taking the trailing
	// segments from the FRONT of the remainder rather than the back, or
	// ".../SCRAM/tree/main" resolves to the repository "tree/main".
	var host, owner, name string
	switch {
	case len(parts) >= 3:
		host, owner, name = parts[0], parts[1], parts[2]
	case len(parts) == 2:
		host, owner, name = "github.com", parts[0], parts[1]
	default:
		return "", fmt.Errorf("repository %q is not in owner/name or host/owner/name form", repo)
	}
	// Every segment must be a plausible host/owner/name token. Without
	// this, an identifier with whitespace or a control character flows
	// straight into the request URL, and the resulting path is either
	// silently wrong or a header injection. Found by FuzzNormalize on its
	// first run: "a b/c d" normalized happily to "github.com/a b/c d".
	for _, seg := range []string{host, owner, name} {
		if !validSegment(seg) {
			return "", fmt.Errorf("repository %q contains an invalid character in %q", repo, seg)
		}
	}
	return host + "/" + owner + "/" + name, nil
}

// validSegment reports whether s is a plausible host, owner, or repository
// name: letters, digits, and the punctuation GitHub and other forges
// actually permit in those positions.
func validSegment(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	// A leading or trailing dot is a path traversal, not a name.
	return s[0] != '.' && s[len(s)-1] != '.'
}

// ErrNotScored is returned when the API has no Scorecard for the project.
//
// This is not a failure and must not be treated as one. Scorecard only runs
// on projects it has been asked to scan, and a small project is routinely
// absent. Returning an error here would make every unscanned repository look
// broken; returning a score of zero would claim the project is unmaintained,
// which is a much worse lie.
type ErrNotScored struct{ Repo string }

func (e *ErrNotScored) Error() string {
	return fmt.Sprintf("no OpenSSF Scorecard for %s", e.Repo)
}

// Fetch retrieves the Scorecard for repo.
//
// A 404 is ErrNotScored, and a malformed body is an error. Neither is
// silently downgraded to a score: the caller decides what an absent score
// means, and the alternative is a maintenance number that no measurement
// produced.
func (c *Client) Fetch(ctx context.Context, repo string) (*Result, error) {
	name, err := Normalize(repo)
	if err != nil {
		return nil, err
	}
	// The slashes MUST NOT be escaped. This API keys projects by the literal
	// path "github.com/owner/name", and url.PathEscape turns that into
	// "github.com%2Fowner%2Fname", which the API answers with a 404. The
	// escape that looked safer here was the bug: it produced a plausible
	// request that could never succeed, and the 404 was indistinguishable
	// from a project that simply has not been scanned.
	//
	// The identifier is validated by Normalize before it gets here -- two
	// path segments of [A-Za-z0-9._-] -- so there is nothing to escape and
	// nothing to inject.
	endpoint := c.base() + "/projects/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "scram-supply-chain-scanner")

	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &ErrNotScored{Repo: name}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scorecard: %s returned %s", name, resp.Status)
	}

	var payload Response
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("scorecard: %s: decoding response: %w", name, err)
	}
	if len(payload.Checks) == 0 {
		return nil, fmt.Errorf("scorecard: %s: response contained no checks", name)
	}
	return NewResult(payload), nil
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return BaseURL
}

// NewResult converts a decoded response into a Result, dropping the
// inapplicable checks and recording how many there were.
func NewResult(r Response) *Result {
	out := &Result{
		Score:  r.Score,
		Date:   r.Date,
		Commit: r.Repo.Commit,
	}
	for _, c := range r.Checks {
		if c.Score < 0 {
			out.Inapplicable++
			continue
		}
		out.Checks = append(out.Checks, c)
	}
	return out
}
