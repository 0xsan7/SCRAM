package badge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

func TestServeFromRealScanShape(t *testing.T) {
	// The document shape a real `scram scan --format json` emits, trimmed to
	// the fields the badge reads.
	doc := `{"schema_version":1,
	  "scan":{"schema_version":1,"repo":"scram","summary":{"repo_score":32,"repo_bucket":"low"}},
	  "passed":true}`
	var out bytes.Buffer
	if err := Serve(&out, strings.NewReader(doc)); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var got ShieldResponse
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("badge output is not valid JSON: %v\n%s", err, out.String())
	}
	if got.Message != "32/65 low" {
		t.Errorf("message = %q, want %q", got.Message, "32/65 low")
	}
	if got.Label != "self score" {
		t.Errorf("label = %q, want %q", got.Label, "self score")
	}
	if got.Color != ColorFor("low") {
		t.Errorf("color = %q, want %q for low", got.Color, ColorFor("low"))
	}
	if got.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", got.SchemaVersion)
	}
}

// The badge is a public claim. Serving "0/100" for a document that is not a
// scan would be a fabricated score on a live badge, which is the worst
// possible failure for this feature.
func TestServeRejectsNonScanDocument(t *testing.T) {
	for _, doc := range []string{
		`{"hello":"world"}`,
		`{}`,
		`{"scan":{"summary":{}}}`,
		`[]`,
	} {
		var out bytes.Buffer
		if err := Serve(&out, strings.NewReader(doc)); err == nil {
			t.Errorf("Serve(%s) produced %q; a non-scan document must be rejected",
				doc, out.String())
		}
	}
}

func TestServeRejectsMalformedJSON(t *testing.T) {
	var out bytes.Buffer
	if err := Serve(&out, strings.NewReader("{not json")); err == nil {
		t.Error("malformed JSON accepted")
	}
}

func TestColorFor(t *testing.T) {
	cases := map[string]string{
		"critical": "red",
		"high":     "orange",
		"medium":   "yellow",
		"low":      "yellowgreen",
		"clean":    "brightgreen",
		// An unknown bucket must not be coloured as if it were severe.
		"":         "brightgreen",
		"nonsense": "brightgreen",
	}
	for bucket, want := range cases {
		if got := ColorFor(bucket); got != want {
			t.Errorf("ColorFor(%q) = %q, want %q", bucket, got, want)
		}
	}
}

// A critical score must never render as a reassuring colour, whatever the
// input shape.
func TestCriticalIsNeverGreen(t *testing.T) {
	// RepoScore is the PRESENTED figure (0-65), so the fixture is written
	// in those units. 65 is the top of the presented scale.
	r := ScanReport{}
	r.Scan.Summary.RepoScore = 65
	r.Scan.Summary.RepoBucket = "critical"
	got := FromScanReport(r)
	if got.Color == "brightgreen" || got.Color == "yellowgreen" {
		t.Errorf("critical score rendered as %q", got.Color)
	}
	if !strings.Contains(got.Message, "65/65") {
		t.Errorf("message = %q, missing the score", got.Message)
	}
}

func TestFromScanReportCarriesScore(t *testing.T) {
	r := ScanReport{}
	r.Scan.Summary.RepoScore = 5
	r.Scan.Summary.RepoBucket = "clean"
	got := FromScanReport(r)
	if !strings.HasPrefix(got.Message, "5/65") {
		t.Errorf("message = %q, want it to start with the score", got.Message)
	}
}

// TestBadgeCannotExceedItsOwnDenominator is the guard against the one
// presentation this tool must never emit.
//
// FromScanReport takes whatever RepoScore is in the document. A scan
// report written by an older SCRAM, a hand-edited file, or a document that
// carries formula-scale points in a presented-scale field would otherwise
// render "95/65" -- a badge claiming 146% of the maximum, on a public
// README. Clamping in the badge rather than trusting the input is the only
// place that can guarantee it, because the badge is what a stranger reads.
func TestBadgeCannotExceedItsOwnDenominator(t *testing.T) {
	for _, score := range []int{65, 66, 80, 95, 100, 1000} {
		r := ScanReport{}
		r.Scan.Summary.RepoScore = score
		r.Scan.Summary.RepoBucket = "critical"
		got := FromScanReport(r)
		want := fmt.Sprintf("%d/65", model.PresentedMax)
		if got.Message != want+" critical" {
			t.Errorf("RepoScore %d -> message %q, want %q", score, got.Message, want+" critical")
		}
	}
}
