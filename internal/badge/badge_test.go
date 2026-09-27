package badge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
	if got.Message != "32/100 low" {
		t.Errorf("message = %q, want %q", got.Message, "32/100 low")
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
	r := ScanReport{}
	r.Scan.Summary.RepoScore = 95
	r.Scan.Summary.RepoBucket = "critical"
	got := FromScanReport(r)
	if got.Color == "brightgreen" || got.Color == "yellowgreen" {
		t.Errorf("critical score rendered as %q", got.Color)
	}
	if !strings.Contains(got.Message, "95/100") {
		t.Errorf("message = %q, missing the score", got.Message)
	}
}

func TestFromScanReportCarriesScore(t *testing.T) {
	r := ScanReport{}
	r.Scan.Summary.RepoScore = 7
	r.Scan.Summary.RepoBucket = "clean"
	got := FromScanReport(r)
	if !strings.HasPrefix(got.Message, "7/100") {
		t.Errorf("message = %q, want it to start with the score", got.Message)
	}
}
