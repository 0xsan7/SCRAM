// Package badge renders SCRAM's own supply chain score as a shields.io
// endpoint badge.
//
// The pitch for a security tool is that it should be willing to point at
// itself. This package exists so SCRAM can publish its own live score, read
// from the same scan the CI dogfood job already runs -- not a second scan, and
// not a number someone typed into a README and forgot.
//
// There is no badge generator here. The output is the JSON a shields.io
// endpoint badge serves, which is a small documented shape, and the workflow
// publishes the scan's JSON output as that endpoint. Doing it any other way
// would mean rendering an SVG in Go, which is a maintenance burden for a
// cosmetic feature.
package badge

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/0xsan7/scram/internal/model"
)

// ShieldResponse is the subset of the shields.io endpoint schema that
// actually gets used. The full schema has fields for things a risk score does
// not have (pass/fail, coverage thresholds) and they are deliberately omitted.
type ShieldResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
	// LabelColor is omitted rather than set to a brand colour; the default
	// grey reads correctly in both GitHub themes without a second brand colour
	// to maintain.
}

// ScanReport is the subset of `scram scan --format json` the badge needs.
// Parsing only the fields used keeps the badge working across output changes
// to unrelated parts of the schema.
type ScanReport struct {
	Scan struct {
		Summary struct {
			RepoScore  int    `json:"repo_score"`
			RepoBucket string `json:"repo_bucket"`
		} `json:"summary"`
	} `json:"scan"`
	Passed bool `json:"passed"`
}

// Label is the badge text. "self score" states plainly that this is SCRAM
// scoring itself, which a bare "score" would leave ambiguous next to the
// build badge.
const Label = "self score"

// ColorFor maps a severity bucket onto a shield colour.
//
// The mapping is deliberately coarser than the bucket names: shields renders
// one colour per badge, and five near-identical greens would imply a
// precision the number does not have.
func ColorFor(bucket string) string {
	switch bucket {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "yellowgreen"
	default:
		return "brightgreen"
	}
}

// FromScanReport builds the badge payload from a scan's JSON.
func FromScanReport(r ScanReport) ShieldResponse {
	return ShieldResponse{
		SchemaVersion: 1,
		Label:         Label,
		Message:       fmt.Sprintf("%d/%d %s", clampedScore(r.Scan.Summary.RepoScore), model.PresentedMax, r.Scan.Summary.RepoBucket),
		Color:         ColorFor(r.Scan.Summary.RepoBucket),
	}
}

// Serve writes the badge JSON for a scan document read from r. It is the
// handler behind the `scram badge` command and the CI endpoint.
func Serve(w io.Writer, r io.Reader) error {
	var report ScanReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return fmt.Errorf("reading scan json: %w", err)
	}
	// A scan with no summary means the document was not a scan at all.
	// Serving "0/100" for that would be a false claim on a public badge.
	if report.Scan.Summary.RepoBucket == "" {
		return fmt.Errorf("scan json has no repo_bucket; is this a scram scan report?")
	}
	out, err := json.Marshal(FromScanReport(report))
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// clampedScore keeps a presented score inside 0..model.PresentedMax.
//
// The input is whatever a document claimed, and a document is not trusted:
// a scan report from an older version carries a 0-100 score, and a
// hand-edited one can carry anything. Without the clamp the badge renders
// "95/65", which is a public claim of 146% of the maximum. Clamping here,
// at the last step before the string is built, is the only place that
// holds for every caller.
func clampedScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > model.PresentedMax {
		return model.PresentedMax
	}
	return v
}
