// Package report renders a scan into every output format SCRAM supports
// (FR-6xx). All formats render from the same model.Scan, so they can never
// disagree about what was found.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/score"
)

// Format names a supported output encoding.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// Write renders the scan in the given format to w.
func Write(w io.Writer, scan model.Scan, diff *model.DiffResult, f Format) error {
	return WriteWithTrend(w, scan, diff, f, nil)
}

// WriteWithTrend renders a scan, optionally including the repo's risk-score
// history. The trend is a separate argument rather than a global so that
// rendering stays deterministic and testable: the same inputs always produce
// the same bytes, and a caller that does not have history simply passes nil.
func WriteWithTrend(w io.Writer, scan model.Scan, diff *model.DiffResult, f Format, tr *Trend) error {
	switch f {
	case FormatJSON:
		return writeJSON(w, scan, diff)
	case FormatSARIF:
		return writeSARIF(w, scan, diff)
	case FormatTable:
		return writeTable(w, scan, diff, tr)
	}
	return fmt.Errorf("unknown format %q (want table, json, or sarif)", f)
}

// Trend is the score history attached to a rendered report.
type Trend struct {
	// Spark is the pre-rendered glyph run, oldest sample first.
	Spark string
	// First and Last bracket the window, so the reader can see the change
	// rather than infer it from a picture.
	First int
	Last  int
	// Samples is how many scans the window covers.
	Samples int
	// Path is where the history is stored, so the row is actionable.
	Path string
}

// JSONDocument is the top-level shape of `scram scan --format json`. Wrapping
// the scan rather than emitting it bare means a later version can add fields
// without breaking consumers, and gives a place to hang the drift report.
type JSONDocument struct {
	SchemaVersion string            `json:"schema_version"`
	Scan          model.Scan        `json:"scan"`
	Drift         *model.DiffResult `json:"drift,omitempty"`
	Passed        bool              `json:"passed"`
	FailReasons   []string          `json:"fail_reasons,omitempty"`
}

func writeJSON(w io.Writer, scan model.Scan, diff *model.DiffResult) error {
	doc := JSONDocument{
		SchemaVersion: model.SchemaVersion,
		Scan:          scan,
		Drift:         diff,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// ANSI colors, disabled when the writer isn't a terminal. Kept as package
// vars so a caller can strip them in CI.
var (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
)

// NoColor disables ANSI output, for non-TTY writers like CI logs.
var NoColor bool

func paint(color, s string) string {
	if NoColor {
		return s
	}
	return color + s + colorReset
}

// trendChangeText describes the movement across the window in words, so the
// sparkline is not the only way to read it. Plain signs beat emoji and avoid
// depending on locale-specific glyphs.
func trendChangeText(tr *Trend) string {
	delta := tr.Last - tr.First
	switch {
	case delta > 0:
		return fmt.Sprintf("%+d over %d scans, worsening", delta, tr.Samples)
	case delta < 0:
		return fmt.Sprintf("%+d over %d scans, improving", delta, tr.Samples)
	default:
		return fmt.Sprintf("flat across %d scans", tr.Samples)
	}
}

// bucketColor picks the color used for a severity bucket.
func bucketColor(bucket string) string {
	switch bucket {
	case model.BucketCritical:
		return colorRed
	case model.BucketHigh:
		return colorYellow
	case model.BucketMedium:
		return colorBlue
	case model.BucketLow:
		return colorDim
	}
	return colorGreen
}

// Paint applies an ANSI color, honouring the NoColor package flag. Exported
// so other commands render the same severity palette instead of each growing
// their own copy of the escape codes.
func Paint(color, s string) string { return paint(color, s) }

// BucketColor is the ANSI color for a severity bucket.
func BucketColor(bucket string) string { return bucketColor(bucket) }

// BucketLabel is the short human label for a bucket.
func BucketLabel(b string) string { return bucketLabel(b) }

// bucketLabel is the short human label for a bucket.
func bucketLabel(b string) string {
	switch b {
	case model.BucketCritical:
		return "CRITICAL"
	case model.BucketHigh:
		return "HIGH"
	case model.BucketMedium:
		return "MEDIUM"
	case model.BucketLow:
		return "LOW"
	}
	return "CLEAN"
}

func writeTable(w io.Writer, scan model.Scan, diff *model.DiffResult, tr *Trend) error {
	var b strings.Builder

	// New-finding ids, for the drift markers in the component table.
	newVulns := map[string]bool{}
	if diff != nil {
		for _, id := range diff.Summary.NewVulnIDs {
			newVulns[id] = true
		}
	}

	fmt.Fprintf(&b, "%s\n", paint(colorBold, "SCRAM supply chain scan"))
	fmt.Fprintf(&b, "%s\n", paint(colorDim, strings.Repeat("─", 64)))
	fmt.Fprintf(&b, "  repo        %s\n", scan.Repo)
	if scan.Commit != "" {
		fmt.Fprintf(&b, "  commit      %s\n", scan.Commit)
	}
	fmt.Fprintf(&b, "  components  %d\n", scan.Summary.TotalComponents)
	fmt.Fprintf(&b, "  findings    %d vulnerability record(s)\n", scan.Summary.VulnTotal)

	bucket := scan.Summary.RepoBucket
	fmt.Fprintf(&b, "  repo score  %d/100  %s\n", scan.Summary.RepoScore,
		paint(bucketColor(bucket), bucketLabel(bucket)))
	fmt.Fprintf(&b, "  breakdown   critical %d  high %d  medium %d  low %d  clean %d\n",
		scan.Summary.Counts[model.BucketCritical],
		scan.Summary.Counts[model.BucketHigh],
		scan.Summary.Counts[model.BucketMedium],
		scan.Summary.Counts[model.BucketLow],
		scan.Summary.Counts[model.BucketClean])
	// The trend row sits directly under the score so the two read together:
	// the number is where you are, the sparkline is which way you are moving.
	// A single sample is omitted rather than drawn, because one point drawn to
	// full width looks like a dramatic trend it cannot support.
	if tr != nil && tr.Samples > 1 {
		fmt.Fprintf(&b, "  trend       %s  %s\n",
			tr.Spark, trendChangeText(tr))
	}
	fmt.Fprintln(&b)

	if diff != nil {
		writeDriftSection(&b, diff)
	}

	// Components with findings, worst first.
	var flagged []model.Component
	for _, c := range scan.Components {
		if len(c.Vulnerabilities) > 0 {
			flagged = append(flagged, c)
		}
	}
	sort.Slice(flagged, func(i, j int) bool {
		si, sj := 0, 0
		if flagged[i].Score != nil {
			si = flagged[i].Score.Total
		}
		if flagged[j].Score != nil {
			sj = flagged[j].Score.Total
		}
		return si > sj
	})

	if len(flagged) == 0 {
		fmt.Fprintf(&b, "%s\n", paint(colorGreen, "  No known vulnerabilities found."))
	}

	for _, c := range flagged {
		marker := "  "
		if diff != nil {
			if d := findDrift(diff, c.Purl); d != nil {
				switch d.Change {
				case model.ChangeAdded:
					marker = paint(colorRed, "NEW ")
				case model.ChangeVersionChanged:
					marker = paint(colorYellow, "CHG ")
				}
			}
		}
		scoreStr := "0"
		if c.Score != nil {
			scoreStr = fmt.Sprintf("%d", c.Score.Total)
		}
		fmt.Fprintf(&b, "%s %s  %s\n",
			marker,
			paint(bucketColor(c.Bucket), fmt.Sprintf("%-8s", bucketLabel(c.Bucket))),
			c.Purl)
		fmt.Fprintf(&b, "         score %s/100, %d finding(s)\n", scoreStr, len(c.Vulnerabilities))
		for _, v := range c.Vulnerabilities {
			flag := " "
			if newVulns[v.ID] {
				flag = paint(colorRed, "N")
			}
			fix := ""
			if v.FixedVersion != "" {
				fix = fmt.Sprintf("  fixed in %s", v.FixedVersion)
			}
			cvss := "    -"
			if v.CVSSv3 > 0 {
				cvss = fmt.Sprintf("%.1f", v.CVSSv3)
			}
			epss := "  -  "
			if v.EPSS > 0 {
				epss = fmt.Sprintf("%.2f%%", v.EPSS*100)
			}
			fmt.Fprintf(&b, "         %s %-18s cvss %s  epss %s%s\n", flag, v.ID, cvss, epss, fix)
		}
		b.WriteString("\n")
	}

	// Warnings last, so they don't scroll past the findings.
	if len(scan.Warnings) > 0 {
		fmt.Fprintf(&b, "%s\n", paint(colorDim, "  warnings:"))
		for _, w := range scan.Warnings {
			fmt.Fprintf(&b, "    - %s\n", w)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeDriftSection(b *strings.Builder, diff *model.DiffResult) {
	var added, changed, removed, resolved int
	for _, d := range diff.Drifts {
		switch d.Change {
		case model.ChangeAdded:
			added++
		case model.ChangeVersionChanged:
			changed++
		case model.ChangeRemoved:
			removed++
		}
		resolved += len(d.ResolvedVulnerabilities)
	}

	fmt.Fprintf(b, "%s\n", paint(colorBold, "  Drift since baseline"))
	fmt.Fprintf(b, "    added %d   version-changed %d   removed %d\n", added, changed, removed)
	fmt.Fprintf(b, "    new vulnerabilities %d   resolved %d\n",
		len(diff.Summary.NewVulnIDs), resolved)
	if diff.Summary.NewHigh > 0 || diff.Summary.NewCritical > 0 {
		fmt.Fprintf(b, "    %s\n", paint(colorRed,
			fmt.Sprintf("    new high %d, new critical %d",
				diff.Summary.NewHigh, diff.Summary.NewCritical)))
	}
	b.WriteString("\n")
}

func findDrift(d *model.DiffResult, purl string) *model.Drift {
	for i := range d.Drifts {
		if d.Drifts[i].Purl == purl {
			return &d.Drifts[i]
		}
	}
	return nil
}

// Explain renders a single component's score breakdown for `--explain`.
func Explain(w io.Writer, c model.Component) error {
	_, err := io.WriteString(w, score.Explain(c))
	return err
}
