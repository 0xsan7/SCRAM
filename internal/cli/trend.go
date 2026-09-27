package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/report"
	"github.com/0xsan7/scram/internal/trend"
)

// trendWindow is how many recent scans the sparkline shows. Twenty is about
// as much as fits legibly on one terminal line while still being wide enough
// for a slope to read as a slope.
const trendWindow = 20

// recordTrend appends this scan to the local history and returns the rendered
// trend for display.
//
// Every failure here is non-fatal. The trend is an aid, not a result: a
// read-only checkout, a corrupt file, or a full disk must not turn a working
// scan into a failed one, so errors are returned only for the caller to log
// under --verbose.
func recordTrend(path string, s model.Scan) (*report.Trend, error) {
	// model.Scan carries no timestamp, so the sample is stamped with the
	// moment it was recorded. That is the honest reading anyway: the trend
	// records when SCRAM observed the score, which is what a reader watching
	// the sparkline over time actually cares about.
	pt := trend.Point{
		Date:   time.Now().UTC().Format(time.RFC3339),
		Score:  s.Summary.RepoScore,
		Bucket: s.Summary.RepoBucket,
		Count:  s.Summary.TotalComponents,
		Commit: s.Commit,
	}

	f, err := trend.Append(path, pt, time.Now())
	if err != nil {
		return nil, err
	}
	pts := trend.Last(f, trendWindow)
	if len(pts) < 2 {
		// One sample is not a trend; the report omits the row for this.
		return nil, nil
	}
	return &report.Trend{
		Spark:   trend.Sparkline(trend.Scores(pts)),
		First:   pts[0].Score,
		Last:    pts[len(pts)-1].Score,
		Samples: len(pts),
		Path:    path,
	}, nil
}

// warnTrendFailure keeps an unwritable history from failing a scan. The trend
// is an aid, not a result: a read-only checkout or a full disk must not turn a
// working scan into a failed one, so the note goes to stderr and only when
// verbose, since the user did not ask for this output.
func warnTrendFailure(err error, verbose bool) {
	if err == nil || !verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "\nnote: score history not updated: %v\n", err)
}
