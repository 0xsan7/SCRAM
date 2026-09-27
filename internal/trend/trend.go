// Package trend records a repo's risk score over time and renders it as a
// one-line sparkline.
//
// A single score tells you where you are. It does not tell you whether you are
// sinking, and a team that only ever sees today's number has no way to notice
// that the last six dependency bumps each cost a little until one of them
// costs a lot. The trend is the signal; today's number is one sample of it.
//
// History is a local append-only file, not a service. There is no account, no
// telemetry, and nothing leaves the machine — consistent with a tool whose
// entire value proposition is that it is the scanner you run yourself.
package trend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// SchemaVersion guards the on-disk format.
const SchemaVersion = 1

// DefaultPath is where score history lives, relative to the repo root.
const DefaultPath = ".scram-trend.json"

// MaxPoints bounds the file. A few years of daily CI runs is ~1000 points;
// past that the early history stops being interesting and the file starts
// being a liability in a diff.
const MaxPoints = 500

// Point is one recorded scan.
type Point struct {
	// Date is the scan timestamp, RFC 3339.
	Date string `json:"date"`
	// Score is the repo risk score, 0-100.
	Score int `json:"score"`
	// Bucket is the severity label at that scan.
	Bucket string `json:"bucket"`
	// Count is the number of components scanned, so a score that moves
	// because the tree changed size is distinguishable from one that moved
	// because risk did.
	Count int `json:"count"`
	// Commit is the git HEAD at scan time, when available.
	Commit string `json:"commit,omitempty"`
}

// File is the on-disk document.
type File struct {
	SchemaVersion int     `json:"schema_version"`
	Repo          string  `json:"repo,omitempty"`
	Points        []Point `json:"points"`
}

// Load reads history, returning an empty document if the file is absent.
// A corrupt file is an error, not a silent reset: losing the trend should be
// visible, and the file is small and version-controlled by convention.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &File{SchemaVersion: SchemaVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.SchemaVersion != SchemaVersion {
		return nil, &VersionError{Want: SchemaVersion, Got: f.SchemaVersion}
	}
	return &f, nil
}

// VersionError reports an unreadable schema version.
type VersionError struct{ Want, Got int }

func (e *VersionError) Error() string {
	return "trend file has schema_version " + itoa(e.Got) + ", this build understands " + itoa(e.Want)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

// Append records a scan. If a point already exists for the same commit, it is
// replaced rather than duplicated, so re-running a scan does not inflate the
// trend with identical samples.
func Append(path string, p Point, now time.Time) (*File, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	if p.Date == "" {
		p.Date = now.UTC().Format(time.RFC3339)
	}
	replaced := false
	for i := range f.Points {
		if p.Commit != "" && f.Points[i].Commit == p.Commit {
			f.Points[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		f.Points = append(f.Points, p)
	}
	if len(f.Points) > MaxPoints {
		f.Points = f.Points[len(f.Points)-MaxPoints:]
	}
	if err := save(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

// save writes atomically via a temp file in the same directory, so a scan
// interrupted mid-write cannot leave a truncated history behind.
func save(path string, f *File) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".scram-trend-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// RAMP is the eight-level Unicode sparkline set, lowest to highest. Chosen
// over block characters because it renders in most terminals without a
// graphics font, and the jump between levels is visible in a short run where
// finer gradation would compress to identical glyphs.
const RAMP = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"

// levels is RAMP decoded once, since indexing a string by byte position on a
// multi-byte constant would slice mid-rune.
var levels = []rune(RAMP)

// Sparkline renders the last n scores. Returns an empty string when there is
// nothing to draw, so callers can omit the line rather than print a
// meaningless row of empty cells.
func Sparkline(scores []int) string {
	if len(scores) == 0 {
		return ""
	}
	// One glyph is not a trend. Returning the bar alone would imply a
	// history that does not exist.
	if len(scores) == 1 {
		return string(levels[0])
	}
	lo, hi := scores[0], scores[0]
	for _, s := range scores {
		if s < lo {
			lo = s
		}
		if s > hi {
			hi = s
		}
	}
	span := hi - lo
	out := make([]rune, len(scores))
	for i, s := range scores {
		idx := 0
		if span > 0 {
			// Scale into 0..7. A flat series sits at the bottom rather than
			// being stretched across the full height, which would make a
			// constant score look like a dramatic trend.
			idx = (s - lo) * (len(levels) - 1) / span
		}
		out[i] = levels[idx]
	}
	return string(out)
}

// Delta returns score[n-1] - score[0] over the window, for the "has grown from
// X to Y" phrasing.
func Delta(scores []int) int {
	if len(scores) < 2 {
		return 0
	}
	return scores[len(scores)-1] - scores[0]
}

// Last returns the most recent n points, oldest-first, which is the order a
// sparkline reads in.
func Last(f *File, n int) []Point {
	if f == nil || len(f.Points) == 0 {
		return nil
	}
	if n <= 0 || n >= len(f.Points) {
		out := make([]Point, len(f.Points))
		copy(out, f.Points)
		return out
	}
	out := make([]Point, n)
	copy(out, f.Points[len(f.Points)-n:])
	return out
}

// Scores extracts the score series from points.
func Scores(pts []Point) []int {
	out := make([]int, len(pts))
	for i, p := range pts {
		out[i] = p.Score
	}
	return out
}
