package trend

import (
	"errors"
	"testing"
)

// The sparkline is read at a glance, so its failure mode is a picture that
// looks meaningful and is not. These pin the cases where that can happen.

func TestSparklineEmpty(t *testing.T) {
	if got := Sparkline(nil); got != "" {
		t.Errorf("empty series rendered %q, want empty so the caller can omit the row", got)
	}
}

// One sample is not a trend. Drawing a full-looking bar for it would imply a
// history that does not exist.
func TestSparklineSingleSampleIsNotATrend(t *testing.T) {
	got := Sparkline([]int{50})
	if got == "" {
		t.Error("single sample rendered nothing")
	}
	if len([]rune(got)) != 1 {
		t.Errorf("single sample rendered %d cells, want 1", len([]rune(got)))
	}
}

func TestSparklineRisesAndFalls(t *testing.T) {
	got := Sparkline([]int{12, 18, 30, 41, 20, 11})
	r := []rune(got)
	if len(r) != 6 {
		t.Fatalf("rendered %d cells for 6 samples", len(r))
	}
	// A rise then a fall must produce a rise then a fall, not a monotone ramp.
	peak := indexOfMax(r)
	if peak != 3 {
		t.Errorf("peak at cell %d, want 3 (the maximum sample)", peak)
	}
	for i := 1; i <= peak; i++ {
		if r[i] < r[i-1] {
			t.Errorf("cell %d decreased during the rising section", i)
		}
	}
	for i := peak + 1; i < len(r); i++ {
		if r[i] > r[i-1] {
			t.Errorf("cell %d increased during the falling section", i)
		}
	}
}

// A constant score stretched across the full ramp height reads as a dramatic
// trend. It must render flat.
func TestSparklineFlatSeriesIsFlat(t *testing.T) {
	got := []rune(Sparkline([]int{40, 40, 40, 40}))
	for i := 1; i < len(got); i++ {
		if got[i] != got[0] {
			t.Fatalf("flat series rendered as a trend: %q", string(got))
		}
	}
}

func TestSparklineSingleValueSeriesIsFlat(t *testing.T) {
	got := []rune(Sparkline([]int{7, 7, 7}))
	for i := 1; i < len(got); i++ {
		if got[i] != got[0] {
			t.Errorf("constant-7 series rendered as a trend: %q", string(got))
		}
	}
}

func TestDelta(t *testing.T) {
	cases := []struct {
		in   []int
		want int
	}{
		{[]int{12, 41}, 29},
		{[]int{41, 12}, -29},
		{[]int{5}, 0},
		{nil, 0},
		{[]int{10, 10}, 0},
	}
	for _, c := range cases {
		if got := Delta(c.in); got != c.want {
			t.Errorf("Delta(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestLastOldestFirst(t *testing.T) {
	f := &File{Points: []Point{
		{Score: 1}, {Score: 2}, {Score: 3}, {Score: 4}, {Score: 5},
	}}
	got := Last(f, 3)
	if len(got) != 3 || got[0].Score != 3 || got[2].Score != 5 {
		t.Errorf("Last(f,3) = %v, want scores 3,4,5 oldest-first", Scores(got))
	}
	if n := len(Last(f, 99)); n != 5 {
		t.Errorf("oversized n returned %d points, want all 5", n)
	}
	if n := len(Last(f, 0)); n != 5 {
		t.Errorf("n=0 should mean all, got %d", n)
	}
	if n := len(Last(nil, 5)); n != 0 {
		t.Errorf("nil file returned %d points", n)
	}
}

func TestAppendDeduplicatesSameCommit(t *testing.T) {
	path := t.TempDir() + "/t.json"
	for i := 0; i < 3; i++ {
		if _, err := Append(path, Point{Score: 50, Commit: "abc", Count: 10}, fixedTime()); err != nil {
			t.Fatal(err)
		}
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Points) != 1 {
		t.Errorf("re-scanning the same commit produced %d points, want 1", len(f.Points))
	}
}

func TestAppendKeepsDistinctCommits(t *testing.T) {
	path := t.TempDir() + "/t.json"
	for i, c := range []string{"a", "b", "c"} {
		if _, err := Append(path, Point{Score: i * 10, Commit: c}, fixedTime()); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := Load(path)
	if len(f.Points) != 3 {
		t.Errorf("points = %d, want 3", len(f.Points))
	}
	if f.Points[0].Score != 0 || f.Points[2].Score != 20 {
		t.Errorf("points out of order: %v", Scores(f.Points))
	}
}

func TestAppendCapsHistory(t *testing.T) {
	path := t.TempDir() + "/t.json"
	for i := 0; i < MaxPoints+25; i++ {
		if _, err := Append(path, Point{Score: i % 100, Commit: string(rune('a'+i%26)) + itoa(i)}, fixedTime()); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := Load(path)
	if len(f.Points) != MaxPoints {
		t.Errorf("history length = %d, want the cap of %d", len(f.Points), MaxPoints)
	}
}

func TestLoadMissingFile(t *testing.T) {
	f, err := Load(t.TempDir() + "/absent.json")
	if err != nil {
		t.Fatalf("a missing file should be an empty trend, not an error: %v", err)
	}
	if len(f.Points) != 0 {
		t.Errorf("points = %d, want 0", len(f.Points))
	}
}

// A truncated or hand-edited file must error rather than silently reporting an
// empty history, which would look like a repo that has never been scanned.
func TestLoadCorruptFileErrors(t *testing.T) {
	path := t.TempDir() + "/t.json"
	write(t, path, "{not json")
	if _, err := Load(path); err == nil {
		t.Error("corrupt trend file loaded as valid")
	}
}

func TestLoadWrongSchemaVersionErrors(t *testing.T) {
	path := t.TempDir() + "/t.json"
	write(t, path, `{"schema_version":99,"points":[]}`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("wrong schema version loaded as valid")
	}
	// errors.As rather than a type assertion: the assertion breaks the
	// moment Load starts wrapping, which is exactly when this test would
	// start failing for the wrong reason.
	var ve *VersionError
	if !errors.As(err, &ve) {
		t.Errorf("error type = %T, want *VersionError", err)
	}
}

func TestScores(t *testing.T) {
	got := Scores([]Point{{Score: 3}, {Score: 1}, {Score: 2}})
	if len(got) != 3 || got[0] != 3 || got[2] != 2 {
		t.Errorf("Scores = %v, want [3 1 2] in input order", got)
	}
}

func indexOfMax(r []rune) int {
	best := 0
	for i := 1; i < len(r); i++ {
		if r[i] > r[best] {
			best = i
		}
	}
	return best
}
