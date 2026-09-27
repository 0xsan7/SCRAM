package drift

import (
	"os"
	"testing"
	"time"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/score"
)

// comp builds a scored component for tests.
func comp(name, version string, bucket string, vulns ...model.Vuln) model.Component {
	c := model.Component{
		Purl:            "pkg:npm/" + name + "@" + version,
		Name:            name,
		Version:         version,
		Ecosystem:       model.EcoNPM,
		Bucket:          bucket,
		Vulnerabilities: vulns,
	}
	c.Score = &model.Score{Total: scoreOfBucket(bucket)}
	return c
}

func scoreOfBucket(b string) int {
	switch b {
	case model.BucketCritical:
		return 95
	case model.BucketHigh:
		return 75
	case model.BucketMedium:
		return 50
	case model.BucketLow:
		return 20
	}
	return 0
}

func vuln(id string, cvss float64) model.Vuln {
	return model.Vuln{ID: id, CVSSv3: cvss, Source: "osv"}
}

func scanOf(repo string, comps ...model.Component) model.Scan {
	e := score.New()
	s := model.Scan{
		SchemaVersion: model.SchemaVersion,
		Repo:          repo,
		Commit:        "abc123",
		Components:    comps,
	}
	s.Summary = e.Score(comps)
	return s
}

// TestDiffVersionChangeIntroducesVulns is the drift test from PRD §16: bump a
// dependency to a vulnerable version and assert the diff flags the new CVEs.
func TestDiffVersionChangeIntroducesVulns(t *testing.T) {
	base := scanOf("app", comp("lodash", "4.17.21", model.BucketClean))
	head := scanOf("app", comp("lodash", "4.17.11", model.BucketHigh,
		vuln("CVE-2019-10744", 9.1),
		vuln("CVE-2021-23337", 7.2),
	))

	d := Diff(base, head)

	if len(d.Drifts) != 1 {
		t.Fatalf("want 1 drift entry, got %d", len(d.Drifts))
	}
	got := d.Drifts[0]
	if got.Change != model.ChangeVersionChanged {
		t.Errorf("change: got %q, want %q", got.Change, model.ChangeVersionChanged)
	}
	if got.PreviousVersion != "4.17.21" || got.NewVersion != "4.17.11" {
		t.Errorf("versions: got %s -> %s, want 4.17.21 -> 4.17.11", got.PreviousVersion, got.NewVersion)
	}
	if len(got.NewVulnerabilities) != 2 {
		t.Errorf("new vulns: got %v, want 2 entries", got.NewVulnerabilities)
	}
	// Both new CVEs are at or above 7.0 (9.1 and 7.2), so both count as high,
	// and the 9.1 additionally counts as critical.
	if d.Summary.NewHigh != 2 {
		t.Errorf("new high: got %d, want 2 (CVSS 9.1 and 7.2)", d.Summary.NewHigh)
	}
	if d.Summary.NewCritical != 1 {
		t.Errorf("new critical: got %d, want 1 (only the 9.1)", d.Summary.NewCritical)
	}
	if len(d.Summary.NewVulnIDs) != 2 {
		t.Errorf("new vuln ids: got %v, want 2", d.Summary.NewVulnIDs)
	}
}

// TestDiffNewHighCountedByVulnNotComponent is the regression test for a real
// gating flaw: a component whose aggregate score lands in the medium bucket
// can still carry a newly introduced CVSS 9.8. Gating on the component's
// bucket alone reported "new high: 0" and let it through.
func TestDiffNewHighCountedByVulnNotComponent(t *testing.T) {
	// Component aggregate score is medium (50/100) even though it holds a 9.8.
	head := scanOf("app", comp("pkg", "1.0.0", model.BucketMedium, vuln("CVE-X", 9.8)))
	base := scanOf("app", comp("pkg", "0.9.0", model.BucketClean))

	d := Diff(base, head)

	if d.Summary.NewHigh != 1 {
		t.Errorf("new high: got %d, want 1 — a 9.8 must count as high "+
			"regardless of the component's aggregate bucket", d.Summary.NewHigh)
	}
	if d.Summary.NewCritical != 1 {
		t.Errorf("new critical: got %d, want 1", d.Summary.NewCritical)
	}
}

func TestDiffAddedComponent(t *testing.T) {
	base := scanOf("app")
	head := scanOf("app", comp("minimist", "1.2.0", model.BucketHigh, vuln("CVE-Y", 7.5)))

	d := Diff(base, head)
	if len(d.Drifts) != 1 || d.Drifts[0].Change != model.ChangeAdded {
		t.Fatalf("want one added drift, got %+v", d.Drifts)
	}
	if d.Summary.NewHigh != 1 {
		t.Errorf("new high: got %d, want 1", d.Summary.NewHigh)
	}
}

func TestDiffRemovedComponent(t *testing.T) {
	base := scanOf("app", comp("minimist", "1.2.0", model.BucketHigh, vuln("CVE-Y", 7.5)))
	head := scanOf("app")

	d := Diff(base, head)
	if len(d.Drifts) != 1 || d.Drifts[0].Change != model.ChangeRemoved {
		t.Fatalf("want one removed drift, got %+v", d.Drifts)
	}
	if len(d.Drifts[0].ResolvedVulnerabilities) != 1 {
		t.Errorf("resolved: got %v, want 1", d.Drifts[0].ResolvedVulnerabilities)
	}
	// A removal introduces nothing, so it must not gate.
	if d.Summary.NewHigh != 0 {
		t.Errorf("new high after removal: got %d, want 0", d.Summary.NewHigh)
	}
}

// TestDiffUnchangedDoesNotRegate is the property that makes the tool
// adoptable: an unchanged repo must never go red just because it has old
// findings still present.
func TestDiffUnchangedDoesNotRegate(t *testing.T) {
	v := vuln("CVE-OLD", 9.8)
	s := scanOf("app", comp("pkg", "1.0.0", model.BucketCritical, v))

	d := Diff(s, s)
	if d.Summary.NewHigh != 0 || d.Summary.NewCritical != 0 {
		t.Errorf("unchanged scan reported %d new high / %d new critical, want 0/0",
			d.Summary.NewHigh, d.Summary.NewCritical)
	}
	if len(d.Summary.NewVulnIDs) != 0 {
		t.Errorf("unchanged scan reported new vulns %v, want none", d.Summary.NewVulnIDs)
	}
}

func TestDiffResolvedVulnerability(t *testing.T) {
	base := scanOf("app", comp("lodash", "4.17.11", model.BucketHigh, vuln("CVE-A", 7.5)))
	head := scanOf("app", comp("lodash", "4.17.21", model.BucketClean))

	d := Diff(base, head)
	if len(d.Drifts) != 1 {
		t.Fatalf("want 1 drift, got %d", len(d.Drifts))
	}
	if len(d.Drifts[0].ResolvedVulnerabilities) != 1 {
		t.Errorf("resolved: got %v, want 1", d.Drifts[0].ResolvedVulnerabilities)
	}
	if len(d.Drifts[0].NewVulnerabilities) != 0 {
		t.Errorf("new: got %v, want none", d.Drifts[0].NewVulnerabilities)
	}
	// The score should improve after upgrading.
	if d.Drifts[0].ScoreDelta >= 0 {
		t.Errorf("score delta: got %d, want negative (upgrading a vuln reduces risk)",
			d.Drifts[0].ScoreDelta)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/baseline.json"
	original := scanOf("app", comp("lodash", "4.17.21", model.BucketClean))

	if err := WriteBaseline(path, original); err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	loaded, err := ReadBaseline(path)
	if err != nil {
		t.Fatalf("ReadBaseline: %v", err)
	}
	if loaded.Repo != original.Repo {
		t.Errorf("repo: got %q, want %q", loaded.Repo, original.Repo)
	}
	if len(loaded.Components) != len(original.Components) {
		t.Fatalf("components: got %d, want %d", len(loaded.Components), len(original.Components))
	}
	if loaded.Components[0].Purl != original.Components[0].Purl {
		t.Errorf("purl: got %q, want %q", loaded.Components[0].Purl, original.Components[0].Purl)
	}
	if loaded.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema version: got %q, want %q", loaded.SchemaVersion, model.SchemaVersion)
	}
}

// TestBaselineIsDeterministic guards FR-404: the file is committed to a repo,
// so writing the same scan twice must produce byte-identical output or every
// run shows up as a diff.
func TestBaselineIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	a := dir + "/a.json"
	b := dir + "/b.json"
	s := scanOf("app",
		comp("zebra", "1.0.0", model.BucketLow),
		comp("alpha", "2.0.0", model.BucketHigh, vuln("CVE-Q", 7.0)),
		comp("mango", "3.0.0", model.BucketClean),
	)

	if err := WriteBaseline(a, s); err != nil {
		t.Fatal(err)
	}
	// GeneratedAt is a timestamp, so compare everything else by reading the
	// file and checking component ordering, which is what must be stable.
	if err := WriteBaseline(b, s); err != nil {
		t.Fatal(err)
	}
	da, err := ReadBaseline(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := ReadBaseline(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range da.Components {
		if da.Components[i].Purl != db.Components[i].Purl {
			t.Fatalf("component %d differs between writes: %q vs %q",
				i, da.Components[i].Purl, db.Components[i].Purl)
		}
	}
	// Components must be sorted by ecosystem then name.
	if da.Components[0].Name != "alpha" {
		t.Errorf("components not sorted: first is %q, want alpha", da.Components[0].Name)
	}
}

// TestLoadMissingBaselineIsNotAnError covers the normal first-run state: no
// baseline file yet, and that must not be a failure.
func TestLoadMissingBaselineIsNotAnError(t *testing.T) {
	s, err := Load(t.TempDir() + "/does-not-exist.json")
	if err != nil {
		t.Fatalf("Load on a missing baseline returned an error: %v", err)
	}
	if len(s.Components) != 0 {
		t.Errorf("expected an empty scan, got %d components", len(s.Components))
	}
}

func TestDiffEmptyBaselineTreatsAllAsNew(t *testing.T) {
	// First run: no baseline, so everything present is "new". This is what
	// a repo sees the day it adopts SCRAM.
	head := scanOf("app", comp("lodash", "4.17.11", model.BucketHigh, vuln("CVE-Z", 7.5)))
	d := Diff(model.Scan{SchemaVersion: model.SchemaVersion}, head)
	if d.Summary.NewHigh != 1 {
		t.Errorf("new high on first run: got %d, want 1", d.Summary.NewHigh)
	}
}

func TestWriteBaselineHandlesEmpty(t *testing.T) {
	path := t.TempDir() + "/b.json"
	if err := WriteBaseline(path, scanOf("empty")); err != nil {
		t.Fatalf("writing an empty baseline: %v", err)
	}
	loaded, err := ReadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Components) != 0 {
		t.Errorf("expected 0 components, got %d", len(loaded.Components))
	}
}

func TestWriteBaselineTimestampIsSet(t *testing.T) {
	path := t.TempDir() + "/b.json"
	before := time.Now().Add(-time.Second)
	if err := WriteBaseline(path, scanOf("app")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Before(before) {
		t.Error("baseline file was not written recently")
	}
}
