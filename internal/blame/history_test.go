package blame

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// These tests build real git repositories in a temp dir. The bugs below
// were not visible from hand-authored Report structs, because the bug is in
// the loop over commits, and a struct literal has no loop. Every case here
// is a commit sequence that happened to be skipped.

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=Tester", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", ".")
	run("config", "user.name", "Tester")
	run("config", "user.email", "t@example.com")
	run("config", "commit.gpgsign", "false")
	return dir
}

func commitFile(t *testing.T, dir, name, body, subject string, when time.Time) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := when.Format(time.RFC3339)
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=Tester", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_AUTHOR_DATE="+ts, "GIT_COMMITTER_DATE="+ts,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("add", "-A")
	run("commit", "-qm", subject)
}

func versionsOf(rep *Report) []string {
	var out []string
	for _, h := range rep.History {
		out = append(out, h.Version)
	}
	return out
}

// TestBlameReportsAReaddAfterRemoval is the regression for D41.
//
// A dependency that was dropped and re-added at the SAME version appeared in
// the report exactly once, with "introduced" pointing at its first
// appearance. The cause: the removed-commit branch did `continue` without
// clearing the "version at the previous commit" variable, so the re-add
// compared equal to the pre-removal version and was classified
// "unchanged" and dropped.
//
// The wrong output was confident and plausible: it said the package arrived
// at the first commit, when in fact the commit that put it in the tree as it
// stands today is a different one.
func TestBlameReportsAReaddAfterRemoval(t *testing.T) {
	dir := initRepo(t)
	d1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	d2 := d1.AddDate(1, 0, 0)
	d3 := d2.AddDate(1, 0, 0)

	commitFile(t, dir, "requirements.txt", "jinja2==2.10\nflask==1.0\n", "add both", d1)
	commitFile(t, dir, "requirements.txt", "flask==1.0\n", "drop jinja2", d2)
	commitFile(t, dir, "requirements.txt", "jinja2==2.10\nflask==1.0\n", "re-add jinja2", d3)

	rep, err := Blame(context.Background(), dir, "requirements.txt", "jinja2", "2.10")
	if err != nil {
		t.Fatalf("Blame: %v", err)
	}
	if got := len(rep.History); got != 2 {
		t.Fatalf("history has %d entries, want 2 (the original add and the "+
			"re-add): %v\nThe re-add is being classified as unchanged, which "+
			"means a removed-and-restored dependency looks like it was never "+
			"removed", got, versionsOf(rep))
	}
	if rep.History[0].Kind != "introduced" {
		t.Errorf("first entry kind = %q, want introduced", rep.History[0].Kind)
	}
	// The re-add must be reported as an introduction too: from the
	// repository's current point of view the package IS new.
	last := rep.History[len(rep.History)-1]
	if last.Kind != "introduced" {
		t.Errorf("last entry kind = %q (%s), want introduced: the commit that "+
			"put the package back is what a reviewer needs to see",
			last.Kind, last.Subject)
	}
	if last.Subject != "re-add jinja2" {
		t.Errorf("last entry subject = %q, want %q", last.Subject, "re-add jinja2")
	}
}

// TestBlameClearRemovedVersionIsEnough isolates the fix: prev must be
// cleared, and clearing it is the whole fix.
func TestBlameClearRemovedVersionIsEnough(t *testing.T) {
	dir := initRepo(t)
	d1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	commitFile(t, dir, "requirements.txt", "requests==2.19.1\n", "add", d1)
	commitFile(t, dir, "requirements.txt", "", "remove", d1.AddDate(1, 0, 0))
	commitFile(t, dir, "requirements.txt", "requests==2.19.1\n", "re-add", d1.AddDate(2, 0, 0))

	rep, err := Blame(context.Background(), dir, "requirements.txt", "requests", "2.19.1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.ScannedCommits != 3 {
		t.Fatalf("scanned %d commits, want 3", rep.ScannedCommits)
	}
	if len(rep.History) != 2 {
		t.Errorf("history has %d entries, want 2: %v", len(rep.History), versionsOf(rep))
	}
}

// TestBlameRemovalDoesNotInventAChange guards the other direction. The fix
// must not make a pure removal look like a version change.
func TestBlameRemovalDoesNotInventAChange(t *testing.T) {
	dir := initRepo(t)
	d1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	commitFile(t, dir, "requirements.txt", "requests==2.19.1\nflask==1.0\n", "add", d1)
	commitFile(t, dir, "requirements.txt", "requests==2.19.1\n", "drop flask", d1.AddDate(1, 0, 0))

	rep, err := Blame(context.Background(), dir, "requirements.txt", "requests", "2.19.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.History) != 1 {
		t.Errorf("history has %d entries, want 1: removing a DIFFERENT "+
			"package is not a change to this one: %v",
			len(rep.History), versionsOf(rep))
	}
	if rep.History[0].Kind != "introduced" {
		t.Errorf("kind = %q, want introduced", rep.History[0].Kind)
	}
}

// TestBlameReportsShallowClone is the regression for the second half of D41.
//
// A shallow clone was reporting "introduced 6.7y ago" from its single
// commit. That is the one claim this command exists to make, stated from a
// history that provably cannot support it, and the note explaining it was
// rendered at the bottom of the output where nobody reads.
func TestBlameReportsShallowClone(t *testing.T) {
	src := initRepo(t)
	d1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	commitFile(t, src, "requirements.txt", "jinja2==2.10\n", "add", d1)
	commitFile(t, src, "requirements.txt", "jinja2==3.1.4\n", "bump", d1.AddDate(1, 0, 0))
	commitFile(t, src, "requirements.txt", "jinja2==2.10\n", "revert", d1.AddDate(2, 0, 0))

	// A real `git clone --depth 1`, not a faked .git/shallow file: the point
	// is that the common case is detected by the common case's shape.
	dst := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot make a shallow clone here: %v\n%s", err, out)
	}

	rep, err := Blame(context.Background(), dst, "requirements.txt", "jinja2", "2.10")
	if err != nil {
		t.Fatalf("Blame on a shallow clone must not fail: %v", err)
	}
	if !rep.Shallow {
		t.Fatalf("Shallow is false in a `git clone --depth 1`; the note "+
			"would be %q", rep.Note)
	}
	if rep.Note == "" {
		t.Error("a shallow clone produced no note; the limitation must be " +
			"stated, not implied")
	}
	if rep.Introduced == nil {
		t.Fatal("no Introduced entry")
	}
	// The JSON consumer needs the flag too, not just the rendered text.
	if rep.Shallow == false {
		t.Error("Shallow must survive into the JSON output")
	}
}

// TestBlameFullCloneIsNotMarkedShallow is the other direction: a complete
// history must not be labelled as truncated, or the warning becomes noise
// people learn to skip.
func TestBlameFullCloneIsNotMarkedShallow(t *testing.T) {
	dir := initRepo(t)
	d1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	commitFile(t, dir, "requirements.txt", "jinja2==2.10\n", "add", d1)
	commitFile(t, dir, "requirements.txt", "jinja2==3.1.4\n", "bump", d1.AddDate(1, 0, 0))

	rep, err := Blame(context.Background(), dir, "requirements.txt", "jinja2", "3.1.4")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Shallow {
		t.Error("a full clone was reported as shallow")
	}
	if rep.Introduced == nil || rep.Introduced.Subject != "add" {
		t.Errorf("Introduced = %+v, want the 'add' commit", rep.Introduced)
	}
}

// TestBlameHistoryIsOldestFirst pins the ordering the rendered output and
// the "last change" selection both depend on. Getting it wrong makes blame
// confidently report the wrong commit, which is the failure mode that
// matters most for a tool whose output is a date and a person.
func TestBlameHistoryIsOldestFirst(t *testing.T) {
	dir := initRepo(t)
	d1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	commitFile(t, dir, "requirements.txt", "jinja2==2.10\n", "v2.10", d1)
	commitFile(t, dir, "requirements.txt", "jinja2==3.1.4\n", "bump", d1.AddDate(1, 0, 0))
	commitFile(t, dir, "requirements.txt", "jinja2==2.10\n", "revert", d1.AddDate(2, 0, 0))

	rep, err := Blame(context.Background(), dir, "requirements.txt", "jinja2", "2.10")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2.10", "3.1.4", "2.10"}
	if len(rep.History) != len(want) {
		t.Fatalf("history = %v, want %v", versionsOf(rep), want)
	}
	for i, w := range want {
		if rep.History[i].Version != w {
			t.Errorf("history[%d] = %s, want %s (full: %v)",
				i, rep.History[i].Version, w, versionsOf(rep))
		}
	}
	// After a revert the most RECENT version change is the revert, not the
	// bump. That is the correct answer and the one a reviewer wants: the
	// revert is the last thing that happened to this dependency.
	if rep.LastChange == nil {
		t.Fatal("no LastChange")
	}
	if rep.LastChange.Subject != "revert" || rep.LastChange.Version != "2.10" {
		t.Errorf("LastChange = %+v, want the revert to 2.10", rep.LastChange)
	}
}

// TestBlameLockfileAddedLate pins the "no commit touched it earlier" case:
// the first commit in the history is not the repository's first commit, and
// blame must not imply otherwise.
func TestBlameLockfileAddedLate(t *testing.T) {
	dir := initRepo(t)
	d1 := time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	commitFile(t, dir, "README.md", "project\n", "init", d1)
	commitFile(t, dir, "requirements.txt", "jinja2==3.1.4\n", "add deps", d1.AddDate(2, 0, 0))

	rep, err := Blame(context.Background(), dir, "requirements.txt", "jinja2", "3.1.4")
	if err != nil {
		t.Fatal(err)
	}
	if rep.ScannedCommits != 1 {
		t.Errorf("scanned %d commits, want 1 (only one touches the lockfile)",
			rep.ScannedCommits)
	}
	if rep.Shallow {
		t.Error("a full clone with one lockfile-touching commit is not a " +
			"shallow clone; the note would be a lie")
	}
	if rep.Introduced == nil || rep.Introduced.Subject != "add deps" {
		t.Errorf("Introduced = %+v, want the 'add deps' commit", rep.Introduced)
	}
}

// TestBlameEmptyHistoryIsNotAnError: a package that is not in the tree has no
// history, and that is a normal answer, not a failure.
func TestBlameEmptyHistoryIsNotAnError(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "requirements.txt", "flask==1.0\n",
		"add", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	rep, err := Blame(context.Background(), dir, "requirements.txt", "absent", "1.0")
	if err != nil {
		t.Fatalf("Blame: %v", err)
	}
	if len(rep.History) != 0 {
		t.Errorf("history = %v, want empty", versionsOf(rep))
	}
	if rep.Note == "" {
		t.Error("no note explaining that nothing in the scanned history " +
			"resolved the package")
	}
}
