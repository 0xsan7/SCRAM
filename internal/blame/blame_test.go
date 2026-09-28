package blame

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// These drive a REAL git repository. Blame is a claim about history, and a
// test that mocks git would only test the mock. Each test builds a throwaway
// repo with a known commit sequence and asserts the answer.

type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	dir := t.TempDir()
	r := &repo{t: t, dir: dir}
	r.git("init", "-q", "-b", "main")
	r.git("config", "user.name", "Test Author")
	r.git("config", "user.email", "author@example.com")
	r.git("config", "commit.gpgsign", "false")
	return r
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2024-01-01T00:00:00Z",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (r *repo) write(name, content string) {
	r.t.Helper()
	full := filepath.Join(r.dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) commit(msg string) {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
}

// The headline case: a dependency introduced, then bumped months later. Blame
// must find BOTH the introduction and the bump, and attribute them correctly.
func TestBlameFindsIntroductionAndVersionChange(t *testing.T) {
	r := newRepo(t)
	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{
	  "node_modules/lodash":{"version":"4.17.11"},
	  "node_modules/express":{"version":"4.18.2"}}}`)
	r.commit("chore: initial lockfile")

	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{
	  "node_modules/lodash":{"version":"4.17.15"},
	  "node_modules/express":{"version":"4.18.2"}}}`)
	r.commit("chore: bump lodash to 4.17.15")

	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{
	  "node_modules/lodash":{"version":"4.17.21"},
	  "node_modules/express":{"version":"4.18.2"}}}`)
	r.commit("fix: upgrade lodash after prototype pollution advisory")

	rep, err := Blame(context.Background(), r.dir, "package-lock.json", "lodash", "4.17.21")
	if err != nil {
		t.Fatalf("Blame: %v", err)
	}
	if len(rep.History) != 3 {
		t.Fatalf("history = %d entries, want 3 (one per commit): %+v", len(rep.History), rep.History)
	}
	if rep.Introduced == nil {
		t.Fatal("no introduction found")
	}
	if rep.Introduced.Version != "4.17.11" {
		t.Errorf("introduced at %s, want 4.17.11", rep.Introduced.Version)
	}
	if rep.Introduced.Kind != "introduced" {
		t.Errorf("first entry kind = %q, want introduced", rep.Introduced.Kind)
	}
	if rep.LastChange == nil {
		t.Fatal("no version change found")
	}
	if rep.LastChange.Version != "4.17.21" {
		t.Errorf("last change version = %s, want 4.17.21", rep.LastChange.Version)
	}
	if rep.LastChange.Author != "Test Author" {
		t.Errorf("author = %q", rep.LastChange.Author)
	}
	// History must be oldest-first so a reader sees the sequence.
	if rep.History[0].Version != "4.17.11" || rep.History[2].Version != "4.17.21" {
		t.Errorf("history is not oldest-first: %v", rep.History)
	}
}

// A dependency present in only ONE commit and never touched again is the
// common case, and must not be reported as changed.
func TestBlameSingleAppearance(t *testing.T) {
	r := newRepo(t)
	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{
	  "node_modules/lodash":{"version":"4.17.11"}}}`)
	r.commit("add lodash")
	r.write("README.md", "unrelated change")
	r.commit("docs: unrelated")

	rep, err := Blame(context.Background(), r.dir, "package-lock.json", "lodash", "4.17.11")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.History) != 1 {
		t.Fatalf("history = %d, want 1", len(rep.History))
	}
	if rep.LastChange != nil {
		t.Errorf("LastChange set for a never-bumped dependency: %+v", rep.LastChange)
	}
	if rep.Introduced == nil || rep.Introduced.Kind != "introduced" {
		t.Errorf("expected a single 'introduced' entry, got %+v", rep.History)
	}
}

// A commit that rewrites the lockfile without changing the package must not
// show up in its history. Otherwise blame reports noise as change.
func TestBlameIgnoresUnrelatedLockfileEdits(t *testing.T) {
	r := newRepo(t)
	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{
	  "node_modules/lodash":{"version":"4.17.11"}}}`)
	r.commit("add lodash")
	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{
	  "node_modules/lodash":{"version":"4.17.11"},
	  "node_modules/left-pad":{"version":"1.3.0"}}}`)
	r.commit("add left-pad")

	rep, err := Blame(context.Background(), r.dir, "package-lock.json", "lodash", "4.17.11")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.History) != 1 {
		t.Errorf("lodash history = %d entries, want 1; unrelated lockfile edits leaked in: %+v",
			len(rep.History), rep.History)
	}
}

func TestBlamePackageNotInHistory(t *testing.T) {
	r := newRepo(t)
	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	r.commit("empty lockfile")

	rep, err := Blame(context.Background(), r.dir, "package-lock.json", "ghost", "1.0.0")
	if err != nil {
		t.Fatalf("a missing package must not be a hard error: %v", err)
	}
	if len(rep.History) != 0 || rep.Introduced != nil {
		t.Errorf("invented history for an absent package: %+v", rep)
	}
	if rep.Note == "" {
		t.Error("expected a note explaining why nothing was found")
	}
}

func TestBlameUntrackedLockfile(t *testing.T) {
	r := newRepo(t)
	r.write("package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	// Written but never committed.
	rep, err := Blame(context.Background(), r.dir, "package-lock.json", "lodash", "")
	if err != nil {
		t.Fatalf("untracked lockfile should degrade, not fail: %v", err)
	}
	if rep.ScannedCommits != 0 || rep.Note == "" {
		t.Errorf("expected a clear note for an untracked lockfile, got %+v", rep)
	}
}

// A repository with no commits at all must not panic or hang.
func TestBlameEmptyRepo(t *testing.T) {
	r := newRepo(t)
	rep, err := Blame(context.Background(), r.dir, "package-lock.json", "lodash", "")
	if err != nil {
		t.Fatalf("empty repo should degrade: %v", err)
	}
	if len(rep.History) != 0 {
		t.Errorf("history from an empty repo: %+v", rep.History)
	}
}

// Requirements.txt blame, which is a different lockfile format end to end.
func TestBlameRequirementsTxt(t *testing.T) {
	r := newRepo(t)
	r.write("requirements.txt", "flask==1.0.0\npyyaml==5.1\n")
	r.commit("add requirements")
	r.write("requirements.txt", "flask==1.0.0\npyyaml==5.3.1\n")
	r.commit("bump pyyaml")

	rep, err := Blame(context.Background(), r.dir, "requirements.txt", "pyyaml", "5.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Introduced == nil || rep.Introduced.Version != "5.1" {
		t.Fatalf("pyyaml introduced = %+v, want version 5.1", rep.Introduced)
	}
	if rep.LastChange == nil || rep.LastChange.Version != "5.3.1" {
		t.Errorf("pyyaml last change = %+v, want 5.3.1", rep.LastChange)
	}
}
