package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOriginRemotes covers the small git-config reader behind the
// --scorecard default. It is a deliberately partial parser, so these are the
// shapes it has to get right rather than a general git-config suite.
func TestOriginRemotes(t *testing.T) {
	const real = `[core]
	repositoryformatversion = 0
[remote "origin"]
	url = https://github.com/0xsan7/SCRAM.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`
	got := originRemotes(real)
	if len(got) != 1 {
		t.Fatalf("originRemotes = %v, want exactly 1 remote", got)
	}
	if got[0] != "https://github.com/0xsan7/SCRAM.git" {
		t.Errorf("url = %q", got[0])
	}
}

func TestOriginRemotesEdgeCases(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   []string
	}{
		{"empty", "", nil},
		{"no remotes", "[core]\n\tbare = false\n", nil},
		{"comments stripped", "# [remote \"x\"]\n[remote \"origin\"]\n\turl = a/b\n", []string{"a/b"}},
		{"inline comment", "[remote \"origin\"]\n\turl = a/b # trailing\n", []string{"a/b"}},
		{"semicolon comment", "[remote \"origin\"]\n\turl = a/b ; note\n", []string{"a/b"}},
		{"bare remote section is not a named remote", "[remote]\n\turl = a/b\n", nil},
		{"pushurl is not url", "[remote \"origin\"]\n\tpushurl = a/b\n", nil},
		{"two remotes", "[remote \"a\"]\n\turl = x/y\n[remote \"b\"]\n\turl = p/q\n", []string{"x/y", "p/q"}},
		{"empty url ignored", "[remote \"origin\"]\n\turl =\n", nil},
		{"no equals sign", "[remote \"origin\"]\n\turl a/b\n", nil},
		{"whitespace around key", "[remote \"origin\"]\n\t  url   =   a/b  \n", []string{"a/b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := originRemotes(c.config)
			if len(got) != len(c.want) {
				t.Fatalf("originRemotes = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestGitOriginProjectInWorktree covers the case that makes this worth its
// own test. In a linked worktree or submodule, .git is a FILE containing
// "gitdir: ...", not a directory. Reading ".git/config" there returns
// nothing, and the maintenance term silently drops to zero -- which is the
// kind of failure that looks like "the tool decided this project is
// unmaintained".
func TestGitOriginProjectInWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	main := filepath.Join(root, "main")

	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run(root, "init", "-q", main)
	run(main, "config", "user.email", "t@example.com")
	run(main, "config", "user.name", "t")
	run(main, "remote", "add", "origin", "https://github.com/0xsan7/SCRAM.git")
	if err := os.WriteFile(filepath.Join(main, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(main, "add", "-A")
	run(main, "commit", "-qm", "one")

	// An ordinary clone: .git is a directory.
	if got := gitOriginProject(main); got != "https://github.com/0xsan7/SCRAM.git" {
		t.Errorf("plain repo: gitOriginProject = %q, want the origin url", got)
	}

	// A linked worktree: .git is a file.
	wt := filepath.Join(root, "wt")
	run(main, "worktree", "add", "-q", wt, "-b", "wtbranch")
	info, err := os.Stat(filepath.Join(wt, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Fatal("expected .git to be a file in a linked worktree; test premise is wrong")
	}
	if got := gitOriginProject(wt); got != "https://github.com/0xsan7/SCRAM.git" {
		t.Errorf("worktree: gitOriginProject = %q, want the origin url "+
			"(reading .git/config in a worktree returns nothing)", got)
	}
}

// TestGitOriginProjectNotARepo keeps the no-op case honest: a directory
// that is not a repository yields "" and the term is simply not computed.
func TestGitOriginProjectNotARepo(t *testing.T) {
	if got := gitOriginProject(t.TempDir()); got != "" {
		t.Errorf("gitOriginProject on a plain directory = %q, want empty", got)
	}
	if got := gitOriginProject(filepath.Join(t.TempDir(), "does-not-exist")); got != "" {
		t.Errorf("gitOriginProject on a missing path = %q, want empty", got)
	}
}

// TestOriginRemotesDoesNotPanic is a cheap guard: this runs on every scan
// that has a .git directory, so it must not be able to crash a scan.
func TestOriginRemotesDoesNotPanic(t *testing.T) {
	inputs := []string{
		"", "\x00", "\n\n\n", "[", "]", "[[[", "]", "=",
		"[remote \"origin\"]\n\turl=", "[:\nurl=a/b",
		strings.Repeat("[remote \"a\"]\n\turl = x/y\n", 500),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("originRemotes panicked on %q: %v", in, r)
				}
			}()
			_ = originRemotes(in)
		}()
	}
}
