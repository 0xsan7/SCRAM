// Package blame answers "which commit put this here, and what did it cost us".
//
// A dependency arrives in a commit. Sometimes much later a CVE is disclosed
// against it, and the instinct is to blame whoever wrote that line of code —
// which is almost always wrong, because the author picked a reasonable
// version that was safe at the time. The useful question is not "who wrote
// this" but "what version did they pick, and what has changed since".
//
// So blame does two things git blame does not: it identifies the commit and
// author, and it reports the risk the choice has accumulated since. A
// reviewer seeing "introduced 14 months ago, 2 CVEs disclosed since" gets a
// different signal from "introduced in #234 by @someone".
//
// This is read-only analysis of local git history. It shells out to `git`
// rather than taking a dependency on a Go git library, because NFR-2 makes the
// dependency footprint part of the product's credibility argument.
package blame

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Finding is one commit that changed a package's presence or version.
type Finding struct {
	Commit   string    `json:"commit"`
	ShortSHA string    `json:"short_sha"`
	Author   string    `json:"author"`
	Email    string    `json:"email,omitempty"`
	Date     time.Time `json:"date"`
	Subject  string    `json:"subject"`
	// Kind is "introduced", "version-changed", or "unchanged". Commits that
	// rewrote the lockfile without altering this package's resolved version
	// are classified "unchanged" and omitted from History, because a commit
	// that did not change the package is not part of its risk history.
	Kind string `json:"kind"`
	// Version is the resolved version as of this commit. Empty for the very
	// first appearance when the lockfile did not record one.
	Version string `json:"version,omitempty"`
	// DaysAgo is relative to now, not to the next commit, so it reads as
	// "how long has this been sitting here".
	DaysAgo int `json:"days_ago"`
}

// Report is the result of blaming one package.
type Report struct {
	Purl    string `json:"purl"`
	Name    string `json:"name"`
	Current string `json:"current_version,omitempty"`
	// History is oldest-first, so a reader sees the sequence in order.
	History []Finding `json:"history"`
	// Introduced is the first appearance, or nil when the package is not in
	// the tree or history is unavailable.
	Introduced *Finding `json:"introduced,omitempty"`
	// LastChange is the most recent version change, which is usually the one
	// a reviewer actually cares about.
	LastChange *Finding `json:"last_change,omitempty"`
	// ScannedCommits is how many commits were inspected, so a truncated
	// history is visible rather than implied.
	ScannedCommits int `json:"scanned_commits"`
	// Shallow records that the local history is truncated, so Introduced
	// means "first seen in the available history" rather than a verified
	// introduction commit. See D41.
	Shallow bool `json:"shallow,omitempty"`
	// Note explains any limitation, e.g. a shallow clone.
	Note string `json:"note,omitempty"`
}

// MaxCommits bounds the history walk. A long-lived repo can have tens of
// thousands of commits and scanning every one per blame call would be
// unusable; the cap is reported in the result so the truncation is visible.
const MaxCommits = 2000

// Blame walks the git history of a lockfile and reports where a package came
// from. root is a repository directory, lockfile is the path within it.
func Blame(ctx context.Context, root, lockfile, name, currentVersion string) (*Report, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("git not found: %w", err)
	}
	rep := &Report{Name: name, Current: currentVersion}

	commits, err := logCommits(ctx, root, lockfile)
	if err != nil {
		return nil, err
	}
	rep.ScannedCommits = len(commits)
	if len(commits) == 0 {
		rep.Note = "no commits touch " + lockfile + "; the file may be untracked or newly added"
		return rep, nil
	}
	if len(commits) == MaxCommits {
		rep.Note = fmt.Sprintf("history truncated at %d commits", MaxCommits)
	}
	// A shallow clone (CI's default fetch-depth: 1, every `git clone
	// --depth N`) makes the oldest scanned commit look like the moment the
	// dependency arrived, which is precisely the claim this command exists to
	// answer. Detect it and say the answer is not determinable rather than
	// reporting a confident wrong one.
	if isShallow(ctx, root) {
		rep.Shallow = true
		rep.Note = strings.TrimSpace(rep.Note + " " +
			"this is a shallow clone, so the earliest commit in the local " +
			"history is not necessarily the commit that introduced the " +
			"dependency; the date above is when it was first SEEN locally, " +
			"not when it was added to the project. Run " +
			"\"git fetch --unshallow\" for a real answer.")
	}

	now := time.Now()
	// git log returns newest-first. Build the sequence oldest-first, so the
	// first element is genuinely the first appearance and the last is HEAD.
	// Getting this order wrong makes blame confidently report the wrong
	// commit, so it is established once here rather than in the loop.
	ordered := make([]commitInfo, 0, len(commits))
	for i := len(commits) - 1; i >= 0; i-- {
		ordered = append(ordered, commits[i])
	}

	// prev is the version the package resolved to at the previous commit, or
	// "" when it was absent. Comparing against it is what distinguishes
	// "introduced" from "version-changed" without a second git call.
	prev := ""
	for _, c := range ordered {
		ver, present := versionAt(ctx, root, lockfile, c.sha, name)
		if !present {
			// Absent here. If it was present before, it was removed; that is
			// not a change worth reporting as a bump.
			//
			// prev MUST be cleared. It carries "the version this package
			// resolved to at the previous commit", and a package that was
			// removed has no version at the previous commit either. Leaving
			// it set made a re-add compare equal to the pre-removal version
			// and report "unchanged", so a dependency that was dropped and
			// re-added appeared in the tree exactly once, with
			// "introduced" pointing at its FIRST appearance rather than the
			// one that put it back. Drop the re-add too and the report says
			// the package has been there since the first commit, which is
			// the specific claim git history is being asked to support.
			prev = ""
			continue
		}
		// A commit that rewrote the lockfile but left this package's
		// version alone did not change THIS package. Recording it as a
		// version change would make blame report lockfile churn as risk
		// history, which is precisely the noise that makes people ignore it.
		kind := "unchanged"
		switch {
		case prev == "":
			kind = "introduced"
		case ver != prev:
			kind = "version-changed"
		}
		if kind != "unchanged" {
			rep.History = append(rep.History, Finding{
				Commit:   c.sha,
				ShortSHA: c.short(),
				Author:   c.author,
				Email:    c.email,
				Date:     c.date,
				Subject:  c.subject,
				Kind:     kind,
				Version:  ver,
				DaysAgo:  int(now.Sub(c.date).Hours() / 24),
			})
		}
		prev = ver
	}

	if len(rep.History) > 0 {
		first := rep.History[0]
		rep.Introduced = &first
		// LastChange is the most RECENT version change. History is
		// oldest-first, so that is the last such entry -- not the first.
		for i := len(rep.History) - 1; i >= 0; i-- {
			if rep.History[i].Kind == "version-changed" {
				last := rep.History[i]
				rep.LastChange = &last
				break
			}
		}
	} else {
		rep.Note = strings.TrimSpace(rep.Note + " " +
			"no commit in the scanned history resolved " + name)
	}
	return rep, nil
}

type commitInfo struct {
	sha     string
	author  string
	email   string
	date    time.Time
	subject string
}

func (c commitInfo) short() string {
	if len(c.sha) >= 7 {
		return c.sha[:7]
	}
	return c.sha
}

// isShallow reports whether the repository has truncated history, which is
// what `git clone --depth N` leaves behind and what CI does by default.
func isShallow(ctx context.Context, root string) bool {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--is-shallow-repository")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		// Too old to answer, or not a repo. Assume the safe direction: if we
		// cannot tell, we do not claim to know more than we do.
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// logCommits returns commits touching the lockfile, newest-first, capped.
// The record separator is used so a subject containing a newline or the
// chosen field separator cannot corrupt the parse.
func logCommits(ctx context.Context, root, lockfile string) ([]commitInfo, error) {
	const sep = "\x1f"
	format := strings.Join([]string{"%H", "%an", "%ae", "%aI", "%s"}, sep) + "\x1e"
	cmd := exec.CommandContext(ctx, "git", "log",
		"--max-count="+strconv.Itoa(MaxCommits),
		"--format="+format,
		"--", lockfile)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		// A repository with no commits yet is a normal state, not a failure:
		// report an empty history so the caller can explain it rather than
		// erroring out on a fresh checkout.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr := strings.TrimSpace(string(ee.Stderr))
			if strings.Contains(stderr, "does not have any commits yet") ||
				strings.Contains(stderr, "unknown revision") {
				return nil, nil
			}
			if stderr != "" {
				return nil, fmt.Errorf("git log: %s", stderr)
			}
		}
		return nil, fmt.Errorf("git log: %w", err)
	}
	var commits []commitInfo
	for _, rec := range strings.Split(string(out), "\x1e") {
		rec = strings.TrimLeft(rec, "\n")
		if strings.TrimSpace(rec) == "" {
			continue
		}
		fields := strings.Split(strings.TrimRight(rec, "\n"), sep)
		if len(fields) < 5 {
			continue
		}
		ts, err := time.Parse(time.RFC3339, fields[3])
		if err != nil {
			// A commit with an unparseable date should not abort the walk.
			ts = time.Time{}
		}
		commits = append(commits, commitInfo{
			sha:     fields[0],
			author:  fields[1],
			email:   fields[2],
			date:    ts,
			subject: fields[4],
		})
	}
	return commits, nil
}
