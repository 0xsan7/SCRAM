package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/0xsan7/scram/internal/blame"
	"github.com/0xsan7/scram/internal/detect"
	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/scan"
	"github.com/spf13/cobra"
)

// newBlameCmd implements `scram blame <purl>` — git blame, but for risk.
//
// The question this answers is not "who wrote this line" but "what did this
// dependency cost us". A CVE disclosed against a package that has sat in a
// lockfile for two years is a different problem from one disclosed against a
// package added last week, and telling those two stories apart is the whole
// point of pointing at history.
func newBlameCmd() *cobra.Command {
	var (
		limit  int
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "blame <purl>",
		Short: "Trace a dependency to the commit that introduced it",
		Long: `Trace a package through git history.

Reports the commit and author that introduced a dependency, later version
changes, and how long each has been sitting in the tree. This is git blame
for risk: the useful signal is not who typed the line, but that a package
arrived 22 months ago at 4.17.11 and nobody has touched it since.

Version history is recovered by reading the lockfile as it existed at each
commit, so a package that was bumped and reverted reports the bumps.

Commits that rewrote the lockfile without changing this package's resolved
version are not listed; they are lockfile churn, not risk history.

This reads local git history only. In a shallow clone the history available
is the history scanned, and the reported commit count makes that visible.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projects, err := detect.Detect(".")
			if err != nil {
				return err
			}
			if len(projects) == 0 {
				return fmt.Errorf("no supported lockfiles found in the current directory")
			}

			name, version := splitPurl(args[0])
			if name == "" {
				return fmt.Errorf("could not read a package name from %q", args[0])
			}

			// Try each project until one resolves the name, so a bare package
			// name works without the caller knowing which lockfile it lives in.
			var lastErr error
			for _, p := range projects {
				rep, err := blame.Blame(cmd.Context(), ".", p.File, name, version)
				if err != nil {
					lastErr = err
					continue
				}
				if len(rep.History) == 0 && rep.Introduced == nil {
					lastErr = fmt.Errorf("no history for %q in %s", name, p.File)
					continue
				}
				rep.Purl = args[0]
				// A real current version beats whatever the caller typed.
				if c := currentComponent(cmd, name); c != nil {
					rep.Current = c.Version
					rep.Purl = c.Purl
				}
				if asJSON {
					return writeBlameJSON(cmd.OutOrStdout(), rep)
				}
				renderBlame(cmd, rep)
				return nil
			}
			if lastErr != nil {
				return lastErr
			}
			return fmt.Errorf("no history found for %q", args[0])
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0,
		"show at most this many history entries (0 = all)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}

func renderBlame(cmd *cobra.Command, rep *blame.Report) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "\n%s\n", rep.Purl)
	if rep.Current != "" {
		fmt.Fprintf(out, "  current version   %s\n", rep.Current)
	}
	if rep.Introduced != nil {
		i := rep.Introduced
		fmt.Fprintf(out, "  introduced        %s ago, %s, by %s\n",
			humanAge(i.Date), i.ShortSHA, i.Author)
		fmt.Fprintf(out, "                     at %s\n", i.Version)
	}
	if rep.LastChange != nil && rep.LastChange.Commit != "" {
		l := rep.LastChange
		fmt.Fprintf(out, "  last changed      %s ago, %s, by %s\n",
			humanAge(l.Date), l.ShortSHA, l.Author)
		fmt.Fprintf(out, "                     to %s — %s\n", l.Version, l.Subject)
	}
	fmt.Fprintf(out, "  commits scanned   %d\n", rep.ScannedCommits)
	if rep.Note != "" {
		fmt.Fprintf(out, "  note              %s\n", rep.Note)
	}
	if len(rep.History) > 0 {
		fmt.Fprintf(out, "\n  Version history:\n")
		for _, h := range rep.History {
			marker := " "
			if h.Kind == "introduced" {
				marker = "*"
			}
			fmt.Fprintf(out, "   %s %-10s %-12s %5s ago  %s\n",
				marker, h.Version, h.ShortSHA, humanAge(h.Date), h.Author)
		}
	}
	fmt.Fprintln(out)
}

// humanAge renders a duration the way a person would say it, because "576
// days" is technically correct and practically unreadable next to a risk
// score.
func humanAge(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 60*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d < 730*24*time.Hour:
		return fmt.Sprintf("%dmo", int(d.Hours()/24/30))
	default:
		return fmt.Sprintf("%.1fy", d.Hours()/24/365)
	}
}

// splitPurl pulls a package name and version out of user input that may be a
// full PURL, a bare name, or name@version.
func splitPurl(input string) (name, version string) {
	s := strings.TrimSpace(input)
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	// Split on the LAST @, but a leading @ is a scope marker, not a version.
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// currentComponent resolves a package against the live tree so the reported
// "current version" is the one actually installed, not the one the caller
// typed. Failure is non-fatal: blame still works off history alone.
func currentComponent(cmd *cobra.Command, name string) *model.Component {
	ctx, cancel := context.WithTimeout(cmd.Context(), 120*time.Second)
	defer cancel()
	res, err := scan.Run(ctx, scan.Options{Path: ".", SkipVuln: true})
	if err != nil {
		return nil
	}
	for i := range res.Scan.Components {
		if res.Scan.Components[i].Name == name {
			return &res.Scan.Components[i]
		}
	}
	return nil
}

// writeBlameJSON emits the machine-readable shape.
func writeBlameJSON(out io.Writer, rep *blame.Report) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
