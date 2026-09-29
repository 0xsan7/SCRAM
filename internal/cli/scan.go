package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xsan7/scram/internal/drift"
	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/policy"
	"github.com/0xsan7/scram/internal/report"
	"github.com/0xsan7/scram/internal/scan"
	"github.com/0xsan7/scram/internal/trend"
	"github.com/spf13/cobra"
)

// scanFlags holds the flags specific to `scram scan`.
type scanFlags struct {
	format      string
	sbomFormats string
	outDir      string
	baseline    string
	ecosystems  []string
	explain     string
	epss        bool
	skipVuln    bool
	// scorecardRepo names the project whose OpenSSF Scorecard feeds the
	// maintenance term. Empty means the term is not computed.
	scorecardRepo string
	noScorecard   bool
	// noGate skips the pass/fail decision, for exploring a repo.
	noGate bool
	// trendPath is the local score history file. Empty disables the sparkline
	// and stops it being written, so `--no-trend` fully opts out.
	trendPath string
	noTrend   bool
}

var sf scanFlags

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Full scan: SBOM + vulnerabilities + risk score",
		Long: `Scan a repository for supply chain risk.

Discovers the dependency tree from lockfiles, generates SBOMs, matches
components against OSV, scores risk, and diffs against a baseline to report
what changed. Exits non-zero when policy fails.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScan,
	}
	f := cmd.Flags()
	f.StringVar(&sf.trendPath, "trend-file", trend.DefaultPath,
		"score history file backing the trend sparkline")
	f.BoolVar(&sf.noTrend, "no-trend", false,
		"do not read or write score history")
	f.StringVar(&sf.format, "format", "table", "output format: table, json, or sarif")
	f.StringVar(&sf.sbomFormats, "sbom", "", "write SBOMs: cyclonedx, spdx, or both (comma-separated)")
	f.StringVar(&sf.outDir, "out", "scram-output", "output directory for SBOM and SARIF files")
	f.StringVar(&sf.baseline, "baseline", drift.DefaultBaselinePath, "path to the baseline file to diff against")
	f.StringSliceVar(&sf.ecosystems, "ecosystems", nil, "restrict to these ecosystems (default: auto-detect)")
	f.StringVar(&sf.explain, "explain", "", "print the score breakdown for one component PURL, then exit")
	f.BoolVar(&sf.epss, "epss", false, "enable EPSS exploitability scoring (more upstream requests)")
	f.BoolVar(&sf.skipVuln, "sbom-only", false, "generate SBOMs and skip vulnerability scanning (fast path)")
	f.BoolVar(&sf.noGate, "no-gate", false, "always exit 0; report findings without gating")
	f.StringVar(&sf.scorecardRepo, "scorecard", "", "repo whose OpenSSF Scorecard feeds the maintenance term (host/owner/name or owner/name)")
	f.BoolVar(&sf.noScorecard, "no-scorecard", false, "do not fetch an OpenSSF Scorecard even if --scorecard is given")

	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// A bare `scram` with no args shouldn't silently scan a directory the
	// user didn't mean.
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cannot scan %s: %w", path, err)
	}

	opts := scan.Options{
		Path:         path,
		Ecosystems:   sf.ecosystems,
		SBOMFormats:  expandFormats(sf.sbomFormats),
		OutDir:       sf.outDir,
		BaselinePath: "",
		DisableCache: g.noCache,
		Offline:      g.offline,
		SkipVuln:     sf.skipVuln,
		EPSS:         sf.epss,
		// The Scorecard defaults to the git origin when there is one, so
		// the common case needs no flag at all. A repository with no
		// origin simply gets no maintenance term, which is correct:
		// there is no project to look up.
		ScorecardRepo: sf.scorecardRepo,
		NoScorecard:   sf.noScorecard,
	}
	if opts.ScorecardRepo == "" && !sf.noScorecard {
		opts.ScorecardRepo = gitOriginProject(path)
	}

	// Only diff against a baseline if one actually exists. A missing baseline
	// is the normal first-run state, not an error.
	if sf.baseline != "" {
		if _, err := os.Stat(sf.baseline); err == nil {
			opts.BaselinePath = sf.baseline
		} else if g.verbose {
			fmt.Fprintf(os.Stderr, "no baseline at %s, reporting current state only\n", sf.baseline)
		}
	}

	result, err := scan.Run(cmd.Context(), opts)
	if err != nil {
		return err
	}

	// --explain short-circuits to the score breakdown (FR-303). Accept either
	// a full PURL or a bare component name; a bare name is only honored when
	// it matches exactly one component, so an ambiguous name is an error
	// rather than a silent pick.
	if sf.explain != "" {
		var matches []model.Component
		for _, c := range result.Scan.Components {
			if c.Purl == sf.explain {
				// An exact PURL match is unambiguous; stop here.
				matches = []model.Component{c}
				break
			}
			if c.Name == sf.explain {
				matches = append(matches, c)
			}
		}
		switch len(matches) {
		case 0:
			return fmt.Errorf("no component matching %q; run `scram scan --format json` to list components", sf.explain)
		case 1:
			return report.Explain(os.Stdout, matches[0], result.Maintenance)
		default:
			names := make([]string, 0, len(matches))
			for _, m := range matches {
				names = append(names, m.Purl)
			}
			return fmt.Errorf("%q matches %d components; use a full PURL:\n  %s",
				sf.explain, len(matches), strings.Join(names, "\n  "))
		}
	}

	format := report.Format(strings.ToLower(sf.format))
	report.NoColor = !isTTY(os.Stdout)

	// Record this scan in the local score history and render the trend, but
	// only for the human-readable report. JSON and SARIF are machine formats
	// with fixed schemas (FR-208), and appending a decorative glyph to a
	// stdout that gets piped to jq would be indefensible.
	var tr *report.Trend
	trendPath := sf.trendPath
	if sf.noTrend {
		trendPath = ""
	}
	if format != report.FormatJSON && format != report.FormatSARIF && trendPath != "" {
		var trendErr error
		tr, trendErr = recordTrend(trendPath, result.Scan)
		warnTrendFailure(trendErr, g.verbose)
	}

	switch format {
	case report.FormatSARIF:
		// SARIF is a machine format for the GitHub Security tab; the policy
		// text goes to stderr so stdout stays a valid, uploadable document.
		if err := report.Write(os.Stdout, result.Scan, result.Diff, format); err != nil {
			return err
		}
		printPolicySummary(os.Stderr, path, result)
	case report.FormatJSON:
		// Same rule for JSON: stdout must parse. Any human-facing summary
		// goes to stderr, so `scram scan --format json | jq` always works.
		if err := report.Write(os.Stdout, result.Scan, result.Diff, format); err != nil {
			return err
		}
		printPolicySummary(os.Stderr, path, result)
	default:
		if err := report.WriteWithTrend(os.Stdout, result.Scan, result.Diff, format, tr); err != nil {
			return err
		}
		fmt.Println()
		printPolicySummary(os.Stdout, path, result)
	}

	if g.verbose {
		fmt.Fprintf(os.Stderr, "\nscan completed in %s\n", result.Duration.Round(time.Millisecond))
	}

	if !result.Decision.Pass && !sf.noGate {
		return ErrPolicyFailed
	}
	return nil
}

// printPolicySummary writes the pass/fail decision and artifact paths. The
// caller chooses the stream: stdout for the human table, stderr for the
// machine formats, whose stdout must stay parseable.
func printPolicySummary(w io.Writer, path string, result *scan.Result) {
	cfg, err := loadConfig(path)
	if err != nil {
		cfg = policy.Default()
	}
	fmt.Fprintln(w)
	fmt.Fprint(w, policy.Explain(cfg, result.Decision))
	if len(result.SBOMPaths) > 0 {
		fmt.Fprintln(w)
		for _, p := range result.SBOMPaths {
			fmt.Fprintf(w, "  SBOM: %s\n", p)
		}
	}
}

// splitList parses a comma-separated flag value, dropping empties.
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// expandFormats is splitList plus the "both" shorthand, which the README and
// CI use. Without it, `--format both` silently produced zero SBOMs: "both" is
// not a recognized format, so the writer skipped it and reported success.
func expandFormats(s string) []string {
	list := splitList(s)
	var out []string
	for _, f := range list {
		if f == "both" || f == "all" {
			out = append(out, "cyclonedx", "spdx")
			continue
		}
		out = append(out, f)
	}
	return out
}

// gitOriginProject reads the repository's origin remote and returns it in a
// form the Scorecard API accepts, or "" if there isn't one.
//
// This reads a file; it never runs `git` and never touches the network. A
// subprocess here would let an ordinary scan hang on a credential prompt,
// and a scan is not the place to introduce that risk. The blame package does
// shell out to git, but it does so as an explicit user-requested feature
// with a context and a timeout; this runs on every scan.
//
// A directory that is not a git repository yields "" and the maintenance term
// is simply not computed.
func gitOriginProject(path string) string {
	raw, err := readGitConfig(path)
	if err != nil {
		return ""
	}
	for _, url := range originRemotes(string(raw)) {
		return url
	}
	return ""
}

// originRemotes extracts remote URLs from a git config file.
//
// It is a deliberately small reader for the one shape SCRAM needs --
// [remote "name"] sections with a url key -- rather than a general INI
// parser. A comment (# or ;) ends a line, keys and values are trimmed, and a
// line that is not a section header or a key is ignored. Anything more
// elaborate would be a git-config implementation with none of git's edge
// cases, which is worse than a small correct one.
func originRemotes(config string) []string {
	var (
		remotes   []string
		inRemote  bool
		remoteURL []string
	)
	flush := func() {
		if inRemote && len(remoteURL) > 0 {
			remotes = append(remotes, remoteURL[0])
		}
		remoteURL = nil
	}
	for _, line := range strings.Split(config, "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			// [remote "origin"] -- a bare [remote] is not a named remote.
			inRemote = strings.HasPrefix(line, `[remote "`) && strings.HasSuffix(line, `"]`)
			continue
		}
		if !inRemote {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == "url" {
			if v := strings.TrimSpace(value); v != "" {
				remoteURL = append(remoteURL, v)
			}
		}
	}
	flush()
	return remotes
}

// readGitConfig reads the config for a repository rooted at path.
//
// Three shapes exist, and only the first is obvious:
//
//	ordinary clone   .git/            is a directory; read .git/config
//	linked worktree  .git             is a FILE: "gitdir: .../worktrees/<n>"
//	submodule        .git             is a FILE: "gitdir: .../modules/<n>"
//
// In the last two, the named directory holds a `commondir` file whose
// contents are the path to the shared repository -- and that shared
// repository is where `[remote "origin"]` actually lives. Reading
// ".git/config" there returns nothing, and the maintenance term then
// silently drops to zero, which looks like "the tool decided this project
// is unmaintained". That is the failure this handles.
//
// `commondir` is the documented mechanism for exactly this walk, so it is
// used rather than reconstructing the `worktrees/<name>` layout by hand.
func readGitConfig(path string) ([]byte, error) {
	gitPath := filepath.Join(path, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return os.ReadFile(filepath.Join(gitPath, "config"))
	}

	raw, err := os.ReadFile(gitPath)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(raw))
	gitDir, ok := strings.CutPrefix(line, "gitdir:")
	if !ok {
		return nil, fmt.Errorf("unrecognised .git file: %q", line)
	}
	gitDir = strings.TrimSpace(gitDir)
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(path, gitDir)
	}

	// The worktree's own directory has no config. Its `commondir` points at
	// the shared repository that does.
	commonRaw, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return nil, fmt.Errorf("no commondir for %s: %w", gitDir, err)
	}
	common := strings.TrimSpace(string(commonRaw))
	if !filepath.IsAbs(common) {
		common = filepath.Join(gitDir, common)
	}
	return os.ReadFile(filepath.Join(common, "config"))
}
