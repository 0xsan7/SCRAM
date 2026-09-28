// Package cli wires the SCRAM command-line interface. Commands here are thin:
// they parse flags, call internal/scan, and render. All the real logic lives
// in the internal packages so the GitHub Action can share it.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/policy"
	"github.com/spf13/cobra"
)

// ErrPolicyFailed is returned when a scan completes but policy says the build
// should fail. It is distinct from a scan error: CI wants a red build either
// way, but a scan that didn't run at all should be reported differently than
// a scan that ran and found something.
var ErrPolicyFailed = errors.New("scram policy check failed")

// ExitCodeFor maps an error to a process exit code. Policy failure gets 1;
// an operational failure gets 2, so a CI job can tell "found something" from
// "the scanner broke". Exported so cmd/scram can call it.
func ExitCodeFor(err error) int {
	if errors.Is(err, ErrPolicyFailed) {
		return 1
	}
	return 2
}

// Version is the build version, overridable at link time:
//
//	go build -ldflags "-X .../cli.Version=1.2.3"
var Version = "0.1.0-dev"

// globalFlags are shared by every subcommand.
type globalFlags struct {
	configPath string
	failOn     string
	noCache    bool
	offline    bool
	verbose    bool
}

var g globalFlags

// Execute runs the root command. Returns nil on success.
func Execute() error {
	return rootCmd().Execute()
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "scram",
		Short: "Supply Chain Risk Assessment & Monitoring",
		Long: `SCRAM pulls the fail-safe on supply chain risk before it ships.

SCRAM discovers your dependency tree, generates a standards-compliant SBOM,
matches every component against OSV, scores the risk with a transparent
algorithm, and — the part most tools skip — tells you what a given PR actually
changed versus the baseline.

By default, CI gating applies only to NEW findings. Adopt it on a repo with
200 pre-existing warnings and day-one PRs still go green.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: false,
		// Bare `scram` should scan the current directory, matching the
		// "one command to try it locally" adoption goal (G8).
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return g.validate()
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&g.configPath, "config", "", "path to .scram.yml (default: ./.scram.yml if present)")
	pf.StringVar(&g.failOn, "fail-on", "", "override the policy severity threshold (clean|low|medium|high|critical)")
	pf.BoolVar(&g.noCache, "no-cache", false, "bypass the vulnerability cache and re-query every source")
	pf.BoolVar(&g.offline, "offline", false, "use only cached vulnerability data; fail loudly rather than skip checks")
	pf.BoolVar(&g.verbose, "verbose", false, "print extra detail about scan progress and warnings")

	root.AddCommand(
		newScanCmd(),
		newSBOMCmd(),
		newDiffCmd(),
		newBaselineCmd(),
		newInitCmd(),
		newReportCmd(),
		newWhyCmd(),
		newBlameCmd(),
		newBadgeCmd(),
	)
	return root
}

func (f *globalFlags) validate() error {
	if f.failOn != "" {
		if _, ok := severityRank[f.failOn]; !ok {
			return fmt.Errorf("--fail-on: %q is not a severity (use clean, low, medium, high, or critical)", f.failOn)
		}
	}
	return nil
}

// severityRank mirrors model.SeverityRank for flag validation without
// pulling the model package into every command file.
var severityRank = map[string]int{
	"clean": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

// loadConfig reads the policy file, applying the --fail-on override.
func loadConfig(root string) (*policy.Config, error) {
	cfg, err := policy.Load(root)
	if err != nil {
		return nil, err
	}
	if g.failOn != "" {
		cfg.FailOn = g.failOn
	}
	if g.offline {
		cfg.Offline = true
	}
	return cfg, nil
}

// isTTY reports whether stdout is a terminal, so colors are only emitted
// when a human is looking.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// warningResolveFailed is the prefix scan puts on a warning about a lockfile
// it could not resolve. The CLI matches on it to distinguish a real parse
// failure from unrelated advisories, so it is a contract, not a string.
const warningResolveFailed = "resolving"

// warnIfNothingResolved is the last line of defence against a silent zero.
//
// The resolve package refuses to return an empty component list for a
// lockfile that declares dependencies, and scan propagates that as an error.
// This covers the remaining gap: a lockfile that was DETECTED but could not
// be parsed at all. scan collects that as a warning and continues, which is
// the right behaviour for one bad file among several, but it means a command
// can succeed having read nothing.
//
// "SBOM generated, 0 components" is indistinguishable from "this repo has no
// dependencies" to anyone reading the output, which is precisely the D01/D22/
// D23 failure. So when a scan resolved nothing AND reported a resolution
// failure, this returns an error instead of letting the command exit 0.
//
// A scan that resolved nothing with no warnings is left alone: that is a
// genuinely dependency-free project.
func warnIfNothingResolved(scan model.Scan, path string) error {
	if scan.Summary.TotalComponents > 0 {
		return nil
	}
	// Match the resolver's own warning prefix rather than scanning for the
	// word "failed". An earlier version used strings.Contains(w, "failed"),
	// which also matched "EPSS enrichment failed, exploitability scored as
	// 0" -- an unrelated advisory that must never fail a scan. Warnings are
	// the one place where a loose substring match turns a useful signal into
	// noise, so the contract is an explicit prefix the resolver sets.
	var parseFailures []string
	for _, w := range scan.Warnings {
		if strings.HasPrefix(w, warningResolveFailed) {
			parseFailures = append(parseFailures, w)
		}
	}
	if len(parseFailures) == 0 {
		return nil // genuinely nothing to scan
	}
	return fmt.Errorf("%s: no components resolved and %d lockfile(s) could not be parsed "+
		"(treating this as a clean SBOM would be a false negative):\n  - %s",
		path, len(parseFailures), strings.Join(parseFailures, "\n  - "))
}
