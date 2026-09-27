package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/0xsan7/scram/internal/drift"
	"github.com/0xsan7/scram/internal/policy"
	"github.com/0xsan7/scram/internal/report"
	"github.com/0xsan7/scram/internal/scan"
	"github.com/spf13/cobra"
)

// --- scram sbom generate ---------------------------------------------------

func newSBOMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "SBOM generation without vulnerability scanning",
	}
	cmd.AddCommand(newSBOMGenerateCmd())
	return cmd
}

func newSBOMGenerateCmd() *cobra.Command {
	var (
		formats string
		outDir  string
		ecosys  []string
	)
	cmd := &cobra.Command{
		Use:   "generate [path]",
		Short: "Generate an SBOM from lockfiles (fast: no network)",
		Long: `Generate an SBOM from your lockfiles.

This is the fast path: it parses lockfiles and writes the SBOM without
querying any vulnerability database, so it works offline and takes about a
second on a mid-size repo.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			list := expandFormats(formats)
			if len(list) == 0 {
				list = []string{"cyclonedx"}
			}
			result, err := scan.Run(cmd.Context(), scan.Options{
				Path:         path,
				Ecosystems:   ecosys,
				SBOMFormats:  list,
				OutDir:       outDir,
				SkipVuln:     true,
				DisableCache: true,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Generated %d SBOM(s) from %d components:\n",
				len(result.SBOMPaths), result.Scan.Summary.TotalComponents)
			for _, p := range result.SBOMPaths {
				fmt.Printf("  %s\n", p)
			}
			if len(result.Scan.Warnings) > 0 && g.verbose {
				fmt.Println("\nwarnings:")
				for _, w := range result.Scan.Warnings {
					fmt.Printf("  - %s\n", w)
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&formats, "format", "cyclonedx", "SBOM format: cyclonedx, spdx, or both (comma-separated)")
	f.StringVar(&outDir, "out", "scram-output", "output directory")
	f.StringSliceVar(&ecosys, "ecosystems", nil, "restrict to these ecosystems")
	return cmd
}

// --- scram diff ------------------------------------------------------------

func newDiffCmd() *cobra.Command {
	var (
		baselinePath string
		against      string
		format       string
		sbom         bool
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff a scan against a stored baseline",
		Long: `Compare a repository's current state against a stored baseline.

This is the command behind SCRAM's core claim: not just "what is broken now"
but "what did this change introduce".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if baselinePath == "" {
				return fmt.Errorf("--baseline is required")
			}
			opts := scan.Options{
				Path:         against,
				BaselinePath: baselinePath,
				SkipVuln:     !sbom,
				OutDir:       "scram-output",
			}
			if sbom {
				opts.SBOMFormats = []string{"cyclonedx"}
			}
			result, err := scan.Run(cmd.Context(), opts)
			if err != nil {
				return err
			}
			if result.Diff == nil {
				return fmt.Errorf("no diff produced; is %s a valid baseline?", baselinePath)
			}
			report.NoColor = !isTTY(os.Stdout) || format == "json"
			if err := report.Write(os.Stdout, result.Scan, result.Diff,
				report.Format(format)); err != nil {
				return err
			}
			if !result.Decision.Pass {
				return ErrPolicyFailed
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&baselinePath, "baseline", drift.DefaultBaselinePath, "baseline file to diff against")
	f.StringVar(&against, "against", ".", "path to the current state to compare")
	f.StringVar(&format, "format", "table", "output format: table, json, or sarif")
	f.BoolVar(&sbom, "vuln", false, "also query vulnerabilities (default: components and versions only)")
	return cmd
}

// --- scram baseline --------------------------------------------------------

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "baseline", Short: "Manage the drift baseline snapshot"}
	cmd.AddCommand(newBaselineUpdateCmd())
	return cmd
}

func newBaselineUpdateCmd() *cobra.Command {
	var (
		outPath string
		format  string
		ecosys  []string
	)
	cmd := &cobra.Command{
		Use:   "update [path]",
		Short: "Write the current scan as the new baseline",
		Long: `Capture the current component, vulnerability, and score state as a baseline.

Commit the resulting .scram/baseline.json to your repo and SCRAM can report
exactly what each subsequent PR changed. The file is plain, sorted JSON so it
diffs cleanly in review.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			opts := scan.Options{
				Path:         path,
				Ecosystems:   ecosys,
				BaselinePath: "", // a baseline update must not diff itself
				OutDir:       "scram-output",
			}
			if format == "sbom" || format == "cyclonedx" || format == "spdx" {
				opts.SBOMFormats = expandFormats(format)
			} else {
				opts.SkipVuln = false
			}
			result, err := scan.Run(cmd.Context(), opts)
			if err != nil {
				return err
			}
			if err := drift.WriteBaseline(outPath, result.Scan); err != nil {
				return fmt.Errorf("writing baseline: %w", err)
			}
			s := result.Scan.Summary
			fmt.Printf("Wrote baseline to %s\n", outPath)
			fmt.Printf("  components   %d\n", s.TotalComponents)
			fmt.Printf("  findings     %d\n", s.VulnTotal)
			fmt.Printf("  repo score   %d/100 (%s)\n", s.RepoScore, s.RepoBucket)
			if len(result.Scan.Warnings) > 0 {
				fmt.Println("  warnings:")
				for _, w := range result.Scan.Warnings {
					fmt.Printf("    - %s\n", w)
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&outPath, "out", drift.DefaultBaselinePath, "where to write the baseline")
	f.StringVar(&format, "sbom", "", "also write SBOMs: cyclonedx, spdx, or both")
	f.StringSliceVar(&ecosys, "ecosystems", nil, "restrict to these ecosystems")
	return cmd
}

// --- scram init ------------------------------------------------------------

func newInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Generate a starter .scram.yml",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			target := path + "/" + policy.ConfigName
			if _, err := os.Stat(target); err == nil && !force {
				return fmt.Errorf("%s already exists; pass --force to overwrite", target)
			}
			if err := os.WriteFile(target, []byte(policy.Starter), 0o644); err != nil {
				return err
			}
			fmt.Printf("Wrote %s\n", target)
			fmt.Println("\nNext:")
			fmt.Println("  scram scan            # run a scan against the defaults")
			fmt.Println("  scram baseline update # capture the current state as a baseline")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config")
	return cmd
}

// --- scram report ----------------------------------------------------------

func newReportCmd() *cobra.Command {
	var (
		from   string
		format string
		out    string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-render a prior scan result in a different format",
		Long: `Re-render a saved scan.

Lets you produce a SARIF file from a JSON scan you ran earlier, without
re-querying any vulnerability database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				return fmt.Errorf("--from is required (a JSON file written by `scram scan --format json`)")
			}
			b, err := os.ReadFile(from)
			if err != nil {
				return err
			}
			var doc report.JSONDocument
			if err := json.Unmarshal(b, &doc); err != nil {
				return fmt.Errorf("parsing %s: %w", from, err)
			}
			var w *os.File = os.Stdout
			if out != "" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			report.NoColor = out != ""
			if err := report.Write(w, doc.Scan, doc.Drift, report.Format(format)); err != nil {
				return err
			}
			if out != "" {
				fmt.Fprintf(os.Stderr, "Wrote %s\n", out)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "path to a JSON scan result")
	f.StringVar(&format, "format", "sarif", "output format: table, json, or sarif")
	f.StringVar(&out, "out", "", "write to a file instead of stdout")
	return cmd
}
