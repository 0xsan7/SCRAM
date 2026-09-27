package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0xsan7/scram/internal/graph"
	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/report"
	"github.com/0xsan7/scram/internal/scan"
	"github.com/spf13/cobra"
)

// newWhyCmd implements `scram why <purl>` — blast radius.
//
// A finding tells you a package is vulnerable. It does not tell you whether
// that package is something you chose or something three layers down that
// arrived with a dependency you added in March. This answers the second
// question, and the answer is what decides whether the fix is urgent.
func newWhyCmd() *cobra.Command {
	var (
		showDependents bool
		jsonOut        bool
	)
	cmd := &cobra.Command{
		Use:   "why <purl>",
		Short: "Show how a package entered your dependency tree",
		Long: `Explain how a package got into your tree.

Prints the dependency path from a direct dependency down to the package you
asked about, so "qs has a CVE" becomes "your-app -> express -> body-parser ->
qs". It also lists what else depends on the package, which is what breaks if
you patch or remove it.

PURLs come from ` + "`scram scan`" + ` output. A bare package name works too if
it is unambiguous.

Parentage is recovered from npm lockfile install paths. ecosystems that do not
record it (PyPI requirements.txt is a flat list, go.sum records checksums)
are reported as having no known path rather than being given an invented one.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := scan.Run(cmd.Context(), scan.Options{
				Path:     ".",
				SkipVuln: false,
			})
			if err != nil {
				return err
			}
			target, err := resolveTarget(result.Scan, args[0])
			if err != nil {
				return err
			}
			g := result.Graph
			if g == nil {
				g = graph.New(result.Scan.Components)
			}
			path := g.PathTo(target)

			if jsonOut {
				return writeWhyJSON(cmd.OutOrStdout(), target, g, path)
			}

			comp := componentByPurl(result, target)
			fmt.Printf("%s\n", target)
			if comp != nil {
				fmt.Printf("  ecosystem  %s\n", comp.Ecosystem)
				if comp.License != "" {
					fmt.Printf("  license    %s\n", comp.License)
				}
				if comp.Score != nil {
					fmt.Printf("  score      %d/100 (%s)\n", comp.Score.Total, comp.Bucket)
				}
			}
			fmt.Println()

			// The three cases must stay distinct. Saying "direct dependency"
			// for a component whose parentage was never recoverable would be a
			// confident false claim: the honest answer is that we do not know.
			ecology := comp.Ecosystem
			known := g.HasEdges()
			switch {
			case comp.Direct:
				fmt.Println("  How it got here: direct dependency, declared by this project.")
			case known && len(path) <= 1:
				fmt.Println("  How it got here: direct dependency (nothing depends on it).")
			case !known:
				fmt.Println("  How it got here: unknown.")
				fmt.Printf("  %s lockfiles do not record which package depends on which, so no path\n", ecology)
				fmt.Println("  can be derived without guessing. Use the package manager to trace it:")
				switch ecology {
				case model.EcoPyPI:
					fmt.Println("    pipdeptree -r .    # or: pip show <package>")
				case model.EcoGo:
					fmt.Println("    go mod why -m <module>")
				default:
					fmt.Println("    npm ls <package>")
				}
			default:
				fmt.Println("  How it got here:")
				printPath(path)
			}

			deps := g.Dependents(target)
			if showDependents || len(deps) > 0 {
				fmt.Println()
				if len(deps) == 0 {
					fmt.Println("  Nothing else in the tree depends on it.")
				} else {
					fmt.Printf("  Also depends on it (%d), transitively:\n", len(deps))
					for _, d := range deps {
						label := "clean"
						if c := componentByPurl(result, d); c != nil && c.Score != nil {
							label = report.BucketLabel(c.Bucket)
						}
						fmt.Printf("      %-8s %s\n", report.Paint(report.BucketColor(label), label), d)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showDependents, "dependents", false,
		"always list dependents, even when there are none")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}

// printPath renders root -> target with a visible elbow per hop, so depth is
// readable at a glance rather than counted.
func printPath(path []string) {
	for i, p := range path {
		prefix := "    "
		for j := 0; j < i; j++ {
			prefix += "    "
		}
		if i == 0 {
			fmt.Printf("%s%s\n", prefix, p)
			continue
		}
		elbow := "    "
		for j := 0; j < i-1; j++ {
			elbow += "    "
		}
		fmt.Printf("%s|__ %s\n", elbow, p)
	}
}

// resolveTarget turns user input into a canonical PURL from the scan.
//
// Accepts a full PURL, a bare name, or a name@version. A bare name that
// matches several installed versions is an error rather than a guess, since
// picking one silently would answer a question nobody asked.
func resolveTarget(s model.Scan, input string) (string, error) {
	needle := strings.TrimSpace(input)
	if needle == "" {
		return "", fmt.Errorf("a package name or PURL is required")
	}
	// Exact PURL: the common case, since `scram scan` prints them.
	for _, c := range s.Components {
		if c.Purl == needle {
			return c.Purl, nil
		}
	}
	var matches []string
	for _, c := range s.Components {
		if c.Name == needle || c.Purl == needle {
			matches = append(matches, c.Purl)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no component matching %q in this tree%s", needle, nameHint(needle, s))
	case 1:
		return matches[0], nil
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m)
		}
		sort.Strings(names)
		return "", fmt.Errorf("%q is ambiguous: %s is installed at several versions. Use the full PURL.",
			needle, strings.Join(names, ", "))
	}
}

// nameHint offers near-matches for a name that is not in the tree at all.
func nameHint(input string, s model.Scan) string {
	names := make([]string, 0, len(s.Components))
	for _, c := range s.Components {
		names = append(names, c.Name)
	}
	return hint(input, names)
}

// whyDocument is the `--json` shape.
type whyDocument struct {
	SchemaVersion string   `json:"schema_version"`
	Target        string   `json:"target"`
	Path          []string `json:"path"`
	PathKnown     bool     `json:"path_known"`
	Dependents    []string `json:"dependents"`
	Direct        bool     `json:"direct"`
}

func writeWhyJSON(out interface{ Write([]byte) (int, error) }, target string, g *graph.Graph, path []string) error {
	doc := whyDocument{
		SchemaVersion: model.SchemaVersion,
		Target:        target,
		Path:          path,
		PathKnown:     len(path) > 1,
		Dependents:    g.Dependents(target),
		Direct:        len(g.Parents[target]) == 0,
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// componentByPurl returns the scanned component behind a PURL, or nil.
func componentByPurl(r *scan.Result, purl string) *model.Component {
	for i := range r.Scan.Components {
		if r.Scan.Components[i].Purl == purl {
			return &r.Scan.Components[i]
		}
	}
	return nil
}

// hint lists unambiguous prefixes so a typo produces a useful error instead of
// "not found".
func hint(input string, names []string) string {
	input = strings.ToLower(input)
	var close []string
	for _, n := range names {
		if strings.HasPrefix(strings.ToLower(n), input) {
			close = append(close, n)
			if len(close) == 4 {
				break
			}
		}
	}
	if len(close) == 0 {
		return ""
	}
	return "\nDid you mean: " + strings.Join(close, ", ") + "?"
}
