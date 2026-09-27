package cli

import (
	"os"

	"github.com/0xsan7/scram/internal/badge"
	"github.com/spf13/cobra"
)

// newBadgeCmd serves SCRAM's own supply chain score as a shields.io endpoint
// badge.
//
// This exists so the README can carry a live score rather than a number typed
// in once and never checked. It reads the JSON that `scram scan --format json`
// already produces, so the badge and the scan can never disagree — there is no
// second scan and no place for a stale value to hide.
//
// In CI the dogfood job runs a scan, saves the JSON, and this turns it into an
// endpoint response. Locally it is useful for checking what the badge would say.
func newBadgeCmd() *cobra.Command {
	var inPath string
	cmd := &cobra.Command{
		Use:   "badge",
		Short: "Render a scan as a shields.io endpoint badge",
		Long: `Render a scan result as a shields.io endpoint badge.

Reads a scan document (the output of ` + "`scram scan --format json`" + `, or a saved
copy from a CI artifact) and writes the JSON a shields.io endpoint serves, so
the README badge shows a measured score rather than a remembered one.

Example:
  scram scan --format json > scan.json
  scram badge --in scan.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var f *os.File
			if inPath == "" || inPath == "-" {
				f = os.Stdin
			} else {
				var err error
				f, err = os.Open(inPath)
				if err != nil {
					return err
				}
				defer f.Close()
			}
			return badge.Serve(cmd.OutOrStdout(), f)
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "-",
		"scan JSON to read, or - for stdin")
	return cmd
}
