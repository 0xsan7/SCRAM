package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/0xsan7/scram/internal/viewer"
	"github.com/spf13/cobra"
)

func newViewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "view [report.json]",
		Short: "Open the local browser report viewer, with an optional saved JSON report",
		Long:  "Serve the bundled report viewer on this computer only. No Node, Python, account or upload is required. Without a report, explore synthetic examples. The browser validates the report schema before displaying it.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []byte
			if len(args) == 1 {
				var err error
				data, err = viewer.ReadReport(args[0])
				if err != nil {
					return err
				}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return viewer.Serve(ctx, data, cmd.OutOrStdout())
		},
	}
}
