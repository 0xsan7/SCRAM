// Command scram is the SCRAM CLI: supply chain risk assessment with
// PR-native drift tracking.
package main

import (
	"os"

	"github.com/0xsan7/scram/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// Cobra has already printed the error; exit with a code that
		// distinguishes "policy failed" (1) from "scanner broke" (2).
		os.Exit(cli.ExitCodeFor(err))
	}
}
