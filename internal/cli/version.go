package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	Version   = "1.0.0"
	GitCommit = "devel"
	BuildDate = "2026-03-31"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print StateWeaver version and build metadata",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("StateWeaver v%s (%s) built %s\n", Version, GitCommit, BuildDate)
		fmt.Printf("Runtime: %s/%s (%s)\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
		fmt.Println("Tagline: \"Find the security bugs that scanners can't understand.\"")
	},
}

