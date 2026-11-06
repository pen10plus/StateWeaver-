package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
)

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "stateweaver",
	Short: "StateWeaver — Stateful API Security Research & Differential Authorization Engine",
	Long: `StateWeaver: "Find the security bugs that scanners can't understand."

An open-source, stateful API security research engine designed to discover
Broken Object Level Authorization (BOLA), cross-tenant access-control weaknesses,
role-based authorization flaws, and revoked-access inconsistencies through
deterministic differential testing.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "stateweaver.yaml", "config file (default is stateweaver.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging output")

	RootCmd.AddCommand(initCmd)
	RootCmd.AddCommand(scopeCmd)
	RootCmd.AddCommand(importCmd)
	RootCmd.AddCommand(analyzeCmd)
	RootCmd.AddCommand(testCmd)
	RootCmd.AddCommand(reportCmd)
	RootCmd.AddCommand(labCmd)
	RootCmd.AddCommand(versionCmd)
}
