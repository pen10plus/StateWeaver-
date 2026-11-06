package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/scope"
	"github.com/stateweaver/stateweaver/internal/storage"
)

var scopeCmd = &cobra.Command{
	Use:   "scope",
	Short: "Manage target boundaries and execution scope",
}

var scopeAddCmd = &cobra.Command{
	Use:   "add <target>",
	Short: "Add a target host or URL pattern to the allowed scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := strings.TrimSpace(args[0])
		if target == "" {
			return fmt.Errorf("target cannot be empty")
		}

		// Validate scope syntax
		tempScope := scope.New(nil, nil, false, true)
		if err := tempScope.AddHost(target); err != nil {
			return fmt.Errorf("invalid target specification: %w", err)
		}

		cfg, err := config.Load(cfgFile)
		if err != nil {
			cfg = config.DefaultConfig()
		}

		dbPath := cfg.Paths.DatabasePath
		store, err := storage.Open(dbPath)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer store.Close()

		if err := store.SaveScope(target); err != nil {
			return fmt.Errorf("failed to save scope to database: %w", err)
		}

		fmt.Printf("[+] In-scope target added: %s\n", target)
		return nil
	},
}

var scopeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current in-scope targets and execution boundaries",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			cfg = config.DefaultConfig()
		}

		store, err := storage.Open(cfg.Paths.DatabasePath)
		var storedScopes []string
		if err == nil {
			storedScopes, _ = store.GetScopes()
			store.Close()
		}

		fmt.Println("==================================================")
		fmt.Println("             STATEWEAVER SCOPE SUMMARY            ")
		fmt.Println("==================================================")
		fmt.Printf("Localhost Only:     %t\n", cfg.Scope.LocalhostOnly)
		fmt.Printf("Read-Only Mode:     %t\n", cfg.Execution.ReadOnly)
		fmt.Printf("Rate Limit:         %d RPS\n", cfg.Execution.RateLimitRPS)
		fmt.Printf("Request Budget:     %d requests\n", cfg.Execution.RequestBudget)
		fmt.Printf("Per-Request Timeout: %ds\n", cfg.Execution.TimeoutSeconds)

		fmt.Println("\nConfigured Target Scope (database):")
		if len(storedScopes) == 0 {
			for _, h := range cfg.Scope.AllowedHosts {
				fmt.Printf("  • %s\n", h)
			}
		} else {
			for _, s := range storedScopes {
				fmt.Printf("  • %s\n", s)
			}
		}

		if len(cfg.Scope.AllowedPorts) > 0 {
			fmt.Printf("\nAllowed Ports: %v\n", cfg.Scope.AllowedPorts)
		}
		fmt.Println("==================================================")
		return nil
	},
}

func init() {
	scopeCmd.AddCommand(scopeAddCmd)
	scopeCmd.AddCommand(scopeShowCmd)
}

