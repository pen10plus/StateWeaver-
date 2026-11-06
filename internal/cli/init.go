package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/identity"
	"github.com/stateweaver/stateweaver/internal/policy"
	"github.com/stateweaver/stateweaver/internal/storage"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new StateWeaver project workspace",
	Long:  "Creates default configuration (stateweaver.yaml), benchmark policies (policies.yaml), test identities (identities.yaml), and initializes the SQLite database.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("[*] Initializing StateWeaver project workspace...")

		// 1. Create config file if not exists
		cfgPath := "stateweaver.yaml"
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			cfg := config.DefaultConfig()
			if err := cfg.Save(cfgPath); err != nil {
				return fmt.Errorf("failed to create %s: %w", cfgPath, err)
			}
			fmt.Printf("    [+] Created configuration: %s\n", cfgPath)
		} else {
			fmt.Printf("    [i] Existing configuration found: %s\n", cfgPath)
		}

		// 2. Create policies.yaml if not exists
		policyPath := "policies.yaml"
		if _, err := os.Stat(policyPath); os.IsNotExist(err) {
			policies := policy.DefaultBenchmarkPolicies()
			if err := policy.Save(policyPath, policies); err != nil {
				return fmt.Errorf("failed to create %s: %w", policyPath, err)
			}
			fmt.Printf("    [+] Created benchmark policies: %s (%d rules)\n", policyPath, len(policies))
		} else {
			fmt.Printf("    [i] Existing policies found: %s\n", policyPath)
		}

		// 3. Create identities.yaml if not exists
		identitiesPath := "identities.yaml"
		if _, err := os.Stat(identitiesPath); os.IsNotExist(err) {
			identities := identity.DefaultSampleIdentities()
			if err := identity.Save(identitiesPath, identities); err != nil {
				return fmt.Errorf("failed to create %s: %w", identitiesPath, err)
			}
			fmt.Printf("    [+] Created sample identities: %s (%d profiles)\n", identitiesPath, len(identities))
		} else {
			fmt.Printf("    [i] Existing identities found: %s\n", identitiesPath)
		}

		// 4. Create directories
		_ = os.MkdirAll("reports", 0750)
		_ = os.MkdirAll("graphs", 0750)
		_ = os.MkdirAll(".stateweaver", 0750)

		// 5. Initialize SQLite database
		dbPath := ".stateweaver/stateweaver.db"
		store, err := storage.Open(dbPath)
		if err != nil {
			return fmt.Errorf("failed to initialize sqlite storage at %s: %w", dbPath, err)
		}
		defer store.Close()

		// Populate default localhost targets
		_ = store.SaveScope("localhost:8080")
		_ = store.SaveScope("127.0.0.1:8080")
		_ = store.SaveScope("localhost:8081")
		_ = store.SaveScope("127.0.0.1:8081")

		fmt.Printf("    [+] Initialized SQLite database: %s\n", dbPath)
		fmt.Println("[✓] StateWeaver workspace successfully initialized!")
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Import traffic:  stateweaver import <traffic.har>")
		fmt.Println("  2. Analyze flows:   stateweaver analyze")
		fmt.Println("  3. Run test suite:  stateweaver test")
		return nil
	},
}

