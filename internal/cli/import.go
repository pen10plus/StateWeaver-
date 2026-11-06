package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/storage"
)

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import HTTP traffic from a HAR (or OpenAPI) file",
	Long:  "Parses HTTP traffic, extracts requests/responses, normalizes dynamic URL parameters into templates, identifies sensitive fields, and stores records in SQLite.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		ext := strings.ToLower(filepath.Ext(filePath))

		cfg, err := config.Load(cfgFile)
		if err != nil {
			cfg = config.DefaultConfig()
		}

		var records []collector.NormalizedRecord
		if ext == ".har" {
			fmt.Printf("[*] Parsing HAR 1.2 archive: %s\n", filePath)
			parser := collector.NewParser()
			records, err = parser.ParseFile(filePath)
		} else if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			fmt.Printf("[*] Parsing OpenAPI specification: %s\n", filePath)
			openAPI := collector.NewOpenAPICollector()
			records, err = openAPI.ParseFile(filePath)
		} else {
			// Default to HAR parser
			fmt.Printf("[*] Parsing archive: %s\n", filePath)
			parser := collector.NewParser()
			records, err = parser.ParseFile(filePath)
		}

		if err != nil {
			return fmt.Errorf("failed to import %s: %w", filePath, err)
		}

		if len(records) == 0 {
			return fmt.Errorf("no valid HTTP transactions found in %s", filePath)
		}

		// Store in SQLite
		store, err := storage.Open(cfg.Paths.DatabasePath)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer store.Close()

		if err := store.SaveImportedRecords(records); err != nil {
			return fmt.Errorf("failed to store imported records: %w", err)
		}

		// Calculate statistics
		templates := make(map[string]struct{})
		sensitiveTotal := 0
		for _, r := range records {
			templates[r.NormalizedTemplate] = struct{}{}
			sensitiveTotal += len(r.SensitiveFields)
		}

		fmt.Println("[✓] Import successfully completed!")
		fmt.Printf("    • Total HTTP Transactions: %d\n", len(records))
		fmt.Printf("    • Unique Endpoint Templates: %d\n", len(templates))
		fmt.Printf("    • Sensitive Field Occurrences: %d\n", sensitiveTotal)
		fmt.Println("\nNormalized Templates Discovered:")
		for tmpl := range templates {
			fmt.Printf("    - %s\n", tmpl)
		}

		return nil
	},
}

