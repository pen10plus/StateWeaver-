package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/reporter"
	"github.com/stateweaver/stateweaver/internal/storage"
)

var (
	reportFormat string
	reportOutDir string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Export formatted security reports from stored findings",
	Long:  "Generates vulnerability reports in JSON, HTML, and Markdown format with full reproduction details, evidence, and defensive remediations.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			cfg = config.DefaultConfig()
		}

		outDir := cfg.Paths.ReportsDir
		if reportOutDir != "" {
			outDir = reportOutDir
		}
		_ = os.MkdirAll(outDir, 0750)

		store, err := storage.Open(cfg.Paths.DatabasePath)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer store.Close()

		findings, err := store.GetFindings("")
		if err != nil {
			return fmt.Errorf("failed to load findings: %w", err)
		}

		storedScopes, _ := store.GetScopes()
		meta := reporter.ReportMetadata{
			ToolVersion:   "1.0.0",
			ProjectName:   cfg.ProjectName,
			ScanTime:      time.Now().UTC(),
			TargetScope:   storedScopes,
			TotalRequests: 0,
		}

		rep := reporter.New(meta, findings)
		format := strings.ToLower(reportFormat)

		var generated []string

		if format == "json" || format == "all" {
			p := filepath.Join(outDir, "report.json")
			if err := rep.WriteJSON(p); err != nil {
				return err
			}
			generated = append(generated, p)
		}

		if format == "md" || format == "markdown" || format == "all" {
			p := filepath.Join(outDir, "report.md")
			if err := rep.WriteMarkdown(p); err != nil {
				return err
			}
			generated = append(generated, p)
		}

		if format == "html" || format == "all" {
			p := filepath.Join(outDir, "report.html")
			if err := rep.WriteHTML(p); err != nil {
				return err
			}
			generated = append(generated, p)
		}

		fmt.Printf("[✓] Generated %d reports in %s:\n", len(generated), outDir)
		for _, g := range generated {
			fmt.Printf("    • %s\n", g)
		}
		fmt.Printf("    Total Findings: %d\n", len(findings))

		return nil
	},
}

func init() {
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "all", "Report format: json, md, html, or all")
	reportCmd.Flags().StringVarP(&reportOutDir, "output-dir", "o", "reports", "Output directory for generated reports")
}

