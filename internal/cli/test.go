package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/engine"
	"github.com/stateweaver/stateweaver/internal/identity"
	"github.com/stateweaver/stateweaver/internal/policy"
	"github.com/stateweaver/stateweaver/internal/reporter"
	"github.com/stateweaver/stateweaver/internal/scope"
	"github.com/stateweaver/stateweaver/internal/storage"
	"github.com/stateweaver/stateweaver/internal/validator"
)

var (
	targetOverride string
	readOnlyFlag   bool
	allowExternal  bool
	budgetFlag     int
	rpsFlag        int
	outputDirFlag  string
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Execute identity-aware differential authorization test suite",
	Long:  "Executes safe differential security probes across multiple identities, comparing actual authorization enforcement against configured policies to detect BOLA, cross-tenant leaks, and privilege escalations.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			cfg = config.DefaultConfig()
		}

		// Apply flag overrides
		if cmd.Flags().Changed("read-only") {
			cfg.Execution.ReadOnly = readOnlyFlag
		}
		if cmd.Flags().Changed("budget") && budgetFlag > 0 {
			cfg.Execution.RequestBudget = budgetFlag
		}
		if cmd.Flags().Changed("rps") && rpsFlag > 0 {
			cfg.Execution.RateLimitRPS = rpsFlag
		}
		reportsDir := cfg.Paths.ReportsDir
		if outputDirFlag != "" {
			reportsDir = outputDirFlag
		}

		// 1. Open storage
		store, err := storage.Open(cfg.Paths.DatabasePath)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer store.Close()

		// 2. Load stored records
		records, err := store.GetImportedRecords()
		if err != nil {
			return fmt.Errorf("failed to load imported records: %w", err)
		}
		if len(records) == 0 {
			return fmt.Errorf("no imported traffic found. Run 'stateweaver import <traffic.har>' first")
		}

		// 3. Load policies
		policyPath := cfg.PoliciesFile
		policyEng, err := policy.Load(policyPath)
		if err != nil {
			// Fallback to default benchmark policies
			policyEng = policy.NewEngine(policy.DefaultBenchmarkPolicies())
		}

		// 4. Load identities
		idMgr, err := identity.Load(cfg.Identities)
		if err != nil {
			// Fallback to default sample identities
			idMgr = identity.NewManager(identity.DefaultSampleIdentities())
		}

		// 5. Build Scope validator
		storedScopes, _ := store.GetScopes()
		allowedHosts := cfg.Scope.AllowedHosts
		allowedHosts = append(allowedHosts, storedScopes...)

		if targetOverride != "" {
			parsed, err := url.Parse(targetOverride)
			if err == nil && parsed.Host != "" {
				allowedHosts = append(allowedHosts, parsed.Host)
			}
		}

		targetScope := scope.New(allowedHosts, cfg.Scope.AllowedPorts, cfg.Scope.LocalhostOnly, allowExternal)

		// 6. Handle target base URL override if provided
		if targetOverride != "" {
			records = rebaseRecords(records, targetOverride)
		}

		// 7. Generate test cases
		generator := engine.NewGenerator(idMgr.All())
		testCases := generator.GenerateTestCases(records)

		fmt.Println("==================================================")
		fmt.Println("       STATEWEAVER DIFFERENTIAL TEST SUITE        ")
		fmt.Println("==================================================")
		fmt.Printf("Baseline Endpoints:   %d\n", len(records))
		fmt.Printf("Identities Involved:  %d\n", len(idMgr.All()))
		fmt.Printf("Test Hypotheses:      %d\n", len(testCases))
		fmt.Printf("Rate Limit:           %d req/sec\n", cfg.Execution.RateLimitRPS)
		fmt.Printf("Max Budget:           %d requests\n", cfg.Execution.RequestBudget)
		fmt.Printf("Read-Only Mode:       %t\n", cfg.Execution.ReadOnly)
		fmt.Println("--------------------------------------------------")

		// 8. Initialize Executor, Comparator, Validator
		executor := engine.NewSafeExecutor(targetScope, &cfg.Execution)
		comparator := engine.NewComparator(cfg.Redaction.SensitiveKeys)
		valEngine := validator.NewValidator(cfg.Redaction.SensitiveKeys, cfg.Redaction.MaskValue)

		testRunID := "run-" + uuid.New().String()[:8]
		_ = store.CreateTestRun(testRunID)

		var findings []*validator.Finding
		findingIdx := 1
		executedCount := 0

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for _, tc := range testCases {
			execRes := executor.Execute(ctx, tc)
			if execRes.Error != nil {
				if execRes.Error == engine.ErrBudgetExceeded {
					fmt.Printf("[!] Request budget of %d reached. Halting test execution.\n", cfg.Execution.RequestBudget)
					break
				}
				if execRes.Error == engine.ErrReadOnlyMode {
					continue // Silently skip destructive methods in read-only mode
				}
				if verbose {
					fmt.Printf("[!] Probe %s failed: %v\n", tc.ID, execRes.Error)
				}
				if cfg.Execution.StopOnError {
					fmt.Printf("[!] Error executing probe %s: %v. StopOnError active.\n", tc.ID, execRes.Error)
					break
				}
				continue
			}

			executedCount++

			// Compare baseline and probe
			compOutcome := comparator.Compare(tc.BaseRecord, execRes)

			// Evaluate policy
			resTenant := ""
			resOwner := ""
			if tc.OwnerIdentity != nil {
				if len(tc.BaseRecord.PathParams) > 0 {
					resTenant = tc.OwnerIdentity.TenantID
					resOwner = tc.OwnerIdentity.UserID
				} else {
					if strings.Contains(execRes.Body, tc.OwnerIdentity.TenantID) {
						resTenant = tc.OwnerIdentity.TenantID
					} else {
						resTenant = tc.TestIdentity.TenantID
					}
				}
			}

			evalCtx := policy.Context{
				IdentityID:     tc.TestIdentity.ID,
				IdentityRole:   tc.TestIdentity.Role,
				IdentityTenant: tc.TestIdentity.TenantID,
				IdentityUser:   tc.TestIdentity.UserID,
				IsRevoked:      tc.TestIdentity.IsRevoked,
				ResourceName:   tc.Resource,
				ResourceTenant: resTenant,
				ResourceOwner:  resOwner,
				Action:         tc.Method,
				HTTPMethod:     tc.Method,
				ObservedStatus: execRes.StatusCode,
			}

			evalRes := policyEng.Evaluate(evalCtx)

			// Validate finding
			if finding, ok := valEngine.Validate(tc, execRes, compOutcome, evalRes, findingIdx); ok {
				findings = append(findings, finding)
				findingIdx++
				fmt.Printf("  [!] [%s] %s on %s by %s -> HTTP %d (Expected %v)\n",
					finding.Severity, finding.Category, tc.Endpoint, tc.TestIdentity.Name, execRes.StatusCode, evalRes.ExpectedStatus)
			}
		}

		// 9. Store findings and complete test run
		_ = store.SaveFindings(testRunID, findings)
		_ = store.CompleteTestRun(testRunID, len(testCases), executedCount, len(findings))

		// 10. Generate reports
		meta := reporter.ReportMetadata{
			ToolVersion:   "1.0.0",
			ProjectName:   cfg.ProjectName,
			ScanTime:      time.Now().UTC(),
			TargetScope:   allowedHosts,
			TotalRequests: executedCount,
		}

		rep := reporter.New(meta, findings)
		_ = os.MkdirAll(reportsDir, 0750)
		jsonReport := filepath.Join(reportsDir, "report.json")
		mdReport := filepath.Join(reportsDir, "report.md")
		htmlReport := filepath.Join(reportsDir, "report.html")

		_ = rep.WriteJSON(jsonReport)
		_ = rep.WriteMarkdown(mdReport)
		_ = rep.WriteHTML(htmlReport)

		fmt.Println("==================================================")
		fmt.Println("                 EXECUTION SUMMARY                ")
		fmt.Println("==================================================")
		fmt.Printf("Probes Dispatched:    %d / %d\n", executedCount, len(testCases))
		fmt.Printf("Findings Discovered:  %d\n", len(findings))
		fmt.Println("--------------------------------------------------")
		fmt.Printf("Reports Generated:\n")
		fmt.Printf("  • JSON:     %s\n", jsonReport)
		fmt.Printf("  • Markdown: %s\n", mdReport)
		fmt.Printf("  • HTML:     %s\n", htmlReport)
		fmt.Println("==================================================")

		return nil
	},
}

func rebaseRecords(records []collector.NormalizedRecord, targetBase string) []collector.NormalizedRecord {
	targetBase = strings.TrimRight(targetBase, "/")
	parsedBase, err := url.Parse(targetBase)
	if err != nil {
		return records
	}

	out := make([]collector.NormalizedRecord, len(records))
	for i, r := range records {
		out[i] = r
		parsedURL, err := url.Parse(r.OriginalURL)
		if err == nil {
			parsedURL.Scheme = parsedBase.Scheme
			parsedURL.Host = parsedBase.Host
			out[i].OriginalURL = parsedURL.String()
		}
	}
	return out
}

func init() {
	testCmd.Flags().StringVar(&targetOverride, "target", "", "Override base target URL (e.g. http://localhost:8080)")
	testCmd.Flags().BoolVar(&readOnlyFlag, "read-only", false, "Restrict tests to non-destructive HTTP methods")
	testCmd.Flags().BoolVar(&allowExternal, "allow-external", false, "Explicitly permit scanning external non-localhost targets")
	testCmd.Flags().IntVar(&budgetFlag, "budget", 0, "Maximum total request budget limit")
	testCmd.Flags().IntVar(&rpsFlag, "rps", 0, "Rate limit in requests per second")
	testCmd.Flags().StringVar(&outputDirFlag, "output-dir", "reports", "Directory for output reports")
}
