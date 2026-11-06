package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stateweaver/stateweaver/internal/validator"
)

func TestReporterJSONMarkdownHTML(t *testing.T) {
	tmpDir := t.TempDir()

	meta := ReportMetadata{
		ToolVersion:   "1.0.0",
		ProjectName:   "Acme API Security",
		ScanTime:      time.Now().UTC(),
		TargetScope:   []string{"localhost:8080"},
		TotalRequests: 15,
		Benchmark: &BenchmarkMetrics{
			TruePositives:   5,
			FalsePositives:  0,
			FalseNegatives:  0,
			Precision:       1.0,
			Recall:          1.0,
			Reproducibility: 1.0,
		},
	}

	findings := []*validator.Finding{
		{
			ID:               "SW-FINDING-0001",
			Category:         "Cross-Tenant Access Weakness",
			Severity:         "Critical",
			Endpoint:         "http://localhost:8080/api/projects/1001",
			HTTPMethod:       "GET",
			AffectedIdentity: "Charlie (Org-B)",
			Resource:         "project",
			ExpectedBehavior: "Access DENIED",
			ObservedBehavior: "Access ALLOWED (200 OK)",
			Confidence:       validator.ConfidenceHigh,
			ValidationStatus: validator.StatusConfirmed,
			Evidence: validator.Evidence{
				DifferenceDetails: "Cross-tenant project data leak",
			},
			Reproduction: "curl -i http://localhost:8080/api/projects/1001",
			Remediation:  "Enforce tenant filtering",
			Timestamp:    time.Now().UTC(),
		},
	}

	rep := New(meta, findings)

	// 1. JSON
	jsonPath := filepath.Join(tmpDir, "report.json")
	if err := rep.WriteJSON(jsonPath); err != nil {
		t.Fatalf("failed to write JSON report: %v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil || !strings.Contains(string(jsonData), "SW-FINDING-0001") {
		t.Errorf("expected JSON report with finding ID")
	}

	// 2. Markdown
	mdPath := filepath.Join(tmpDir, "report.md")
	if err := rep.WriteMarkdown(mdPath); err != nil {
		t.Fatalf("failed to write Markdown report: %v", err)
	}
	mdData, err := os.ReadFile(mdPath)
	if err != nil || !strings.Contains(string(mdData), "Research Benchmark Verification") {
		t.Errorf("expected Markdown report with benchmark")
	}

	// 3. HTML
	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := rep.WriteHTML(htmlPath); err != nil {
		t.Fatalf("failed to write HTML report: %v", err)
	}
	htmlData, err := os.ReadFile(htmlPath)
	if err != nil || !strings.Contains(string(htmlData), "StateWeaver Security Audit Report") {
		t.Errorf("expected HTML report with title")
	}
}

