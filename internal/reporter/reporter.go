package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stateweaver/stateweaver/internal/validator"
)

// ReportMetadata contains scan context, target info, and summary metrics.
type ReportMetadata struct {
	ToolVersion    string                 `json:"tool_version"`
	ProjectName    string                 `json:"project_name"`
	ScanTime       time.Time              `json:"scan_time"`
	TargetScope    []string               `json:"target_scope"`
	TotalRequests  int                    `json:"total_requests"`
	TotalFindings  int                    `json:"total_findings"`
	SeverityCounts map[string]int         `json:"severity_counts"`
	Benchmark      *BenchmarkMetrics      `json:"benchmark,omitempty"`
}

// BenchmarkMetrics records precision/recall when evaluated against verified lab ground-truth.
type BenchmarkMetrics struct {
	TruePositives   int     `json:"true_positives"`
	FalsePositives  int     `json:"false_positives"`
	FalseNegatives  int     `json:"false_negatives"`
	Precision       float64 `json:"precision"`
	Recall          float64 `json:"recall"`
	Reproducibility float64 `json:"reproducibility"`
}

// Report holds the complete dataset for all report formats.
type Report struct {
	Metadata ReportMetadata          `json:"metadata"`
	Findings []*validator.Finding    `json:"findings"`
}

// Reporter handles outputting reports in JSON, Markdown, and HTML.
type Reporter struct {
	report Report
}

// New creates a new Reporter instance.
func New(meta ReportMetadata, findings []*validator.Finding) *Reporter {
	if meta.SeverityCounts == nil {
		meta.SeverityCounts = make(map[string]int)
	}
	for _, f := range findings {
		meta.SeverityCounts[f.Severity]++
	}
	meta.TotalFindings = len(findings)

	return &Reporter{
		report: Report{
			Metadata: meta,
			Findings: findings,
		},
	}
}

// WriteJSON exports report in JSON format.
func (r *Reporter) WriteJSON(path string) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r.report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// WriteMarkdown exports report in GitHub Flavored Markdown format.
func (r *Reporter) WriteMarkdown(path string) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	var sb strings.Builder

	meta := r.report.Metadata
	sb.WriteString("# StateWeaver — Differential Authorization Security Report\n\n")
	sb.WriteString(fmt.Sprintf("**Project:** `%s` | **Version:** `%s` | **Date:** `%s`\n\n",
		meta.ProjectName, meta.ToolVersion, meta.ScanTime.Format(time.RFC3339)))

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", meta.TotalFindings))
	sb.WriteString(fmt.Sprintf("- **Critical:** %d | **High:** %d | **Medium:** %d | **Low:** %d\n",
		meta.SeverityCounts["Critical"], meta.SeverityCounts["High"],
		meta.SeverityCounts["Medium"], meta.SeverityCounts["Low"]))
	sb.WriteString(fmt.Sprintf("- **In-Scope Targets:** `%s`\n\n", strings.Join(meta.TargetScope, ", ")))

	if meta.Benchmark != nil {
		b := meta.Benchmark
		sb.WriteString("### Research Benchmark Verification\n\n")
		sb.WriteString("| Metric | Value |\n")
		sb.WriteString("|---|---|\n")
		sb.WriteString(fmt.Sprintf("| True Positives (TP) | %d |\n", b.TruePositives))
		sb.WriteString(fmt.Sprintf("| False Positives (FP) | %d |\n", b.FalsePositives))
		sb.WriteString(fmt.Sprintf("| False Negatives (FN) | %d |\n", b.FalseNegatives))
		sb.WriteString(fmt.Sprintf("| Precision | %.1f%% |\n", b.Precision*100))
		sb.WriteString(fmt.Sprintf("| Recall | %.1f%% |\n", b.Recall*100))
		sb.WriteString(fmt.Sprintf("| Reproducibility | %.1f%% |\n\n", b.Reproducibility*100))
	}

	sb.WriteString("## Findings Detail\n\n")
	if len(r.report.Findings) == 0 {
		sb.WriteString("No authorization vulnerabilities detected. All tested operations strictly adhered to configured security policies.\n")
	} else {
		for i, f := range r.report.Findings {
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s — %s %s\n\n", i+1, f.Severity, f.Category, f.HTTPMethod, f.Endpoint))
			sb.WriteString(fmt.Sprintf("- **Finding ID:** `%s`\n", f.ID))
			sb.WriteString(fmt.Sprintf("- **Affected Identity:** `%s`\n", f.AffectedIdentity))
			sb.WriteString(fmt.Sprintf("- **Resource:** `%s`\n", f.Resource))
			sb.WriteString(fmt.Sprintf("- **Validation Status:** `%s` (Confidence: `%s`)\n", f.ValidationStatus, f.Confidence))
			sb.WriteString(fmt.Sprintf("- **Expected Behavior:** %s\n", f.ExpectedBehavior))
			sb.WriteString(fmt.Sprintf("- **Observed Behavior:** %s\n\n", f.ObservedBehavior))

			sb.WriteString("#### Evidence & Difference Analysis\n\n")
			sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", f.Evidence.DifferenceDetails))

			sb.WriteString("#### Safe Reproduction Steps\n\n")
			sb.WriteString(fmt.Sprintf("```bash\n%s\n```\n\n", f.Reproduction))

			sb.WriteString("#### Defensive Remediation\n\n")
			sb.WriteString(fmt.Sprintf("> %s\n\n", f.Remediation))
			sb.WriteString("---\n\n")
		}
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// WriteHTML exports an interactive, standalone single-file HTML report.
func (r *Reporter) WriteHTML(path string) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	var sb strings.Builder

	meta := r.report.Metadata
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StateWeaver Security Report</title>
<style>
  :root {
    --bg: #0f172a; --card-bg: #1e293b; --text: #f8fafc; --text-muted: #94a3b8;
    --border: #334155; --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #3b82f6; --success: #10b981; --accent: #6366f1;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }
  h1 { margin: 0; font-size: 1.8rem; color: #fff; }
  .tagline { color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }
  .badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
  .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
  .badge-medium { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
  .badge-low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }
  .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
  .stat-val { font-size: 2rem; font-weight: 700; margin-top: 0.5rem; }
  .finding-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem; }
  .finding-title { font-size: 1.2rem; font-weight: 600; color: #fff; margin: 0; }
  .meta-row { display: flex; flex-wrap: wrap; gap: 1.5rem; color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem; }
  pre { background: #0b1120; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: 0.85rem; color: #e2e8f0; }
  .remediation-box { background: rgba(99, 102, 241, 0.1); border-left: 4px solid var(--accent); padding: 1rem; border-radius: 4px; margin-top: 1rem; }
</style>
</head>
<body>
<div class="container">
<header>
  <div>
    <h1>StateWeaver Security Audit Report</h1>
    <div class="tagline">"Find the security bugs that scanners can't understand."</div>
  </div>
  <div>
    <span class="badge" style="background:#334155;color:#f8fafc;">v`)
	sb.WriteString(html.EscapeString(meta.ToolVersion))
	sb.WriteString(`</span>
  </div>
</header>

<div class="stats-grid">
  <div class="stat-card">
    <div style="color:var(--text-muted);font-size:0.85rem;">TOTAL FINDINGS</div>
    <div class="stat-val">`)
	sb.WriteString(fmt.Sprintf("%d", meta.TotalFindings))
	sb.WriteString(`</div>
  </div>
  <div class="stat-card">
    <div style="color:var(--critical);font-size:0.85rem;">CRITICAL</div>
    <div class="stat-val" style="color:var(--critical);">`)
	sb.WriteString(fmt.Sprintf("%d", meta.SeverityCounts["Critical"]))
	sb.WriteString(`</div>
  </div>
  <div class="stat-card">
    <div style="color:var(--high);font-size:0.85rem;">HIGH</div>
    <div class="stat-val" style="color:var(--high);">`)
	sb.WriteString(fmt.Sprintf("%d", meta.SeverityCounts["High"]))
	sb.WriteString(`</div>
  </div>
  <div class="stat-card">
    <div style="color:var(--medium);font-size:0.85rem;">MEDIUM</div>
    <div class="stat-val" style="color:var(--medium);">`)
	sb.WriteString(fmt.Sprintf("%d", meta.SeverityCounts["Medium"]))
	sb.WriteString(`</div>
  </div>
</div>

<h2>Findings Log</h2>
`)

	if len(r.report.Findings) == 0 {
		sb.WriteString(`<div class="finding-card"><p style="color:var(--success);font-weight:600;">No policy violations detected. API authorization controls functioning as expected.</p></div>`)
	} else {
		for _, f := range r.report.Findings {
			badgeClass := "badge-low"
			switch strings.ToLower(f.Severity) {
			case "critical":
				badgeClass = "badge-critical"
			case "high":
				badgeClass = "badge-high"
			case "medium":
				badgeClass = "badge-medium"
			}

			sb.WriteString(fmt.Sprintf(`
<div class="finding-card">
  <div class="finding-header">
    <div>
      <h3 class="finding-title">%s: %s %s</h3>
      <div style="color:var(--text-muted);font-size:0.85rem;margin-top:0.25rem;">%s | ID: %s</div>
    </div>
    <span class="badge %s">%s</span>
  </div>

  <div class="meta-row">
    <div><strong>Identity:</strong> %s</div>
    <div><strong>Resource:</strong> %s</div>
    <div><strong>Confidence:</strong> %s</div>
    <div><strong>Status:</strong> %s</div>
  </div>

  <div><strong>Expected:</strong> <span style="color:var(--text-muted);">%s</span></div>
  <div style="margin-top:0.25rem;"><strong>Observed:</strong> <span style="color:var(--critical);">%s</span></div>

  <h4 style="margin-top:1rem;margin-bottom:0.5rem;font-size:0.95rem;">Reproduction</h4>
  <pre><code>%s</code></pre>

  <div class="remediation-box">
    <strong>Remediation:</strong> %s
  </div>
</div>
`,
				html.EscapeString(f.Category), html.EscapeString(f.HTTPMethod), html.EscapeString(f.Endpoint),
				html.EscapeString(f.Resource), html.EscapeString(f.ID),
				badgeClass, html.EscapeString(f.Severity),
				html.EscapeString(f.AffectedIdentity), html.EscapeString(f.Resource),
				html.EscapeString(string(f.Confidence)), html.EscapeString(string(f.ValidationStatus)),
				html.EscapeString(f.ExpectedBehavior), html.EscapeString(f.ObservedBehavior),
				html.EscapeString(f.Reproduction),
				html.EscapeString(f.Remediation),
			))
		}
	}

	sb.WriteString(`
</div>
</body>
</html>
`)

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		return os.MkdirAll(dir, 0750)
	}
	return nil
}

