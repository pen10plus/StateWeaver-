package validator

import (
	"fmt"
	"strings"
	"time"

	"github.com/stateweaver/stateweaver/internal/engine"
	"github.com/stateweaver/stateweaver/internal/normalizer"
	"github.com/stateweaver/stateweaver/internal/policy"
)

// ValidationStatus represents the triage state of a finding.
type ValidationStatus string

const (
	StatusConfirmed   ValidationStatus = "Confirmed"
	StatusNeedsReview ValidationStatus = "Needs Review"
	StatusHypothesis  ValidationStatus = "Hypothesis"
	StatusRejected    ValidationStatus = "Rejected"
)

// ConfidenceLevel assesses evidence certainty.
type ConfidenceLevel string

const (
	ConfidenceHigh   ConfidenceLevel = "High"
	ConfidenceMedium ConfidenceLevel = "Medium"
	ConfidenceLow    ConfidenceLevel = "Low"
)

// Finding describes a validated authorization vulnerability.
type Finding struct {
	ID               string           `json:"id"`
	Category         string           `json:"category"`
	Severity         string           `json:"severity"`
	Endpoint         string           `json:"endpoint"`
	HTTPMethod       string           `json:"http_method"`
	AffectedIdentity string           `json:"affected_identity"`
	Resource         string           `json:"resource"`
	ExpectedBehavior string           `json:"expected_behavior"`
	ObservedBehavior string           `json:"observed_behavior"`
	Evidence         Evidence         `json:"evidence"`
	Reproduction     string           `json:"reproduction"`
	Confidence       ConfidenceLevel  `json:"confidence"`
	ValidationStatus ValidationStatus `json:"validation_status"`
	Remediation      string           `json:"remediation"`
	Timestamp        time.Time        `json:"timestamp"`
}

// Evidence packages request and response details.
type Evidence struct {
	ProbeRequestHeaders  map[string]string `json:"probe_request_headers"`
	ProbeRequestBody     string            `json:"probe_request_body"`
	ProbeResponseStatus  int               `json:"probe_response_status"`
	ProbeResponseHeaders map[string]string `json:"probe_response_headers"`
	ProbeResponseBody    string            `json:"probe_response_body"`
	BaselineStatus       int               `json:"baseline_status"`
	BaselineResponseBody string            `json:"baseline_response_body"`
	DifferenceDetails    string            `json:"difference_details"`
	LeakedFields         []string          `json:"leaked_fields,omitempty"`
}

// Validator evaluates candidate findings.
type Validator struct {
	sensitiveKeys []string
	maskValue     string
}

// NewValidator creates a Validator instance.
func NewValidator(sensitiveKeys []string, maskValue string) *Validator {
	if maskValue == "" {
		maskValue = "[REDACTED]"
	}
	return &Validator{
		sensitiveKeys: sensitiveKeys,
		maskValue:     maskValue,
	}
}

// Validate analyzes a test probe execution against policies and differential comparison to create a Finding if warranted.
func (v *Validator) Validate(
	tc engine.TestCase,
	execRes engine.ExecutionResult,
	compRes engine.ComparisonOutcome,
	evalRes policy.EvaluationResult,
	findingIdx int,
) (*Finding, bool) {
	// A finding requires a policy violation or unauthorized status code match on a restricted resource
	if !evalRes.Violated {
		// No policy was violated. Do not report arbitrary differences as vulnerabilities!
		return nil, false
	}

	status := StatusConfirmed
	confidence := ConfidenceHigh

	// Assess confidence:
	// If the server returned 200/204 on an operation that should be denied:
	isSuccessCode := execRes.StatusCode >= 200 && execRes.StatusCode < 300
	if !isSuccessCode {
		// Server returned error status code (e.g. 500 or 400), not a clean authorization bypass
		status = StatusNeedsReview
		confidence = ConfidenceLow
	} else if len(execRes.Body) == 0 && tc.Method == "GET" {
		// GET returned 200 with empty body - might be empty list or stub
		status = StatusNeedsReview
		confidence = ConfidenceMedium
	}

	severity := "High"
	if evalRes.MatchedRule != nil && evalRes.MatchedRule.Severity != "" {
		severity = evalRes.MatchedRule.Severity
	} else if tc.Category == engine.CategoryCrossTenant {
		severity = "Critical"
	}

	category := string(tc.Category)
	if evalRes.MatchedRule != nil && evalRes.MatchedRule.Category != "" {
		category = evalRes.MatchedRule.Category
	}

	remediation := "Implement strict authorization checks verifying identity role and tenant ownership before processing request."
	if evalRes.MatchedRule != nil && evalRes.MatchedRule.Remediation != "" {
		remediation = evalRes.MatchedRule.Remediation
	}

	// Redact evidence before storing / reporting
	redactedProbeReqHeaders := v.redactHeaders(tc.BaseRecord.RequestHeaders)
	redactedProbeRespHeaders := v.redactHeaders(execRes.Headers)
	redactedProbeBody := string(normalizer.RedactSensitiveJSON([]byte(execRes.Body), v.sensitiveKeys, v.maskValue))
	redactedBaseBody := string(normalizer.RedactSensitiveJSON([]byte(tc.BaseRecord.ResponseBody), v.sensitiveKeys, v.maskValue))

	// Generate safe reproduction curl command (with redacted token placeholder)
	reproCurl := v.generateReproCurl(tc)

	idName := "Unknown"
	if tc.TestIdentity != nil {
		idName = fmt.Sprintf("%s (Role: %s, Tenant: %s)", tc.TestIdentity.Name, tc.TestIdentity.Role, tc.TestIdentity.TenantID)
	}

	finding := &Finding{
		ID:               fmt.Sprintf("SW-FINDING-%04d", findingIdx),
		Category:         category,
		Severity:         severity,
		Endpoint:         tc.Endpoint,
		HTTPMethod:       tc.Method,
		AffectedIdentity: idName,
		Resource:         tc.Resource,
		ExpectedBehavior: fmt.Sprintf("Access %s (Expected HTTP %v)", strings.ToUpper(string(evalRes.ExpectedDecision)), evalRes.ExpectedStatus),
		ObservedBehavior: fmt.Sprintf("Access allowed with HTTP %d %s", execRes.StatusCode, execRes.StatusText),
		Evidence: Evidence{
			ProbeRequestHeaders:  redactedProbeReqHeaders,
			ProbeRequestBody:     tc.BaseRecord.RequestBody,
			ProbeResponseStatus:  execRes.StatusCode,
			ProbeResponseHeaders: redactedProbeRespHeaders,
			ProbeResponseBody:    redactedProbeBody,
			BaselineStatus:       tc.BaseRecord.ResponseStatus,
			BaselineResponseBody: redactedBaseBody,
			DifferenceDetails:    compRes.DifferenceSummary,
			LeakedFields:         compRes.LeakedFields,
		},
		Reproduction:     reproCurl,
		Confidence:       confidence,
		ValidationStatus: status,
		Remediation:      remediation,
		Timestamp:        time.Now().UTC(),
	}

	return finding, true
}

func (v *Validator) redactHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string)
	for k, val := range headers {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "cookie" || lower == "x-api-key" || strings.Contains(lower, "token") {
			out[k] = v.maskValue
		} else {
			out[k] = val
		}
	}
	return out
}

func (v *Validator) generateReproCurl(tc engine.TestCase) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("curl -i -X %s %q", tc.Method, tc.Endpoint))
	sb.WriteString(" \\\n  -H \"Authorization: Bearer <TEST_IDENTITY_TOKEN>\"")
	if tc.TestIdentity != nil && tc.TestIdentity.TenantID != "" {
		sb.WriteString(fmt.Sprintf(" \\\n  -H \"X-Tenant-ID: %s\"", tc.TestIdentity.TenantID))
	}
	if tc.BaseRecord.RequestBody != "" {
		sb.WriteString(fmt.Sprintf(" \\\n  -H \"Content-Type: application/json\" \\\n  -d '%s'", tc.BaseRecord.RequestBody))
	}
	return sb.String()
}

