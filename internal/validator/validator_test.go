package validator

import (
	"testing"

	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/engine"
	"github.com/stateweaver/stateweaver/internal/identity"
	"github.com/stateweaver/stateweaver/internal/policy"
)

func TestValidator(t *testing.T) {
	val := NewValidator([]string{"password", "secret"}, "[REDACTED]")

	charlie := &identity.Identity{
		ID:       "charlie",
		Name:     "Charlie",
		Role:     "member",
		TenantID: "org-b",
	}

	tc := engine.TestCase{
		ID:           "TC-0001",
		Category:     engine.CategoryCrossTenant,
		Endpoint:     "http://localhost:8080/api/projects/1001",
		Method:       "GET",
		Resource:     "project",
		TestIdentity: charlie,
		BaseRecord: collector.NormalizedRecord{
			ResponseStatus: 200,
			ResponseBody:   `{"id": 1001, "name": "Confidential Org-A Project", "secret": "s3cr3t"}`,
			RequestHeaders: map[string]string{
				"Authorization": "Bearer real-alice-token-do-not-leak",
			},
		},
	}

	execRes := engine.ExecutionResult{
		StatusCode: 200,
		StatusText: "200 OK",
		Body:       `{"id": 1001, "name": "Confidential Org-A Project", "secret": "s3cr3t"}`,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	compRes := engine.ComparisonOutcome{
		StatusMatch:       true,
		NormalizedMatch:   true,
		LeakedFields:      []string{"secret"},
		DifferenceSummary: "Payload match; leaked secret",
	}

	// 1. Violated policy case
	evalResViolated := policy.EvaluationResult{
		Violated: true,
		MatchedRule: &policy.Rule{
			Name:        "cross-tenant-isolation",
			Category:    "Cross-Tenant Access Weakness",
			Severity:    "Critical",
			Expected:    policy.DecisionDeny,
			Remediation: "Enforce tenant scoping",
		},
		ExpectedDecision: policy.DecisionDeny,
		ExpectedStatus:   []int{403, 404},
	}

	finding, ok := val.Validate(tc, execRes, compRes, evalResViolated, 1)
	if !ok || finding == nil {
		t.Fatalf("expected finding to be created")
	}

	if finding.Severity != "Critical" {
		t.Errorf("expected Critical severity, got %s", finding.Severity)
	}
	if finding.ValidationStatus != StatusConfirmed {
		t.Errorf("expected Confirmed status, got %s", finding.ValidationStatus)
	}
	if finding.Confidence != ConfidenceHigh {
		t.Errorf("expected High confidence, got %s", finding.Confidence)
	}

	// Check evidence redaction
	if finding.Evidence.ProbeRequestHeaders["Authorization"] != "[REDACTED]" {
		t.Errorf("expected redacted Authorization header in evidence, got %s", finding.Evidence.ProbeRequestHeaders["Authorization"])
	}
	if finding.Evidence.ProbeResponseHeaders["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type to be preserved")
	}

	// 2. Non-violated policy case
	evalResOk := policy.EvaluationResult{
		Violated: false,
	}

	findingNo, okNo := val.Validate(tc, execRes, compRes, evalResOk, 2)
	if okNo || findingNo != nil {
		t.Errorf("expected no finding when policy is not violated")
	}
}
