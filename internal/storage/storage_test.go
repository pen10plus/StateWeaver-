package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/validator"
)

func TestStorage(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_stateweaver.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	// 1. Scopes
	if err := store.SaveScope("localhost:8080"); err != nil {
		t.Fatalf("failed to save scope: %v", err)
	}
	if err := store.SaveScope("127.0.0.1:8081"); err != nil {
		t.Fatalf("failed to save scope 2: %v", err)
	}

	scopes, err := store.GetScopes()
	if err != nil {
		t.Fatalf("failed to get scopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}

	if err := store.DeleteScope("localhost:8080"); err != nil {
		t.Fatalf("failed to delete scope: %v", err)
	}
	scopesAfter, _ := store.GetScopes()
	if len(scopesAfter) != 1 {
		t.Errorf("expected 1 scope after delete, got %d", len(scopesAfter))
	}

	// 2. Imported records
	records := []collector.NormalizedRecord{
		{
			ID:                 "rec-01",
			Method:             "GET",
			OriginalURL:        "http://localhost:8080/api/projects/1001",
			NormalizedTemplate: "/api/projects/{project_id}",
			RequestHeaders:     map[string]string{"Accept": "application/json"},
			ResponseStatus:     200,
			ResponseBody:       `{"id":1001,"name":"Alpha"}`,
			Timestamp:          time.Now().UTC(),
		},
	}

	if err := store.SaveImportedRecords(records); err != nil {
		t.Fatalf("failed to save records: %v", err)
	}

	loadedRecords, err := store.GetImportedRecords()
	if err != nil {
		t.Fatalf("failed to get imported records: %v", err)
	}
	if len(loadedRecords) != 1 || loadedRecords[0].NormalizedTemplate != "/api/projects/{project_id}" {
		t.Errorf("expected 1 record loaded correctly")
	}

	// 3. Test run & findings
	testRunID := "run-001"
	if err := store.CreateTestRun(testRunID); err != nil {
		t.Fatalf("failed to create test run: %v", err)
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
				BaselineStatus:      200,
				ProbeResponseStatus: 200,
				DifferenceDetails:   "Cross-tenant data leakage",
			},
			Reproduction: "curl -i http://localhost:8080/api/projects/1001",
			Remediation:  "Add tenant filter",
			Timestamp:    time.Now().UTC(),
		},
	}

	if err := store.SaveFindings(testRunID, findings); err != nil {
		t.Fatalf("failed to save findings: %v", err)
	}

	if err := store.CompleteTestRun(testRunID, 10, 10, 1); err != nil {
		t.Fatalf("failed to complete test run: %v", err)
	}

	loadedFindings, err := store.GetFindings(testRunID)
	if err != nil {
		t.Fatalf("failed to get findings: %v", err)
	}
	if len(loadedFindings) != 1 {
		t.Fatalf("expected 1 finding loaded, got %d", len(loadedFindings))
	}
	if loadedFindings[0].Severity != "Critical" {
		t.Errorf("expected Critical severity, got %s", loadedFindings[0].Severity)
	}
}
