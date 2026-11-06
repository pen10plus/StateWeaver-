package policy

import (
	"path/filepath"
	"testing"
)

func TestPolicyEvaluation(t *testing.T) {
	rules := DefaultBenchmarkPolicies()
	engine := NewEngine(rules)

	// 1. Cross-tenant test: Charlie from org-b tries to read org-a project -> should deny!
	// If observed is 200, it's a violation!
	ctxCrossTenantViolated := Context{
		IdentityID:     "charlie",
		IdentityRole:   "member",
		IdentityTenant: "org-b",
		ResourceName:   "project",
		ResourceTenant: "org-a",
		Action:         "read",
		HTTPMethod:     "GET",
		ObservedStatus: 200,
	}

	res := engine.Evaluate(ctxCrossTenantViolated)
	if !res.Violated {
		t.Fatalf("expected cross-tenant violation when status 200 returned")
	}
	if res.MatchedRule.Name != "cross-tenant-isolation" {
		t.Errorf("expected matched rule 'cross-tenant-isolation', got %s", res.MatchedRule.Name)
	}

	// When API properly denies cross-tenant with 403, there is no violation:
	ctxCrossTenantSecure := Context{
		IdentityID:     "charlie",
		IdentityRole:   "member",
		IdentityTenant: "org-b",
		ResourceName:   "project",
		ResourceTenant: "org-a",
		Action:         "read",
		HTTPMethod:     "GET",
		ObservedStatus: 403,
	}
	resSecure := engine.Evaluate(ctxCrossTenantSecure)
	if resSecure.Violated {
		t.Errorf("expected no violation when properly denied with 403")
	}

	// 2. Viewer trying to delete project
	ctxViewerDelete := Context{
		IdentityID:     "bob",
		IdentityRole:   "viewer",
		IdentityTenant: "org-a",
		ResourceName:   "project",
		ResourceTenant: "org-a",
		Action:         "delete",
		HTTPMethod:     "DELETE",
		ObservedStatus: 204,
	}
	resViewer := engine.Evaluate(ctxViewerDelete)
	if !resViewer.Violated {
		t.Errorf("expected violation when viewer deletes project with 204 status")
	}
	if resViewer.MatchedRule.Name != "viewer-cannot-delete-project" {
		t.Errorf("expected viewer-cannot-delete-project, got %s", resViewer.MatchedRule.Name)
	}

	// 3. Revoked member
	ctxRevoked := Context{
		IdentityID:     "dave",
		IdentityRole:   "member",
		IdentityTenant: "org-a",
		IsRevoked:      true,
		ResourceName:   "project",
		ResourceTenant: "org-a",
		Action:         "read",
		HTTPMethod:     "GET",
		ObservedStatus: 200,
	}
	resRevoked := engine.Evaluate(ctxRevoked)
	if !resRevoked.Violated {
		t.Errorf("expected violation for revoked member when status 200")
	}
}

func TestPolicyLoadAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policies.yaml")

	rules := DefaultBenchmarkPolicies()
	if err := Save(path, rules); err != nil {
		t.Fatalf("failed to save policies: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	if len(loaded.Rules()) != len(rules) {
		t.Errorf("expected %d rules, got %d", len(rules), len(loaded.Rules()))
	}
}

