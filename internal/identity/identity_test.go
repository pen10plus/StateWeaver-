package identity

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityAuthApplication(t *testing.T) {
	os.Setenv("TEST_ALICE_TOKEN", "secret-bearer-token-12345")
	defer os.Unsetenv("TEST_ALICE_TOKEN")

	id := &Identity{
		ID:       "alice",
		Name:     "Alice",
		Role:     "owner",
		TenantID: "org-a",
		UserID:   "user-101",
		AuthType: AuthTypeBearer,
		Token:    "${TEST_ALICE_TOKEN}",
		Headers: map[string]string{
			"X-Tenant-ID": "org-a",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/projects", nil)
	id.ApplyAuth(req)

	if auth := req.Header.Get("Authorization"); auth != "Bearer secret-bearer-token-12345" {
		t.Errorf("expected Bearer secret-bearer-token-12345, got %q", auth)
	}

	if tenant := req.Header.Get("X-Tenant-ID"); tenant != "org-a" {
		t.Errorf("expected X-Tenant-ID org-a, got %q", tenant)
	}
}

func TestIdentityLoadAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "identities.yaml")

	identities := DefaultSampleIdentities()
	if err := Save(path, identities); err != nil {
		t.Fatalf("failed to save identities: %v", err)
	}

	mgr, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load identities: %v", err)
	}

	if len(mgr.All()) != len(identities) {
		t.Errorf("expected %d identities, got %d", len(identities), len(mgr.All()))
	}

	alice, ok := mgr.Get("alice")
	if !ok || alice.Role != "owner" {
		t.Errorf("expected alice with role owner")
	}

	orgAMembers := mgr.ByTenant("org-a")
	if len(orgAMembers) < 2 {
		t.Errorf("expected at least 2 members for org-a, got %d", len(orgAMembers))
	}
}

func TestRedactedSecret(t *testing.T) {
	short := "abc"
	if r := RedactedSecret(short); r != "[REDACTED]" {
		t.Errorf("expected [REDACTED], got %q", r)
	}

	long := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw"
	if r := RedactedSecret(long); r == long || len(r) > 15 {
		t.Errorf("expected masked string, got %q", r)
	}
}

