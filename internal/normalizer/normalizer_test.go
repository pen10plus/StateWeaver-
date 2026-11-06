package normalizer

import (
	"encoding/json"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	norm := NewPathTemplateNormalizer()

	tests := []struct {
		url          string
		expectedTmpl string
		expectedParam string
		expectedVal   string
	}{
		{
			url:          "http://localhost:8080/api/projects/1001",
			expectedTmpl: "/api/projects/{project_id}",
			expectedParam: "project_id",
			expectedVal:   "1001",
		},
		{
			url:          "http://localhost:8080/api/projects/550e8400-e29b-41d4-a716-446655440000/members/42",
			expectedTmpl: "/api/projects/{project_id}/members/{member_id}",
			expectedParam: "member_id",
			expectedVal:   "42",
		},
		{
			url:          "http://localhost:8080/api/organizations/org-test/categories/99",
			expectedTmpl: "/api/organizations/org-test/categories/{category_id}",
			expectedParam: "category_id",
			expectedVal:   "99",
		},
	}

	for _, tt := range tests {
		tmpl, params := norm.NormalizeURL(tt.url)
		if tmpl != tt.expectedTmpl {
			t.Errorf("expected template %q, got %q", tt.expectedTmpl, tmpl)
		}
		if val, ok := params[tt.expectedParam]; !ok || val != tt.expectedVal {
			t.Errorf("expected param %q = %q, got %q", tt.expectedParam, tt.expectedVal, val)
		}
	}
}

func TestNormalizeJSONBody(t *testing.T) {
	input := []byte(`{
		"id": 1001,
		"name": "Secret Project",
		"created_at": "2026-03-31T14:30:00Z",
		"request_id": "req-998877",
		"items": [
			{"uuid": "550e8400-e29b-41d4-a716-446655440000", "title": "Task 1"}
		]
	}`)

	normalized := NormalizeJSONBody(input)
	var data map[string]interface{}
	if err := json.Unmarshal(normalized, &data); err != nil {
		t.Fatalf("failed to unmarshal normalized json: %v", err)
	}

	if data["created_at"] != "<DYNAMIC_VALUE>" {
		t.Errorf("expected created_at to be normalized to <DYNAMIC_VALUE>, got %v", data["created_at"])
	}
	if data["request_id"] != "<DYNAMIC_VALUE>" {
		t.Errorf("expected request_id to be normalized to <DYNAMIC_VALUE>, got %v", data["request_id"])
	}
	if data["name"] != "Secret Project" {
		t.Errorf("expected invariant field name to be preserved, got %v", data["name"])
	}
}

func TestRedactSensitiveJSON(t *testing.T) {
	input := []byte(`{
		"user": "alice",
		"password": "super-secret-password",
		"api_key": "xyz123456",
		"note": "Bearer secret-access-token"
	}`)

	redacted := RedactSensitiveJSON(input, []string{"password", "api_key"}, "[REDACTED]")
	var data map[string]interface{}
	if err := json.Unmarshal(redacted, &data); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if data["password"] != "[REDACTED]" {
		t.Errorf("expected password to be redacted, got %v", data["password"])
	}
	if data["api_key"] != "[REDACTED]" {
		t.Errorf("expected api_key to be redacted, got %v", data["api_key"])
	}
	if data["user"] != "alice" {
		t.Errorf("expected non-sensitive field to be preserved")
	}
	if data["note"] != "Bearer [REDACTED]" {
		t.Errorf("expected bearer token inside string to be redacted, got %v", data["note"])
	}
}

