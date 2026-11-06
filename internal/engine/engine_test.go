package engine

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/identity"
	"github.com/stateweaver/stateweaver/internal/scope"
)

type mockRoundTripper struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}

func TestGenerator(t *testing.T) {
	identities := identity.DefaultSampleIdentities()
	gen := NewGenerator([]*identity.Identity{
		&identities[0], // alice (owner org-a)
		&identities[1], // bob (viewer org-a)
		&identities[2], // charlie (member org-b)
		&identities[3], // dave (revoked org-a)
	})

	records := []collector.NormalizedRecord{
		{
			ID:                 "rec-1",
			Method:             "GET",
			OriginalURL:        "http://localhost:8080/api/projects/1001",
			NormalizedTemplate: "/api/projects/{project_id}",
			ExtractedEntities:  map[string]string{"project": "1001"},
		},
		{
			ID:                 "rec-2",
			Method:             "DELETE",
			OriginalURL:        "http://localhost:8080/api/projects/1001",
			NormalizedTemplate: "/api/projects/{project_id}",
			ExtractedEntities:  map[string]string{"project": "1001"},
		},
	}

	testCases := gen.GenerateTestCases(records)
	if len(testCases) == 0 {
		t.Fatalf("expected test cases to be generated")
	}

	hasCrossTenant := false
	hasRBAC := false
	hasRevoked := false

	for _, tc := range testCases {
		if tc.Category == CategoryCrossTenant {
			hasCrossTenant = true
		}
		if tc.Category == CategoryRBAC {
			hasRBAC = true
		}
		if tc.Category == CategoryRevokedAccess {
			hasRevoked = true
		}
	}

	if !hasCrossTenant {
		t.Errorf("expected cross-tenant test case to be generated")
	}
	if !hasRBAC {
		t.Errorf("expected RBAC test case to be generated for DELETE by viewer")
	}
	if !hasRevoked {
		t.Errorf("expected revoked access test case to be generated")
	}
}

func TestComparator(t *testing.T) {
	comp := NewComparator([]string{"secret_key", "password"})

	base := collector.NormalizedRecord{
		ResponseStatus: 200,
		ResponseBody:   `{"id": 1001, "name": "Project A", "timestamp": "2026-03-31T10:00:00Z"}`,
	}

	// Probe with different timestamp but same data
	probeSameData := ExecutionResult{
		StatusCode: 200,
		Body:       `{"id": 1001, "name": "Project A", "timestamp": "2026-03-31T10:05:00Z"}`,
	}

	outcome := comp.Compare(base, probeSameData)
	if !outcome.StatusMatch {
		t.Errorf("expected status match")
	}
	if !outcome.NormalizedMatch {
		t.Errorf("expected normalized match despite dynamic timestamp difference")
	}

	// Probe with leaked secret
	probeLeaked := ExecutionResult{
		StatusCode: 200,
		Body:       `{"id": 1001, "secret_key": "topsecret123"}`,
	}
	outcomeLeaked := comp.Compare(base, probeLeaked)
	if len(outcomeLeaked.LeakedFields) == 0 {
		t.Errorf("expected leaked field detection for secret_key")
	}
}

func TestSafeExecutorBudgetAndReadOnly(t *testing.T) {
	sc := scope.New([]string{"127.0.0.1", "localhost"}, nil, true, false)
	cfg := &config.Execution{
		RateLimitRPS:     50,
		RequestBudget:    2, // small budget
		TimeoutSeconds:   2,
		MaxResponseBytes: 1024,
		ReadOnly:         true,
	}

	exec := NewSafeExecutor(sc, cfg)
	exec.SetTransport(&mockRoundTripper{
		fn: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
				Header:     make(http.Header),
			}, nil
		},
	})

	targetURL := "http://localhost:8080/api/projects"

	// Test 1: Mutation blocked in ReadOnly mode
	tcMut := TestCase{
		Endpoint:      targetURL,
		Method:        "POST",
		IsDestructive: true,
	}
	resMut := exec.Execute(context.Background(), tcMut)
	if resMut.Error != ErrReadOnlyMode {
		t.Errorf("expected ErrReadOnlyMode, got %v", resMut.Error)
	}

	// Test 2: Safe GET should succeed
	tcSafe := TestCase{
		Endpoint:      targetURL,
		Method:        "GET",
		IsDestructive: false,
	}
	res1 := exec.Execute(context.Background(), tcSafe)
	if res1.Error != nil || res1.StatusCode != 200 {
		t.Errorf("expected successful execution, got status %d, err %v", res1.StatusCode, res1.Error)
	}

	// Test 3: Next GET succeeds
	res2 := exec.Execute(context.Background(), tcSafe)
	if res2.Error != nil {
		t.Errorf("expected second request to succeed, got %v", res2.Error)
	}

	// Test 4: Third GET exceeds budget of 2
	res3 := exec.Execute(context.Background(), tcSafe)
	if res3.Error != ErrBudgetExceeded {
		t.Errorf("expected ErrBudgetExceeded on 3rd request, got %v", res3.Error)
	}
}
