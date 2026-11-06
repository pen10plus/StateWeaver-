package scope

import (
	"testing"
)

func TestScopeValidation(t *testing.T) {
	s := New([]string{"localhost", "127.0.0.1"}, []int{8080, 8081}, true, false)

	// Valid localhost with allowed port
	if err := s.ValidateTarget("http://localhost:8080/api/projects"); err != nil {
		t.Fatalf("expected valid target, got err: %v", err)
	}

	// Valid 127.0.0.1
	if err := s.ValidateTarget("http://127.0.0.1:8081/test"); err != nil {
		t.Fatalf("expected valid target, got err: %v", err)
	}

	// Invalid port
	if err := s.ValidateTarget("http://localhost:9999/api"); err == nil {
		t.Errorf("expected error for disallowed port 9999, got nil")
	}

	// External host blocked by localhostOnly
	if err := s.ValidateTarget("https://api.external.com/v1"); err == nil {
		t.Errorf("expected error for external target under localhost-only, got nil")
	}

	// External allowed when allowExternal is true
	sExternal := New([]string{"api.external.com"}, nil, true, true)
	if err := sExternal.ValidateTarget("https://api.external.com/v1"); err != nil {
		t.Errorf("expected allowed external target when allowExternal=true, got: %v", err)
	}

	// Wildcard subdomain
	sWildcard := New([]string{"*.mycompany.internal"}, nil, false, false)
	if err := sWildcard.ValidateTarget("http://api.mycompany.internal/test"); err != nil {
		t.Errorf("expected wildcard match, got err: %v", err)
	}
	if err := sWildcard.ValidateTarget("http://othercompany.com/test"); err == nil {
		t.Errorf("expected rejection for non-matching domain, got nil")
	}
}

func TestScopeAddRemove(t *testing.T) {
	s := New(nil, nil, false, false)
	if err := s.AddHost("custom.host.local:8080"); err != nil {
		t.Fatalf("failed to add host: %v", err)
	}

	if err := s.ValidateTarget("http://custom.host.local:8080"); err != nil {
		t.Errorf("expected custom.host.local to be valid, got: %v", err)
	}

	s.RemoveHost("custom.host.local")
	if err := s.ValidateTarget("http://custom.host.local:8080"); err == nil {
		t.Errorf("expected error after removing host, got nil")
	}
}

