package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Decision defines the expected authorization decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Rule represents an explicit authorization rule defining expected access.
type Rule struct {
	Name               string   `yaml:"name"`
	Description        string   `yaml:"description"`
	Category           string   `yaml:"category"` // e.g. "BOLA", "Cross-Tenant", "Privilege Escalation", "Revoked Access"
	Severity           string   `yaml:"severity"` // "Critical", "High", "Medium", "Low"
	Resource           string   `yaml:"resource"` // e.g. "project", "member", "*"
	Action             string   `yaml:"action"`   // "read", "create", "update", "delete", "*" or HTTP method
	Roles              []string `yaml:"roles"`    // roles to match, e.g. ["viewer"]
	CrossTenant        *bool    `yaml:"cross_tenant,omitempty"`
	CrossUser          *bool    `yaml:"cross_user,omitempty"`
	RequiresOwnership  *bool    `yaml:"requires_ownership,omitempty"`
	RevokedAccess      *bool    `yaml:"revoked_access,omitempty"`
	Expected           Decision `yaml:"expected"`                 // "allow" or "deny"
	ExpectedHTTPStatus []int    `yaml:"expected_http_status,omitempty"` // e.g. [403, 404]
	Remediation        string   `yaml:"remediation,omitempty"`
}

// Config represents the YAML policy document.
type Config struct {
	Version  string `yaml:"version"`
	Policies []Rule `yaml:"policies"`
}

// Engine evaluates operations against defined policies.
type Engine struct {
	rules []Rule
}

// NewEngine creates a Policy Engine with the provided rules.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Load reads and parses policies from a YAML file.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse policy file %q: %w", path, err)
	}

	return NewEngine(cfg.Policies), nil
}

// Save writes policies to a YAML file.
func Save(path string, rules []Rule) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", dir, err)
		}
	}

	cfg := Config{
		Version:  "1.0",
		Policies: rules,
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policies: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// Rules returns all loaded rules.
func (e *Engine) Rules() []Rule {
	return e.rules
}

// Context contains parameters about the requested operation for policy evaluation.
type Context struct {
	IdentityID     string
	IdentityRole   string
	IdentityTenant string
	IdentityUser   string
	IsRevoked      bool

	ResourceName   string
	ResourceTenant string
	ResourceOwner  string

	Action         string // "read", "update", "delete", "create"
	HTTPMethod     string // "GET", "POST", "PUT", "DELETE"
	ObservedStatus int
}

// EvaluationResult represents the output of policy matching.
type EvaluationResult struct {
	Violated        bool
	MatchedRule     *Rule
	ExpectedDecision Decision
	ExpectedStatus  []int
	Explanation     string
}

// Evaluate evaluates an operation context against all policies.
func (e *Engine) Evaluate(ctx Context) EvaluationResult {
	actionNorm := normalizeAction(ctx.Action, ctx.HTTPMethod)

	for _, rule := range e.rules {
		if !ruleMatchesResource(rule, ctx.ResourceName) {
			continue
		}
		if !ruleMatchesAction(rule, actionNorm, ctx.HTTPMethod) {
			continue
		}
		if !ruleMatchesRole(rule, ctx.IdentityRole) {
			continue
		}
		if !ruleMatchesRevoked(rule, ctx.IsRevoked) {
			continue
		}
		if !ruleMatchesCrossTenant(rule, ctx.IdentityTenant, ctx.ResourceTenant) {
			continue
		}
		if !ruleMatchesCrossUser(rule, ctx.IdentityUser, ctx.ResourceOwner) {
			continue
		}

		// Rule matches! Check whether observed behavior violates the expected policy
		ruleCopy := rule
		expectedStatus := rule.ExpectedHTTPStatus
		if len(expectedStatus) == 0 {
			if rule.Expected == DecisionDeny {
				expectedStatus = []int{401, 403, 404}
			} else {
				expectedStatus = []int{200, 201, 204}
			}
		}

		observedSuccess := ctx.ObservedStatus >= 200 && ctx.ObservedStatus < 300
		violated := false
		var explanation string

		if rule.Expected == DecisionDeny && observedSuccess {
			violated = true
			explanation = fmt.Sprintf("Policy %q expects DENY for %s on %s by %s, but API returned HTTP %d (Allowed)",
				rule.Name, actionNorm, ctx.ResourceName, ctx.IdentityRole, ctx.ObservedStatus)
		} else if rule.Expected == DecisionAllow && (ctx.ObservedStatus == 401 || ctx.ObservedStatus == 403) {
			violated = true
			explanation = fmt.Sprintf("Policy %q expects ALLOW for %s on %s by %s, but API returned HTTP %d (Denied)",
				rule.Name, actionNorm, ctx.ResourceName, ctx.IdentityRole, ctx.ObservedStatus)
		}

		return EvaluationResult{
			Violated:         violated,
			MatchedRule:      &ruleCopy,
			ExpectedDecision: rule.Expected,
			ExpectedStatus:   expectedStatus,
			Explanation:      explanation,
		}
	}

	return EvaluationResult{
		Violated:         false,
		MatchedRule:      nil,
		ExpectedDecision: DecisionAllow,
		Explanation:      "No explicit matching policy found",
	}
}

func normalizeAction(action, httpMethod string) string {
	if action != "" {
		return strings.ToLower(action)
	}
	switch strings.ToUpper(httpMethod) {
	case "GET", "HEAD":
		return "read"
	case "POST":
		return "create"
	case "PUT", "PATCH":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return strings.ToLower(httpMethod)
	}
}

func ruleMatchesResource(r Rule, resource string) bool {
	if r.Resource == "" || r.Resource == "*" {
		return true
	}
	return strings.EqualFold(r.Resource, resource)
}

func ruleMatchesAction(r Rule, action, httpMethod string) bool {
	if r.Action == "" || r.Action == "*" {
		return true
	}
	if strings.EqualFold(r.Action, action) {
		return true
	}
	if strings.EqualFold(r.Action, httpMethod) {
		return true
	}
	return false
}

func ruleMatchesRole(r Rule, role string) bool {
	if len(r.Roles) == 0 {
		return true
	}
	for _, rRole := range r.Roles {
		if strings.EqualFold(rRole, "*") || strings.EqualFold(rRole, role) {
			return true
		}
	}
	return false
}

func ruleMatchesRevoked(r Rule, isRevoked bool) bool {
	if r.RevokedAccess == nil {
		return true
	}
	return *r.RevokedAccess == isRevoked
}

func ruleMatchesCrossTenant(r Rule, idTenant, resTenant string) bool {
	if r.CrossTenant == nil {
		return true
	}
	isCross := (idTenant != "" && resTenant != "" && idTenant != resTenant)
	return *r.CrossTenant == isCross
}

func ruleMatchesCrossUser(r Rule, idUser, resOwner string) bool {
	if r.CrossUser == nil {
		return true
	}
	isCross := (idUser != "" && resOwner != "" && idUser != resOwner)
	return *r.CrossUser == isCross
}

// DefaultBenchmarkPolicies returns standard policy rules for multi-tenant differential testing.
func DefaultBenchmarkPolicies() []Rule {
	tVal := true
	return []Rule{
		{
			Name:        "cross-tenant-isolation",
			Description: "Tenants must never read or modify resources belonging to another organization",
			Category:    "Cross-Tenant Access Weakness",
			Severity:    "Critical",
			Resource:    "*",
			Action:      "*",
			CrossTenant: &tVal,
			Expected:    DecisionDeny,
			Remediation: "Enforce strict tenant_id scoping in database queries and verify tenant membership from authenticated session token.",
		},
		{
			Name:        "viewer-cannot-delete-project",
			Description: "Users with Viewer role must not be able to delete projects",
			Category:    "Role-Based Authorization Flaw",
			Severity:    "High",
			Resource:    "project",
			Action:      "delete",
			Roles:       []string{"viewer"},
			Expected:    DecisionDeny,
			Remediation: "Ensure role-based permission checks verify DELETE permission before executing project deletion.",
		},
		{
			Name:        "viewer-cannot-access-secrets",
			Description: "Users with Viewer role must not access sensitive project secrets",
			Category:    "Role-Based Authorization Flaw",
			Severity:    "High",
			Resource:    "secrets",
			Action:      "read",
			Roles:       []string{"viewer"},
			Expected:    DecisionDeny,
			Remediation: "Restrict secrets endpoint to Owner and Admin roles only.",
		},
		{
			Name:          "revoked-member-denied",
			Description:   "Revoked or deactivated members must not retain access to organization resources",
			Category:      "Revoked-Access Inconsistency",
			Severity:      "Critical",
			Resource:      "*",
			Action:        "*",
			RevokedAccess: &tVal,
			Expected:      DecisionDeny,
			Remediation:   "Check real-time revocation status in database/cache rather than relying solely on non-expiring JWT claims.",
		},
		{
			Name:        "unauthenticated-access-denied",
			Description: "Unauthenticated requests to protected API endpoints must be rejected",
			Category:    "Broken Authentication",
			Severity:    "High",
			Resource:    "*",
			Action:      "*",
			Roles:       []string{"anonymous"},
			Expected:    DecisionDeny,
			Remediation: "Enforce authentication middleware on all private API routes.",
		},
	}
}

