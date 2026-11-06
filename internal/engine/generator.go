package engine

import (
	"fmt"
	"strings"

	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/identity"
)

// TestCategory categorizes the hypothesis being evaluated.
type TestCategory string

const (
	CategoryBOLA            TestCategory = "Broken Object Level Authorization (BOLA/IDOR)"
	CategoryCrossTenant     TestCategory = "Cross-Tenant Access Weakness"
	CategoryRBAC            TestCategory = "Role-Based Privilege Escalation"
	CategoryRevokedAccess   TestCategory = "Revoked-Access Inconsistency"
	CategoryUnauthenticated TestCategory = "Unauthenticated Access"
)

// TestCase represents an individual authorization test probe hypothesis.
type TestCase struct {
	ID             string                    `json:"id"`
	Category       TestCategory              `json:"category"`
	Description    string                    `json:"description"`
	Endpoint       string                    `json:"endpoint"`
	Method         string                    `json:"method"`
	Resource       string                    `json:"resource"`
	BaseRecord     collector.NormalizedRecord `json:"base_record"`
	TestIdentity   *identity.Identity        `json:"test_identity"`
	OwnerIdentity  *identity.Identity        `json:"owner_identity,omitempty"`
	IsDestructive  bool                      `json:"is_destructive"`
}

// Generator generates differential test cases from imported records and identity profiles.
type Generator struct {
	identities []*identity.Identity
}

// NewGenerator creates a Generator instance.
func NewGenerator(identities []*identity.Identity) *Generator {
	return &Generator{identities: identities}
}

// GenerateTestCases creates differential test cases for each imported record.
func (g *Generator) GenerateTestCases(records []collector.NormalizedRecord) []TestCase {
	var tests []TestCase
	testIdx := 1

	for _, rec := range records {
		resourceName := inferResourceName(rec.NormalizedTemplate)
		isDestructive := isMutationMethod(rec.Method)

		// Identify which identity likely produced this baseline record based on Auth header or defaults
		var owner *identity.Identity
		for _, id := range g.identities {
			if id.Role == "owner" || id.Role == "admin" {
				owner = id
				break
			}
		}

		for _, testId := range g.identities {
			// Skip comparing owner to themselves for differential test
			if owner != nil && testId.ID == owner.ID {
				continue
			}

			category := determineCategory(owner, testId, isDestructive)
			desc := fmt.Sprintf("[%s] Test %s access on %s %s", category, testId.Name, rec.Method, rec.NormalizedTemplate)

			tests = append(tests, TestCase{
				ID:            fmt.Sprintf("TC-%04d", testIdx),
				Category:      category,
				Description:   desc,
				Endpoint:      rec.OriginalURL,
				Method:        rec.Method,
				Resource:      resourceName,
				BaseRecord:    rec,
				TestIdentity:  testId,
				OwnerIdentity: owner,
				IsDestructive: isDestructive,
			})
			testIdx++
		}
	}

	return tests
}

func determineCategory(owner, testId *identity.Identity, isDestructive bool) TestCategory {
	if testId.AuthType == identity.AuthTypeNone || testId.Role == "anonymous" {
		return CategoryUnauthenticated
	}
	if testId.IsRevoked {
		return CategoryRevokedAccess
	}
	if owner != nil && testId.TenantID != "" && owner.TenantID != "" && testId.TenantID != owner.TenantID {
		return CategoryCrossTenant
	}
	if isDestructive && (testId.Role == "viewer" || testId.Role == "guest") {
		return CategoryRBAC
	}
	return CategoryBOLA
}

func inferResourceName(template string) string {
	parts := strings.Split(strings.Trim(template, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if !strings.HasPrefix(p, "{") && p != "api" && p != "v1" && p != "v2" {
			if strings.HasSuffix(p, "s") {
				return strings.TrimSuffix(p, "s")
			}
			return p
		}
	}
	return "resource"
}

func isMutationMethod(m string) bool {
	upper := strings.ToUpper(m)
	return upper == "POST" || upper == "PUT" || upper == "PATCH" || upper == "DELETE"
}

