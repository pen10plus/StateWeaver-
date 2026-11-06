package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/normalizer"
)

// ComparisonOutcome describes the differential outcome between baseline and probe.
type ComparisonOutcome struct {
	StatusMatch        bool     `json:"status_match"`
	BaselineStatus     int      `json:"baseline_status"`
	ProbeStatus        int      `json:"probe_status"`
	StructuralMatch    bool     `json:"structural_match"`
	BodyIdentical      bool     `json:"body_identical"`
	NormalizedMatch    bool     `json:"normalized_match"`
	LeakedFields       []string `json:"leaked_fields,omitempty"`
	DifferenceSummary  string   `json:"difference_summary"`
}

// Comparator compares baseline HTTP response against differential test probe response.
type Comparator struct {
	sensitiveKeys []string
}

// NewComparator creates a Comparator instance.
func NewComparator(sensitiveKeys []string) *Comparator {
	if len(sensitiveKeys) == 0 {
		sensitiveKeys = []string{
			"password", "secret", "token", "api_key", "access_token",
			"private_key", "session_id", "credit_card",
		}
	}
	return &Comparator{
		sensitiveKeys: sensitiveKeys,
	}
}

// Compare evaluates differences between a baseline record and the observed test execution result.
func (c *Comparator) Compare(base collector.NormalizedRecord, probe ExecutionResult) ComparisonOutcome {
	statusMatch := base.ResponseStatus == probe.StatusCode
	bodyIdentical := base.ResponseBody == probe.Body

	normBase := normalizer.NormalizeJSONBody([]byte(base.ResponseBody))
	normProbe := normalizer.NormalizeJSONBody([]byte(probe.Body))
	normalizedMatch := bytes.Equal(normBase, normProbe)

	structuralMatch := compareJSONStructure([]byte(base.ResponseBody), []byte(probe.Body))
	leaked := c.detectLeakedSensitiveData([]byte(probe.Body))

	var summaryParts []string
	if !statusMatch {
		summaryParts = append(summaryParts, fmt.Sprintf("Status code disparity: Baseline=%d, Probe=%d", base.ResponseStatus, probe.StatusCode))
	} else {
		summaryParts = append(summaryParts, fmt.Sprintf("Status codes match (%d)", base.ResponseStatus))
	}

	if statusMatch && probe.StatusCode >= 200 && probe.StatusCode < 300 {
		if normalizedMatch {
			summaryParts = append(summaryParts, "Response payload matches baseline data (Potential Unauthorized Data Exposure)")
		} else if structuralMatch {
			summaryParts = append(summaryParts, "Response body structure matches baseline")
		}
	}

	if len(leaked) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("Sensitive fields exposed: %s", strings.Join(leaked, ", ")))
	}

	return ComparisonOutcome{
		StatusMatch:       statusMatch,
		BaselineStatus:    base.ResponseStatus,
		ProbeStatus:       probe.StatusCode,
		StructuralMatch:   structuralMatch,
		BodyIdentical:     bodyIdentical,
		NormalizedMatch:   normalizedMatch,
		LeakedFields:      leaked,
		DifferenceSummary: strings.Join(summaryParts, "; "),
	}
}

// compareJSONStructure checks if two JSON strings have the same schema/key hierarchy.
func compareJSONStructure(a, b []byte) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) == 0 || len(b) == 0 {
		return false
	}

	var dataA, dataB interface{}
	if err := json.Unmarshal(a, &dataA); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &dataB); err != nil {
		return false
	}

	return reflect.DeepEqual(extractStructure(dataA), extractStructure(dataB))
}

func extractStructure(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make(map[string]interface{})
		for k, child := range val {
			keys[k] = extractStructure(child)
		}
		return keys
	case []interface{}:
		if len(val) == 0 {
			return []interface{}{}
		}
		return []interface{}{extractStructure(val[0])}
	default:
		return "type:" + reflect.TypeOf(v).String()
	}
}

// detectLeakedSensitiveData inspects probe response body for sensitive keys.
func (c *Comparator) detectLeakedSensitiveData(body []byte) []string {
	var leaked []string
	if len(body) == 0 {
		return leaked
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return leaked
	}

	foundMap := make(map[string]struct{})
	c.searchKeys(data, foundMap)

	for k := range foundMap {
		leaked = append(leaked, k)
	}
	return leaked
}

func (c *Comparator) searchKeys(v interface{}, found map[string]struct{}) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			kLower := strings.ToLower(k)
			for _, sensitive := range c.sensitiveKeys {
				if strings.Contains(kLower, strings.ToLower(sensitive)) {
					found[k] = struct{}{}
					break
				}
			}
			c.searchKeys(child, found)
		}
	case []interface{}:
		for _, child := range val {
			c.searchKeys(child, found)
		}
	}
}

