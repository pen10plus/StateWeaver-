package normalizer

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	// UUID regex: 8-4-4-4-12 hex chars
	uuidRegex = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// Mongo ObjectID: 24 hex chars
	mongoIDRegex = regexp.MustCompile(`^[0-9a-f]{24}$`)
	// Numeric ID
	numericIDRegex = regexp.MustCompile(`^\d+$`)
	// ISO8601 / RFC3339 timestamp
	isoTimestampRegex = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	// Bearer token pattern
	bearerRegex = regexp.MustCompile(`(?i)Bearer\s+([A-Za-z0-9\-_\.]+)`)
)

// PathTemplateNormalizer normalizes dynamic URL segments into parameterized templates.
type PathTemplateNormalizer struct{}

// NewPathTemplateNormalizer returns a new normalizer instance.
func NewPathTemplateNormalizer() *PathTemplateNormalizer {
	return &PathTemplateNormalizer{}
}

// NormalizeURL converts a raw URL into a normalized URL template and extracted parameters.
// E.g.: "http://localhost:8080/api/v1/projects/1001/members/205?filter=active"
// Template: "/api/v1/projects/{project_id}/members/{member_id}"
func (n *PathTemplateNormalizer) NormalizeURL(rawURL string) (templatePath string, params map[string]string) {
	params = make(map[string]string)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, params
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}

	segments := strings.Split(path, "/")
	normalizedSegments := make([]string, 0, len(segments))

	for i, seg := range segments {
		if seg == "" {
			normalizedSegments = append(normalizedSegments, "")
			continue
		}

		if isDynamicSegment(seg) {
			paramName := inferParamName(segments, i)
			params[paramName] = seg
			normalizedSegments = append(normalizedSegments, "{"+paramName+"}")
		} else {
			normalizedSegments = append(normalizedSegments, seg)
		}
	}

	templatePath = strings.Join(normalizedSegments, "/")
	return templatePath, params
}

// isDynamicSegment checks if a path segment is an ID, UUID, or hash.
func isDynamicSegment(seg string) bool {
	if numericIDRegex.MatchString(seg) {
		return true
	}
	if uuidRegex.MatchString(seg) {
		return true
	}
	if mongoIDRegex.MatchString(seg) {
		return true
	}
	return false
}

// inferParamName guesses a semantic parameter name based on preceding path segment.
func inferParamName(segments []string, currentIndex int) string {
	if currentIndex > 0 {
		prev := strings.ToLower(segments[currentIndex-1])
		// Strip common prefixes or plural 's'
		if strings.HasSuffix(prev, "ies") { // e.g. categories -> category_id
			return strings.TrimSuffix(prev, "ies") + "y_id"
		}
		if strings.HasSuffix(prev, "s") {
			singular := strings.TrimSuffix(prev, "s")
			return singular + "_id"
		}
		if prev != "" {
			return prev + "_id"
		}
	}
	return "id"
}

// NormalizeJSONBody normalizes volatile fields (timestamps, request IDs, trace IDs)
// in a JSON payload so differential comparator can focus on true authorization and logic differences.
func NormalizeJSONBody(rawJSON []byte) []byte {
	if len(rawJSON) == 0 {
		return rawJSON
	}

	var data interface{}
	if err := json.Unmarshal(rawJSON, &data); err != nil {
		// Not JSON, return as is
		return rawJSON
	}

	normalized := walkAndNormalize(data)
	out, err := json.Marshal(normalized)
	if err != nil {
		return rawJSON
	}
	return out
}

func walkAndNormalize(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, item := range val {
			kLower := strings.ToLower(k)
			if isVolatileKey(kLower) {
				result[k] = "<DYNAMIC_VALUE>"
				continue
			}
			result[k] = walkAndNormalize(item)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = walkAndNormalize(item)
		}
		return result
	case string:
		if isoTimestampRegex.MatchString(val) {
			return "<TIMESTAMP>"
		}
		if uuidRegex.MatchString(val) {
			return "<UUID>"
		}
		return val
	default:
		return val
	}
}

// isVolatileKey identifies keys that normally fluctuate between requests without security significance.
func isVolatileKey(key string) bool {
	volatileKeys := []string{
		"timestamp",
		"created_at",
		"updated_at",
		"last_modified",
		"request_id",
		"trace_id",
		"span_id",
		"nonce",
		"_csrf",
		"csrftoken",
		"csrf_token",
		"uptime",
		"time",
	}
	for _, vk := range volatileKeys {
		if strings.Contains(key, vk) {
			return true
		}
	}
	return false
}

// RedactSensitiveJSON redacts values of keys identified as sensitive.
func RedactSensitiveJSON(rawJSON []byte, sensitiveKeys []string, maskValue string) []byte {
	if len(rawJSON) == 0 {
		return rawJSON
	}

	var data interface{}
	if err := json.Unmarshal(rawJSON, &data); err != nil {
		return rawJSON
	}

	keysMap := make(map[string]struct{})
	for _, k := range sensitiveKeys {
		keysMap[strings.ToLower(k)] = struct{}{}
	}

	redacted := walkAndRedact(data, keysMap, maskValue)
	out, err := json.Marshal(redacted)
	if err != nil {
		return rawJSON
	}
	return out
}

func walkAndRedact(v interface{}, keysMap map[string]struct{}, mask string) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, item := range val {
			kLower := strings.ToLower(k)
			sensitive := false
			for sKey := range keysMap {
				if strings.Contains(kLower, sKey) {
					sensitive = true
					break
				}
			}
			if sensitive {
				result[k] = mask
			} else {
				result[k] = walkAndRedact(item, keysMap, mask)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = walkAndRedact(item, keysMap, mask)
		}
		return result
	case string:
		// Check for inline bearer tokens in strings
		if bearerRegex.MatchString(val) {
			return bearerRegex.ReplaceAllString(val, "Bearer "+mask)
		}
		return val
	default:
		return val
	}
}

// ExtractLikelyEntities searches a URL and parameters for domain entity names and IDs.
func ExtractLikelyEntities(templatePath string, params map[string]string) map[string]string {
	entities := make(map[string]string)
	for k, v := range params {
		cleanKey := strings.TrimSuffix(k, "_id")
		if cleanKey != "" {
			entities[cleanKey] = v
		}
	}
	return entities
}

// ParseIntegerID attempts to parse string as int64.
func ParseIntegerID(val string) (int64, bool) {
	id, err := strconv.ParseInt(val, 10, 64)
	return id, err == nil
}

