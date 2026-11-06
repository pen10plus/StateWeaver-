package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stateweaver/stateweaver/internal/normalizer"
	"gopkg.in/yaml.v3"
)

// OpenAPISpec represents a subset of OpenAPI 2.0 / 3.0 specification.
type OpenAPISpec struct {
	OpenAPI string                          `json:"openapi" yaml:"openapi"`
	Swagger string                          `json:"swagger" yaml:"swagger"`
	Info    OpenAPIInfo                     `json:"info" yaml:"info"`
	Paths   map[string]map[string]OpenAPIOp `json:"paths" yaml:"paths"`
}

// OpenAPIInfo metadata.
type OpenAPIInfo struct {
	Title   string `json:"title" yaml:"title"`
	Version string `json:"version" yaml:"version"`
}

// OpenAPIOp represents an HTTP operation on a path.
type OpenAPIOp struct {
	Summary     string              `json:"summary" yaml:"summary"`
	Description string              `json:"description" yaml:"description"`
	OperationID string              `json:"operationId" yaml:"operationId"`
	Parameters  []OpenAPIParameter  `json:"parameters" yaml:"parameters"`
	Responses   map[string]struct{} `json:"responses" yaml:"responses"`
}

// OpenAPIParameter represents an endpoint parameter.
type OpenAPIParameter struct {
	Name     string `json:"name" yaml:"name"`
	In       string `json:"in" yaml:"in"` // "path", "query", "header"
	Required bool   `json:"required" yaml:"required"`
}

// OpenAPICollector parses OpenAPI specifications into NormalizedRecords.
type OpenAPICollector struct{}

// NewOpenAPICollector creates a new OpenAPI collector.
func NewOpenAPICollector() *OpenAPICollector {
	return &OpenAPICollector{}
}

// ParseFile parses an OpenAPI/Swagger file from JSON or YAML.
func (c *OpenAPICollector) ParseFile(path string) ([]NormalizedRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAPI spec %q: %w", path, err)
	}

	return c.Parse(strings.NewReader(string(data)))
}

// Parse parses OpenAPI data from io.Reader.
func (c *OpenAPICollector) Parse(r io.Reader) ([]NormalizedRecord, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var spec OpenAPISpec
	// Try JSON first, fallback to YAML
	if err := json.Unmarshal(data, &spec); err != nil {
		if yamlErr := yaml.Unmarshal(data, &spec); yamlErr != nil {
			return nil, fmt.Errorf("failed to parse OpenAPI as JSON or YAML: %v", yamlErr)
		}
	}

	if len(spec.Paths) == 0 {
		return nil, fmt.Errorf("no paths found in OpenAPI specification")
	}

	var records []NormalizedRecord
	idx := 1
	for pathKey, methods := range spec.Paths {
		for method, op := range methods {
			methodUpper := strings.ToUpper(method)
			if !isHTTPMethod(methodUpper) {
				continue
			}

			pathParams := make(map[string]string)
			queryParams := make(map[string]string)

			for _, param := range op.Parameters {
				switch strings.ToLower(param.In) {
				case "path":
					pathParams[param.Name] = "{" + param.Name + "}"
				case "query":
					queryParams[param.Name] = "test-value"
				}
			}

			records = append(records, NormalizedRecord{
				ID:                 fmt.Sprintf("openapi-entry-%04d", idx),
				OriginalURL:        pathKey,
				NormalizedTemplate: pathKey,
				Method:             methodUpper,
				RequestHeaders:     map[string]string{"Content-Type": "application/json"},
				QueryParams:        queryParams,
				PathParams:         pathParams,
				ExtractedEntities:  normalizer.ExtractLikelyEntities(pathKey, pathParams),
				ResponseStatus:     200,
			})
			idx++
		}
	}

	return records, nil
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}
