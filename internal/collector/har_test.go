package collector

import (
	"strings"
	"testing"
)

const sampleHAR = `{
  "log": {
    "version": "1.2",
    "creator": {
      "name": "StateWeaverTest",
      "version": "1.0"
    },
    "entries": [
      {
        "startedDateTime": "2026-03-31T12:00:00Z",
        "time": 45.2,
        "request": {
          "method": "GET",
          "url": "http://localhost:8080/api/projects/1001",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [
            { "name": "Authorization", "value": "Bearer token-alice-org-a-owner" },
            { "name": "Accept", "value": "application/json" }
          ],
          "queryString": [
            { "name": "view", "value": "full" }
          ],
          "postData": null,
          "bodySize": 0
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [
            { "name": "Content-Type", "value": "application/json" }
          ],
          "content": {
            "size": 75,
            "mimeType": "application/json",
            "text": "{\"id\": 1001, \"name\": \"Project Titan\", \"tenant_id\": \"org-a\"}"
          },
          "bodySize": 75
        }
      },
      {
        "startedDateTime": "2026-03-31T12:01:00Z",
        "time": 30.0,
        "request": {
          "method": "DELETE",
          "url": "http://localhost:8080/api/projects/1001",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [
            { "name": "Authorization", "value": "Bearer token-alice-org-a-owner" }
          ],
          "queryString": [],
          "postData": null,
          "bodySize": 0
        },
        "response": {
          "status": 204,
          "statusText": "No Content",
          "httpVersion": "HTTP/1.1",
          "cookies": [],
          "headers": [],
          "content": {
            "size": 0,
            "mimeType": "text/plain",
            "text": ""
          },
          "bodySize": 0
        }
      }
    ]
  }
}`

func TestHARParser(t *testing.T) {
	parser := NewParser()
	records, err := parser.Parse(strings.NewReader(sampleHAR))
	if err != nil {
		t.Fatalf("unexpected error parsing valid HAR: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	rec1 := records[0]
	if rec1.Method != "GET" {
		t.Errorf("expected GET, got %s", rec1.Method)
	}
	if rec1.NormalizedTemplate != "/api/projects/{project_id}" {
		t.Errorf("expected /api/projects/{project_id}, got %q", rec1.NormalizedTemplate)
	}
	if rec1.PathParams["project_id"] != "1001" {
		t.Errorf("expected project_id 1001, got %q", rec1.PathParams["project_id"])
	}
	if rec1.ResponseStatus != 200 {
		t.Errorf("expected 200, got %d", rec1.ResponseStatus)
	}
	if len(rec1.SensitiveFields) == 0 {
		t.Errorf("expected sensitive fields detected for Authorization header")
	}

	rec2 := records[1]
	if rec2.Method != "DELETE" {
		t.Errorf("expected DELETE, got %s", rec2.Method)
	}
	if rec2.ResponseStatus != 204 {
		t.Errorf("expected 204, got %d", rec2.ResponseStatus)
	}
}

func TestMalformedHAR(t *testing.T) {
	parser := NewParser()
	_, err := parser.Parse(strings.NewReader(`{ "invalid": true }`))
	if err == nil {
		t.Errorf("expected error parsing malformed HAR, got nil")
	}

	_, errEmpty := parser.Parse(strings.NewReader(``))
	if errEmpty == nil {
		t.Errorf("expected error for empty HAR")
	}
}

func TestOpenAPICollector(t *testing.T) {
	openAPISample := `{
		"openapi": "3.0.0",
		"info": { "title": "Test API", "version": "1.0.0" },
		"paths": {
			"/api/projects/{id}": {
				"get": {
					"summary": "Get project",
					"parameters": [
						{ "name": "id", "in": "path", "required": true }
					]
				}
			}
		}
	}`

	collector := NewOpenAPICollector()
	records, err := collector.Parse(strings.NewReader(openAPISample))
	if err != nil {
		t.Fatalf("unexpected error parsing openapi: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Method != "GET" {
		t.Errorf("expected GET method, got %s", records[0].Method)
	}
	if records[0].NormalizedTemplate != "/api/projects/{id}" {
		t.Errorf("expected /api/projects/{id}, got %q", records[0].NormalizedTemplate)
	}
}

