package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/stateweaver/stateweaver/internal/normalizer"
)

var (
	ErrEmptyHAR    = errors.New("HAR document is empty")
	ErrInvalidHAR  = errors.New("malformed or unsupported HAR structure")
	ErrNoEntries   = errors.New("no HTTP entries found in HAR log")
)

// HAR represents a standard HTTP Archive 1.2 root object.
type HAR struct {
	Log Log `json:"log"`
}

// Log represents the log container in HAR.
type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Entries []Entry `json:"entries"`
}

// Creator metadata.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Entry is an individual HTTP transaction.
type Entry struct {
	StartedDateTime time.Time `json:"startedDateTime"`
	Time            float64   `json:"time"`
	Request         Request   `json:"request"`
	Response        Response  `json:"response"`
}

// Request details in HAR.
type Request struct {
	Method      string        `json:"method"`
	URL         string        `json:"url"`
	HTTPVersion string        `json:"httpVersion"`
	Cookies     []Cookie      `json:"cookies"`
	Headers     []NameValuePair `json:"headers"`
	QueryString []NameValuePair `json:"queryString"`
	PostData    *PostData     `json:"postData,omitempty"`
	BodySize    int64         `json:"bodySize"`
}

// Response details in HAR.
type Response struct {
	Status      int           `json:"status"`
	StatusText  string        `json:"statusText"`
	HTTPVersion string        `json:"httpVersion"`
	Cookies     []Cookie      `json:"cookies"`
	Headers     []NameValuePair `json:"headers"`
	Content     Content       `json:"content"`
	BodySize    int64         `json:"bodySize"`
}

// NameValuePair generic header or query param.
type NameValuePair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie representation.
type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path"`
	Domain   string    `json:"domain"`
	Expires  time.Time `json:"expires"`
	HTTPOnly bool      `json:"httpOnly"`
	Secure   bool      `json:"secure"`
}

// PostData representation.
type PostData struct {
	MimeType string          `json:"mimeType"`
	Text     string          `json:"text"`
	Params   []NameValuePair `json:"params,omitempty"`
}

// Content representation.
type Content struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

// NormalizedRecord is the internal structured representation of an imported HTTP request-response pair.
type NormalizedRecord struct {
	ID                 string            `json:"id"`
	OriginalURL        string            `json:"original_url"`
	NormalizedTemplate string            `json:"normalized_template"`
	Method             string            `json:"method"`
	RequestHeaders     map[string]string `json:"request_headers"`
	QueryParams        map[string]string `json:"query_params"`
	RequestBody        string            `json:"request_body"`
	PathParams         map[string]string `json:"path_params"`
	ExtractedEntities  map[string]string `json:"extracted_entities"`
	ResponseStatus     int               `json:"response_status"`
	ResponseHeaders    map[string]string `json:"response_headers"`
	ResponseBody       string            `json:"response_body"`
	SensitiveFields    []string          `json:"sensitive_fields"`
	Timestamp          time.Time         `json:"timestamp"`
}

// Parser parses and processes HAR files.
type Parser struct {
	norm *normalizer.PathTemplateNormalizer
}

// NewParser creates a new HAR parser.
func NewParser() *Parser {
	return &Parser{
		norm: normalizer.NewPathTemplateNormalizer(),
	}
}

// ParseFile reads and parses a HAR file from disk.
func (p *Parser) ParseFile(path string) ([]NormalizedRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open HAR file %q: %w", path, err)
	}
	defer f.Close()

	return p.Parse(f)
}

// Parse parses HAR data from an io.Reader.
func (p *Parser) Parse(r io.Reader) ([]NormalizedRecord, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read HAR input: %w", err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, ErrEmptyHAR
	}

	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHAR, err)
	}

	if len(har.Log.Entries) == 0 {
		return nil, ErrNoEntries
	}

	records := make([]NormalizedRecord, 0, len(har.Log.Entries))
	for idx, entry := range har.Log.Entries {
		rec := p.processEntry(idx, entry)
		records = append(records, rec)
	}

	return records, nil
}

func (p *Parser) processEntry(index int, entry Entry) NormalizedRecord {
	req := entry.Request
	resp := entry.Response

	template, pathParams := p.norm.NormalizeURL(req.URL)
	entities := normalizer.ExtractLikelyEntities(template, pathParams)

	reqHeaders := make(map[string]string)
	for _, h := range req.Headers {
		reqHeaders[h.Name] = h.Value
	}

	respHeaders := make(map[string]string)
	for _, h := range resp.Headers {
		respHeaders[h.Name] = h.Value
	}

	queryParams := make(map[string]string)
	for _, q := range req.QueryString {
		queryParams[q.Name] = q.Value
	}

	var reqBody string
	if req.PostData != nil {
		reqBody = req.PostData.Text
	}

	sensitiveFields := detectSensitiveFields(reqHeaders, queryParams, reqBody, resp.Content.Text)

	return NormalizedRecord{
		ID:                 fmt.Sprintf("har-entry-%04d", index+1),
		OriginalURL:        req.URL,
		NormalizedTemplate: template,
		Method:             strings.ToUpper(req.Method),
		RequestHeaders:     reqHeaders,
		QueryParams:        queryParams,
		RequestBody:        reqBody,
		PathParams:         pathParams,
		ExtractedEntities:  entities,
		ResponseStatus:     resp.Status,
		ResponseHeaders:    respHeaders,
		ResponseBody:       resp.Content.Text,
		SensitiveFields:    sensitiveFields,
		Timestamp:          entry.StartedDateTime,
	}
}

func detectSensitiveFields(headers map[string]string, queryParams map[string]string, reqBody, respBody string) []string {
	var found []string
	sensitiveKeywords := []string{
		"authorization", "token", "password", "secret", "cookie", "api_key", "session", "access_token",
	}

	for k := range headers {
		lower := strings.ToLower(k)
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lower, kw) {
				found = append(found, "header:"+k)
				break
			}
		}
	}

	for k := range queryParams {
		lower := strings.ToLower(k)
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lower, kw) {
				found = append(found, "query:"+k)
				break
			}
		}
	}

	// Simple check in JSON bodies for sensitive keys
	checkBodyJSON := func(body, prefix string) {
		if strings.HasPrefix(strings.TrimSpace(body), "{") {
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(body), &m); err == nil {
				for k := range m {
					lower := strings.ToLower(k)
					for _, kw := range sensitiveKeywords {
						if strings.Contains(lower, kw) {
							found = append(found, prefix+":"+k)
							break
						}
					}
				}
			}
		}
	}

	checkBodyJSON(reqBody, "req_body")
	checkBodyJSON(respBody, "resp_body")

	return found
}

