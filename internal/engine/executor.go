package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/scope"
)

var (
	ErrBudgetExceeded = errors.New("request budget exceeded")
	ErrReadOnlyMode   = errors.New("mutation operation blocked by read-only mode")
)

// ExecutionResult captures the raw result of executing a test request.
type ExecutionResult struct {
	StatusCode    int
	StatusText    string
	Headers       map[string]string
	Body          string
	Duration      time.Duration
	BlockedReason string
	Error         error
}

// SafeExecutor executes HTTP requests adhering to safety limits and policies.
type SafeExecutor struct {
	client       *http.Client
	scope        *scope.TargetScope
	cfg          *config.Execution
	rateLimiter  <-chan time.Time
	requestCount int64
	mu           sync.Mutex
}

// NewSafeExecutor creates a new SafeExecutor.
func NewSafeExecutor(sc *scope.TargetScope, cfg *config.Execution) *SafeExecutor {
	rps := cfg.RateLimitRPS
	if rps <= 0 {
		rps = 5
	}

	ticker := time.NewTicker(time.Second / time.Duration(rps))

	client := &http.Client{
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.FollowRedirects {
				return http.ErrUseLastResponse
			}
			// Restrict redirects to same origin/host
			if len(via) > 0 && req.URL.Hostname() != via[0].URL.Hostname() {
				return fmt.Errorf("cross-origin redirect blocked to %s", req.URL.Hostname())
			}
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			return nil
		},
	}

	return &SafeExecutor{
		client:      client,
		scope:       sc,
		cfg:         cfg,
		rateLimiter: ticker.C,
	}
}

// SetTransport allows injecting a custom RoundTripper (e.g. for mock testing or specialized proxies).
func (e *SafeExecutor) SetTransport(rt http.RoundTripper) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.client.Transport = rt
}

// Execute performs a safe HTTP request for the given test case.
func (e *SafeExecutor) Execute(ctx context.Context, tc TestCase) ExecutionResult {
	// 1. Check scope validation
	if err := e.scope.ValidateTarget(tc.Endpoint); err != nil {
		return ExecutionResult{
			BlockedReason: fmt.Sprintf("Scope violation: %v", err),
			Error:         err,
		}
	}

	// 2. Check read-only constraint
	if e.cfg.ReadOnly && tc.IsDestructive {
		return ExecutionResult{
			BlockedReason: "Mutation blocked: read-only mode active",
			Error:         ErrReadOnlyMode,
		}
	}

	// 3. Check request budget
	count := atomic.AddInt64(&e.requestCount, 1)
	if e.cfg.RequestBudget > 0 && int(count) > e.cfg.RequestBudget {
		return ExecutionResult{
			BlockedReason: "Budget exceeded",
			Error:         ErrBudgetExceeded,
		}
	}

	// 4. Rate limiting: wait for next tick or context cancellation
	select {
	case <-ctx.Done():
		return ExecutionResult{Error: ctx.Err()}
	case <-e.rateLimiter:
	}

	// 5. Construct request
	var bodyReader io.Reader
	if tc.BaseRecord.RequestBody != "" {
		bodyReader = strings.NewReader(tc.BaseRecord.RequestBody)
	}

	req, err := http.NewRequestWithContext(ctx, tc.Method, tc.Endpoint, bodyReader)
	if err != nil {
		return ExecutionResult{Error: fmt.Errorf("failed to create request: %w", err)}
	}

	// Copy baseline headers except authentication
	for k, v := range tc.BaseRecord.RequestHeaders {
		kLower := strings.ToLower(k)
		if kLower != "authorization" && kLower != "cookie" && kLower != "x-api-key" {
			req.Header.Set(k, v)
		}
	}

	// Apply test identity's credentials
	if tc.TestIdentity != nil {
		tc.TestIdentity.ApplyAuth(req)
	}

	// 6. Perform HTTP request with retry logic
	start := time.Now()
	var resp *http.Response
	maxRetries := e.cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 1
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err = e.client.Do(req)
		if err == nil {
			break
		}
		// If transient network error and attempts remain, wait briefly
		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return ExecutionResult{Error: ctx.Err()}
			case <-time.After(time.Duration(100*(attempt+1)) * time.Millisecond):
			}
		}
	}

	if err != nil {
		return ExecutionResult{
			Duration: time.Since(start),
			Error:    err,
		}
	}
	defer resp.Body.Close()

	// 7. Limit max response body size to prevent memory bloat
	maxBytes := int64(e.cfg.MaxResponseBytes)
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024 // 2MB
	}

	limitedReader := io.LimitReader(resp.Body, maxBytes)
	var bodyBuf bytes.Buffer
	_, _ = io.Copy(&bodyBuf, limitedReader)

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	return ExecutionResult{
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
		Headers:    respHeaders,
		Body:       bodyBuf.String(),
		Duration:   time.Since(start),
	}
}

// RequestCount returns total number of requests dispatched.
func (e *SafeExecutor) RequestCount() int64 {
	return atomic.LoadInt64(&e.requestCount)
}
