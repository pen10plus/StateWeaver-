package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

var (
	ErrOutOfScope         = errors.New("target is out of configured scope")
	ErrExternalDisallowed = errors.New("external target disallowed by localhost-only policy")
	ErrInvalidTargetURL   = errors.New("invalid target URL format")
	ErrDisallowedPort     = errors.New("target port is not allowed by policy")
)

// TargetScope manages and validates target boundaries.
type TargetScope struct {
	mu            sync.RWMutex
	allowedHosts  map[string]struct{}
	allowedPorts  map[int]struct{}
	localhostOnly bool
	allowExternal bool // explicit CLI override
}

// New creates a new TargetScope instance.
func New(allowedHosts []string, allowedPorts []int, localhostOnly bool, allowExternal bool) *TargetScope {
	hosts := make(map[string]struct{})
	for _, h := range allowedHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	ports := make(map[int]struct{})
	for _, p := range allowedPorts {
		if p > 0 && p <= 65535 {
			ports[p] = struct{}{}
		}
	}

	return &TargetScope{
		allowedHosts:  hosts,
		allowedPorts:  ports,
		localhostOnly: localhostOnly,
		allowExternal: allowExternal,
	}
}

// AddHost adds a host or target to the allowed list.
func (s *TargetScope) AddHost(target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	host, _, err := parseTargetHostPort(target)
	if err != nil {
		return err
	}

	s.allowedHosts[strings.ToLower(host)] = struct{}{}
	return nil
}

// RemoveHost removes a host from the allowed list.
func (s *TargetScope) RemoveHost(target string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	host, _, err := parseTargetHostPort(target)
	if err == nil {
		delete(s.allowedHosts, strings.ToLower(host))
	} else {
		delete(s.allowedHosts, strings.ToLower(target))
	}
}

// AllowedHosts returns a list of allowed hosts.
func (s *TargetScope) AllowedHosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]string, 0, len(s.allowedHosts))
	for h := range s.allowedHosts {
		res = append(res, h)
	}
	return res
}

// AllowedPorts returns a list of allowed ports.
func (s *TargetScope) AllowedPorts() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]int, 0, len(s.allowedPorts))
	for p := range s.allowedPorts {
		res = append(res, p)
	}
	return res
}

// LocalhostOnly returns whether localhost-only mode is active.
func (s *TargetScope) LocalhostOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localhostOnly && !s.allowExternal
}

// ValidateTarget checks whether a URL or host:port is permitted by the scope.
func (s *TargetScope) ValidateTarget(rawURL string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	host, port, err := parseTargetHostPort(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTargetURL, err)
	}

	isLocal := isLocalhost(host)

	// Enforce Localhost-Only unless explicitly bypassed
	if s.localhostOnly && !s.allowExternal && !isLocal {
		return fmt.Errorf("%w: host %q is not localhost", ErrExternalDisallowed, host)
	}

	hostLower := strings.ToLower(host)

	// Check if host is permitted by allowedHosts list
	if len(s.allowedHosts) > 0 {
		matched := false
		if _, ok := s.allowedHosts[hostLower]; ok {
			matched = true
		} else {
			// Check wildcard subdomains
			for allowed := range s.allowedHosts {
				if strings.HasPrefix(allowed, "*.") {
					suffix := allowed[1:] // e.g. .example.com
					if strings.HasSuffix(hostLower, suffix) {
						matched = true
						break
					}
				}
			}
		}

		if !matched {
			return fmt.Errorf("%w: host %q is not in allowed target list", ErrOutOfScope, host)
		}
	} else {
		// When allowedHosts list is empty, only localhost is allowed unless allowExternal is explicitly granted
		if !isLocal && !s.allowExternal {
			return fmt.Errorf("%w: host %q is not in allowed target list", ErrOutOfScope, host)
		}
		// If an allowlist is completely empty, reject even custom hosts if they are not explicitly allowed
		if !isLocal && s.allowExternal && len(s.allowedHosts) == 0 {
			// Must have at least one explicit allowed host to prevent unbound arbitrary scanning
			return fmt.Errorf("%w: no allowed hosts defined in scope", ErrOutOfScope)
		}
	}

	// Check port if port restrictions are defined
	if len(s.allowedPorts) > 0 && port > 0 {
		if _, ok := s.allowedPorts[port]; !ok {
			return fmt.Errorf("%w: port %d is not in allowed port list", ErrDisallowedPort, port)
		}
	}

	return nil
}

func parseTargetHostPort(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, fmt.Errorf("target is empty")
	}

	// If no scheme, add http:// temporarily to parse with net/url
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", 0, err
	}

	host := parsed.Hostname()
	if host == "" {
		host = parsed.Path
	}
	if host == "" {
		return "", 0, fmt.Errorf("could not determine hostname")
	}

	port := 0
	portStr := parsed.Port()
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err == nil {
			port = p
		}
	} else {
		if parsed.Scheme == "https" {
			port = 443
		} else if parsed.Scheme == "http" {
			port = 80
		}
	}

	return host, port, nil
}

func isLocalhost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" {
		return true
	}
	ip := net.ParseIP(h)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}
