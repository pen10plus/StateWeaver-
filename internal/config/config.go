package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration for StateWeaver.
type Config struct {
	Version      string        `yaml:"version"`
	ProjectName  string        `yaml:"project_name"`
	Scope        ScopeConfig   `yaml:"scope"`
	Execution    Execution     `yaml:"execution"`
	Paths        PathsConfig   `yaml:"paths"`
	Redaction    Redaction     `yaml:"redaction"`
	PoliciesFile string        `yaml:"policies_file"`
	Identities   string        `yaml:"identities_file"`
}

// ScopeConfig defines the target scope boundaries.
type ScopeConfig struct {
	AllowedHosts  []string `yaml:"allowed_hosts"`
	LocalhostOnly bool     `yaml:"localhost_only"`
	AllowedPorts  []int    `yaml:"allowed_ports"`
}

// Execution defines safe execution boundaries and rate limits.
type Execution struct {
	RateLimitRPS     int  `yaml:"rate_limit_rps"`      // Requests per second
	RequestBudget    int  `yaml:"request_budget"`     // Max total requests permitted per test run
	TimeoutSeconds   int  `yaml:"timeout_seconds"`    // Per-request timeout
	FollowRedirects  bool `yaml:"follow_redirects"`   // Restrict redirects to same origin
	MaxResponseBytes int  `yaml:"max_response_bytes"` // Max response body size to read
	ReadOnly         bool `yaml:"read_only"`          // Only safe methods (GET, HEAD, OPTIONS)
	StopOnError      bool `yaml:"stop_on_error"`      // Abort test run on consecutive errors
	MaxRetries       int  `yaml:"max_retries"`        // Safe retry count
}

// PathsConfig contains paths for database, artifacts, and export locations.
type PathsConfig struct {
	DatabasePath string `yaml:"database_path"`
	ReportsDir   string `yaml:"reports_dir"`
	GraphsDir    string `yaml:"graphs_dir"`
}

// Redaction defines sensitive patterns to scrub from logs and reports.
type Redaction struct {
	SensitiveHeaders []string `yaml:"sensitive_headers"`
	SensitiveKeys    []string `yaml:"sensitive_keys"`
	MaskValue        string   `yaml:"mask_value"`
}

// DefaultConfig returns safe, production-grade defaults.
func DefaultConfig() *Config {
	return &Config{
		Version:     "1.0",
		ProjectName: "stateweaver-project",
		Scope: ScopeConfig{
			AllowedHosts:  []string{"localhost", "127.0.0.1", "::1"},
			LocalhostOnly: true,
			AllowedPorts:  []int{8080, 8081, 8000, 3000, 5000},
		},
		Execution: Execution{
			RateLimitRPS:     5,
			RequestBudget:    200,
			TimeoutSeconds:   5,
			FollowRedirects:  false,
			MaxResponseBytes: 2 * 1024 * 1024, // 2MB
			ReadOnly:         true,
			StopOnError:      false,
			MaxRetries:       2,
		},
		Paths: PathsConfig{
			DatabasePath: ".stateweaver/stateweaver.db",
			ReportsDir:   "reports",
			GraphsDir:    "graphs",
		},
		Redaction: Redaction{
			SensitiveHeaders: []string{
				"authorization",
				"cookie",
				"set-cookie",
				"x-api-key",
				"x-auth-token",
				"proxy-authorization",
			},
			SensitiveKeys: []string{
				"password",
				"token",
				"secret",
				"api_key",
				"access_token",
				"refresh_token",
				"session_id",
				"credit_card",
				"cvv",
				"private_key",
			},
			MaskValue: "[REDACTED]",
		},
		PoliciesFile: "policies.yaml",
		Identities:   "identities.yaml",
	}
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}

	return cfg, nil
}

// Save writes configuration to a YAML file, creating parent directories if needed.
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create config directory %q: %w", dir, err)
		}
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config to %q: %w", path, err)
	}

	return nil
}

// IsHeaderSensitive returns true if the header name matches sensitive patterns.
func (c *Config) IsHeaderSensitive(headerName string) bool {
	lower := strings.ToLower(strings.TrimSpace(headerName))
	for _, h := range c.Redaction.SensitiveHeaders {
		if strings.ToLower(h) == lower {
			return true
		}
	}
	return false
}

// IsKeySensitive returns true if a key name matches sensitive patterns.
func (c *Config) IsKeySensitive(keyName string) bool {
	lower := strings.ToLower(strings.TrimSpace(keyName))
	for _, k := range c.Redaction.SensitiveKeys {
		if strings.Contains(lower, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

