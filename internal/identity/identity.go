package identity

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var envVarRegex = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)

// AuthType defines supported authentication types.
type AuthType string

const (
	AuthTypeBearer AuthType = "bearer"
	AuthTypeHeader AuthType = "header"
	AuthTypeCookie AuthType = "cookie"
	AuthTypeBasic  AuthType = "basic"
	AuthTypeNone   AuthType = "none"
)

// Identity represents a test actor profile with specific permissions and tenant affiliation.
type Identity struct {
	ID        string            `yaml:"id"`
	Name      string            `yaml:"name"`
	Role      string            `yaml:"role"`
	TenantID  string            `yaml:"tenant_id"`
	UserID    string            `yaml:"user_id"`
	AuthType  AuthType          `yaml:"auth_type"`
	Token     string            `yaml:"token"`       // Can be raw token or ${ENV_VAR}
	Username  string            `yaml:"username"`    // For basic auth
	Password  string            `yaml:"password"`    // For basic auth (${ENV_VAR} supported)
	Headers   map[string]string `yaml:"headers"`     // Additional headers (e.g. X-Tenant-ID)
	Cookies   map[string]string `yaml:"cookies"`     // Specific cookies
	IsRevoked bool              `yaml:"is_revoked"`  // True if testing revoked/expired session
}

// Config wraps a collection of identities loaded from file.
type Config struct {
	Identities []Identity `yaml:"identities"`
}

// Manager stores and manages identities.
type Manager struct {
	profiles map[string]*Identity
}

// NewManager creates an Identity Manager from a slice of Identities.
func NewManager(identities []Identity) *Manager {
	mgr := &Manager{
		profiles: make(map[string]*Identity),
	}
	for i := range identities {
		mgr.profiles[identities[i].ID] = &identities[i]
	}
	return mgr
}

// Load loads identities from a YAML file.
func Load(path string) (*Manager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read identities file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse identities file %q: %w", path, err)
	}

	return NewManager(cfg.Identities), nil
}

// Save writes identities to a YAML file.
func Save(path string, identities []Identity) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", dir, err)
		}
	}

	cfg := Config{Identities: identities}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal identities: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// Get returns an identity by ID.
func (m *Manager) Get(id string) (*Identity, bool) {
	idObj, ok := m.profiles[id]
	return idObj, ok
}

// All returns all registered identities.
func (m *Manager) All() []*Identity {
	list := make([]*Identity, 0, len(m.profiles))
	for _, idObj := range m.profiles {
		list = append(list, idObj)
	}
	return list
}

// ByRole returns identities matching a specific role.
func (m *Manager) ByRole(role string) []*Identity {
	var matched []*Identity
	roleLower := strings.ToLower(role)
	for _, idObj := range m.profiles {
		if strings.ToLower(idObj.Role) == roleLower {
			matched = append(matched, idObj)
		}
	}
	return matched
}

// ByTenant returns identities belonging to a specific tenant.
func (m *Manager) ByTenant(tenantID string) []*Identity {
	var matched []*Identity
	for _, idObj := range m.profiles {
		if idObj.TenantID == tenantID {
			matched = append(matched, idObj)
		}
	}
	return matched
}

// ResolveSecret resolves ${ENV_VAR} placeholders or returns the raw string.
func ResolveSecret(val string) string {
	return envVarRegex.ReplaceAllStringFunc(val, func(m string) string {
		varName := m[2 : len(m)-1]
		if envVal, ok := os.LookupEnv(varName); ok {
			return envVal
		}
		return m // Return unchanged if not found in environment
	})
}

// RedactedSecret returns a masked representation of a secret (e.g. "eyJh...d9a" or "[REDACTED]").
func RedactedSecret(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) <= 8 {
		return "[REDACTED]"
	}
	return fmt.Sprintf("%s...%s", trimmed[:4], trimmed[len(trimmed)-4:])
}

// ApplyAuth applies authentication headers/cookies to an outgoing HTTP request.
func (id *Identity) ApplyAuth(req *http.Request) {
	if id == nil {
		return
	}

	switch id.AuthType {
	case AuthTypeBearer:
		token := ResolveSecret(id.Token)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case AuthTypeBasic:
		username := ResolveSecret(id.Username)
		password := ResolveSecret(id.Password)
		auth := username + ":" + password
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	case AuthTypeHeader:
		token := ResolveSecret(id.Token)
		if token != "" {
			req.Header.Set("X-API-Key", token)
		}
	case AuthTypeCookie:
		token := ResolveSecret(id.Token)
		if token != "" {
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: token,
			})
		}
	case AuthTypeNone:
		// Do not set credentials
	}

	// Apply custom headers (e.g. X-Tenant-ID)
	for k, v := range id.Headers {
		req.Header.Set(k, ResolveSecret(v))
	}

	// Apply custom cookies
	for k, v := range id.Cookies {
		req.AddCookie(&http.Cookie{
			Name:  k,
			Value: ResolveSecret(v),
		})
	}
}

// DefaultSampleIdentities returns standard sample identities for testing and lab usage.
func DefaultSampleIdentities() []Identity {
	return []Identity{
		{
			ID:       "alice",
			Name:     "Alice (Owner)",
			Role:     "owner",
			TenantID: "org-a",
			UserID:   "user-101",
			AuthType: AuthTypeBearer,
			Token:    "token-alice-org-a-owner",
		},
		{
			ID:       "bob",
			Name:     "Bob (Viewer)",
			Role:     "viewer",
			TenantID: "org-a",
			UserID:   "user-102",
			AuthType: AuthTypeBearer,
			Token:    "token-bob-org-a-viewer",
		},
		{
			ID:       "charlie",
			Name:     "Charlie (Member Org-B)",
			Role:     "member",
			TenantID: "org-b",
			UserID:   "user-201",
			AuthType: AuthTypeBearer,
			Token:    "token-charlie-org-b-member",
		},
		{
			ID:        "dave",
			Name:      "Dave (Revoked Member)",
			Role:      "member",
			TenantID:  "org-a",
			UserID:    "user-103",
			AuthType:  AuthTypeBearer,
			Token:     "token-dave-org-a-revoked",
			IsRevoked: true,
		},
		{
			ID:       "anonymous",
			Name:     "Anonymous User",
			Role:     "anonymous",
			TenantID: "",
			UserID:   "",
			AuthType: AuthTypeNone,
		},
	}
}

