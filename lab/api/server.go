package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// User represents a lab user.
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TenantID  string `json:"tenant_id"`
	IsRevoked bool   `json:"is_revoked"`
	Token     string `json:"token"`
}

// Project represents a project entity.
type Project struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TenantID    string   `json:"tenant_id"`
	OwnerID     string   `json:"owner_id"`
	Members     []string `json:"members"`
	Secrets     string   `json:"secrets,omitempty"`
}

// LabServer serves either the vulnerable or secure version of the API.
type LabServer struct {
	IsSecure    bool
	Port        int
	server      *http.Server
	listener    net.Listener
	mu          sync.RWMutex
	users       map[string]User      // token -> User
	projects    map[int64]Project    // id -> Project
	revocations map[string]struct{} // revoked tokens
}

// NewLabServer initializes a lab server with seed data.
func NewLabServer(port int, isSecure bool) *LabServer {
	s := &LabServer{
		IsSecure:    isSecure,
		Port:        port,
		users:       make(map[string]User),
		projects:    make(map[int64]Project),
		revocations: make(map[string]struct{}),
	}
	s.seedData()
	return s
}

func (s *LabServer) seedData() {
	// Seed users
	uAlice := User{ID: "user-101", Username: "alice", Role: "owner", TenantID: "org-a", Token: "token-alice-org-a-owner"}
	uBob := User{ID: "user-102", Username: "bob", Role: "viewer", TenantID: "org-a", Token: "token-bob-org-a-viewer"}
	uCharlie := User{ID: "user-201", Username: "charlie", Role: "member", TenantID: "org-b", Token: "token-charlie-org-b-member"}
	uDave := User{ID: "user-103", Username: "dave", Role: "member", TenantID: "org-a", IsRevoked: true, Token: "token-dave-org-a-revoked"}

	s.users[uAlice.Token] = uAlice
	s.users[uBob.Token] = uBob
	s.users[uCharlie.Token] = uCharlie
	s.users[uDave.Token] = uDave
	s.revocations[uDave.Token] = struct{}{}

	// Seed projects
	s.projects[1001] = Project{
		ID:          1001,
		Name:        "Project Titan",
		Description: "Acme core enterprise platform",
		TenantID:    "org-a",
		OwnerID:     "user-101",
		Members:     []string{"user-101", "user-102"},
		Secrets:     "API_KEY=prod-secret-key-titan-998811",
	}
	s.projects[1002] = Project{
		ID:          1002,
		Name:        "Project Atlas",
		Description: "Acme infrastructure telemetry",
		TenantID:    "org-a",
		OwnerID:     "user-101",
		Members:     []string{"user-101"},
		Secrets:     "DB_PASS=super-confidential-atlas-pass",
	}
	s.projects[2001] = Project{
		ID:          2001,
		Name:        "Project Phoenix",
		Description: "Beta Inc next-generation app",
		TenantID:    "org-b",
		OwnerID:     "user-201",
		Members:     []string{"user-201"},
		Secrets:     "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
	}
}

// Router builds http.Handler for the lab API.
func (s *LabServer) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := "vulnerable"
		if s.IsSecure {
			status = "secure"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"mode":     status,
			"isSecure": s.IsSecure,
			"time":     time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/projects/", s.handleProjectByID)

	return mux
}

// authenticate extracts user from Authorization header.
func (s *LabServer) authenticate(r *http.Request) (*User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[token]
	if !exists {
		return nil, fmt.Errorf("unknown token")
	}

	// SECURE CHECK: verify revocation status
	if s.IsSecure {
		if _, isRevoked := s.revocations[token]; isRevoked || user.IsRevoked {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	return &user, nil
}

func (s *LabServer) handleProjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user *User
	var err error

	if s.IsSecure {
		user, err = s.authenticate(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	} else {
		// Vulnerable API: if auth provided, extract it; if missing/invalid, allow anonymous access!
		user, err = s.authenticate(r)
		if err != nil {
			// Vulnerability 5: Missing authentication check allows anonymous enumeration
			user = &User{ID: "anon", Username: "anonymous", Role: "anonymous", TenantID: "org-a"}
		}
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		defer s.mu.RUnlock()

		var results []Project
		for _, p := range s.projects {
			if s.IsSecure {
				// Secure: Only return projects belonging to user's tenant
				if p.TenantID == user.TenantID {
					pClean := p
					pClean.Secrets = "" // Redact secrets on general list
					results = append(results, pClean)
				}
			} else {
				// Vulnerable: Returns all projects across all tenants (Cross-Tenant Leakage)
				results = append(results, p)
			}
		}
		json.NewEncoder(w).Encode(results)

	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid json"})
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		newID := int64(1000 + len(s.projects) + 1)
		proj := Project{
			ID:          newID,
			Name:        req.Name,
			Description: req.Description,
			TenantID:    user.TenantID,
			OwnerID:     user.ID,
			Members:     []string{user.ID},
		}
		s.projects[newID] = proj

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(proj)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *LabServer) handleProjectByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user *User
	var err error

	if s.IsSecure {
		user, err = s.authenticate(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	} else {
		// Vulnerable API: unauthenticated requests on project endpoints are accepted
		user, err = s.authenticate(r)
		if err != nil {
			user = &User{ID: "anon", Username: "anonymous", Role: "anonymous", TenantID: "org-a"}
		}
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/projects/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "project ID required"})
		return
	}

	projectID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid project ID"})
		return
	}

	subResource := ""
	if len(parts) > 1 {
		subResource = parts[1]
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	project, exists := s.projects[projectID]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "project not found"})
		return
	}

	// ================= AUTHORIZATION CHECKS =================
	if s.IsSecure {
		// 1. Cross-Tenant check: user must belong to project's tenant
		if project.TenantID != user.TenantID {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "project not found"})
			return
		}

		// 2. Subresource secrets check: only owner or admin can read secrets
		if subResource == "secrets" {
			if user.Role != "owner" && user.Role != "admin" {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "insufficient permissions to access project secrets"})
				return
			}
		}

		// 3. Mutation authorization check: viewer cannot DELETE or mutate project
		if r.Method == http.MethodDelete || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if user.Role == "viewer" {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "viewers are not permitted to mutate or delete projects"})
				return
			}
			if project.OwnerID != user.ID && user.Role != "admin" {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "only project owner can delete project"})
				return
			}
		}
	} else {
		// ================= VULNERABLE IMPLEMENTATION =================
		// Flaw 1 (Cross-Tenant): Charlie (org-b) can access Org-A project 1001!
		// Flaw 2 (Secrets): Bob (Viewer) can access /secrets!
		// Flaw 3 (Privilege Escalation): Bob (Viewer) can DELETE project 1001!
		// Flaw 4 (Revoked Member): Dave succeeds because token revocation is never checked!
		// Flaw 5 (Missing Auth): Anonymous requests return HTTP 200!
	}

	// Handle sub-resource: /secrets
	if subResource == "secrets" {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"project_id": project.ID,
				"name":       project.Name,
				"secrets":    project.Secrets,
			})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Handle root resource: /api/projects/{id}
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(project)

	case http.MethodDelete:
		delete(s.projects, projectID)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Start runs the HTTP server.
func (s *LabServer) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.server = &http.Server{
		Handler: s.Router(),
	}
	return s.server.Serve(ln)
}

// Stop terminates the server.
func (s *LabServer) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
