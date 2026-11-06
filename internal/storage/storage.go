package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stateweaver/stateweaver/internal/collector"
	"github.com/stateweaver/stateweaver/internal/validator"
	_ "modernc.org/sqlite"
)

// Storage handles persistent state in SQLite.
type Storage struct {
	db *sql.DB
}

// Open initializes SQLite database and runs migrations.
func Open(dbPath string) (*Storage, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create db directory %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database %q: %w", dbPath, err)
	}

	s := &Storage{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return s, nil
}

// Close closes the database handle.
func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scopes (
		target TEXT PRIMARY KEY,
		added_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS imported_records (
		id TEXT PRIMARY KEY,
		method TEXT NOT NULL,
		original_url TEXT NOT NULL,
		normalized_template TEXT NOT NULL,
		request_headers_json TEXT,
		query_params_json TEXT,
		request_body TEXT,
		path_params_json TEXT,
		entities_json TEXT,
		response_status INTEGER,
		response_headers_json TEXT,
		response_body TEXT,
		sensitive_fields_json TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS test_runs (
		id TEXT PRIMARY KEY,
		started_at DATETIME NOT NULL,
		completed_at DATETIME,
		total_tests INTEGER DEFAULT 0,
		executed_tests INTEGER DEFAULT 0,
		findings_count INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		test_run_id TEXT NOT NULL,
		category TEXT NOT NULL,
		severity TEXT NOT NULL,
		endpoint TEXT NOT NULL,
		http_method TEXT NOT NULL,
		affected_identity TEXT NOT NULL,
		resource TEXT NOT NULL,
		expected TEXT NOT NULL,
		observed TEXT NOT NULL,
		confidence TEXT NOT NULL,
		validation_status TEXT NOT NULL,
		evidence_json TEXT,
		reproduction TEXT,
		remediation TEXT,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (test_run_id) REFERENCES test_runs(id) ON DELETE CASCADE
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

// SaveScope stores an allowed scope target.
func (s *Storage) SaveScope(target string) error {
	query := `INSERT OR REPLACE INTO scopes (target, added_at) VALUES (?, ?)`
	_, err := s.db.Exec(query, target, time.Now().UTC())
	return err
}

// GetScopes retrieves all stored scope targets.
func (s *Storage) GetScopes() ([]string, error) {
	rows, err := s.db.Query(`SELECT target FROM scopes ORDER BY added_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// DeleteScope removes a target from the scope.
func (s *Storage) DeleteScope(target string) error {
	_, err := s.db.Exec(`DELETE FROM scopes WHERE target = ?`, target)
	return err
}

// SaveImportedRecords stores normalized traffic records.
func (s *Storage) SaveImportedRecords(records []collector.NormalizedRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO imported_records (
			id, method, original_url, normalized_template, request_headers_json,
			query_params_json, request_body, path_params_json, entities_json,
			response_status, response_headers_json, response_body, sensitive_fields_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range records {
		reqH, _ := json.Marshal(r.RequestHeaders)
		qP, _ := json.Marshal(r.QueryParams)
		pP, _ := json.Marshal(r.PathParams)
		ent, _ := json.Marshal(r.ExtractedEntities)
		respH, _ := json.Marshal(r.ResponseHeaders)
		sens, _ := json.Marshal(r.SensitiveFields)

		ts := r.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}

		_, err := stmt.Exec(
			r.ID, r.Method, r.OriginalURL, r.NormalizedTemplate, string(reqH),
			string(qP), r.RequestBody, string(pP), string(ent),
			r.ResponseStatus, string(respH), r.ResponseBody, string(sens), ts,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetImportedRecords retrieves all imported records.
func (s *Storage) GetImportedRecords() ([]collector.NormalizedRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, method, original_url, normalized_template, request_headers_json,
		       query_params_json, request_body, path_params_json, entities_json,
		       response_status, response_headers_json, response_body, sensitive_fields_json, created_at
		FROM imported_records
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []collector.NormalizedRecord
	for rows.Next() {
		var r collector.NormalizedRecord
		var reqH, qP, pP, ent, respH, sens string

		err := rows.Scan(
			&r.ID, &r.Method, &r.OriginalURL, &r.NormalizedTemplate, &reqH,
			&qP, &r.RequestBody, &pP, &ent,
			&r.ResponseStatus, &respH, &r.ResponseBody, &sens, &r.Timestamp,
		)
		if err != nil {
			return nil, err
		}

		_ = json.Unmarshal([]byte(reqH), &r.RequestHeaders)
		_ = json.Unmarshal([]byte(qP), &r.QueryParams)
		_ = json.Unmarshal([]byte(pP), &r.PathParams)
		_ = json.Unmarshal([]byte(ent), &r.ExtractedEntities)
		_ = json.Unmarshal([]byte(respH), &r.ResponseHeaders)
		_ = json.Unmarshal([]byte(sens), &r.SensitiveFields)

		records = append(records, r)
	}

	return records, nil
}

// CreateTestRun records the start of a test run.
func (s *Storage) CreateTestRun(id string) error {
	query := `INSERT INTO test_runs (id, started_at) VALUES (?, ?)`
	_, err := s.db.Exec(query, id, time.Now().UTC())
	return err
}

// CompleteTestRun finalizes a test run record.
func (s *Storage) CompleteTestRun(id string, total, executed, findingsCount int) error {
	query := `
		UPDATE test_runs
		SET completed_at = ?, total_tests = ?, executed_tests = ?, findings_count = ?
		WHERE id = ?
	`
	_, err := s.db.Exec(query, time.Now().UTC(), total, executed, findingsCount, id)
	return err
}

// SaveFindings stores findings associated with a test run.
func (s *Storage) SaveFindings(testRunID string, findings []*validator.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO findings (
			id, test_run_id, category, severity, endpoint, http_method,
			affected_identity, resource, expected, observed, confidence,
			validation_status, evidence_json, reproduction, remediation, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		evJSON, _ := json.Marshal(f.Evidence)
		ts := f.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}

		_, err := stmt.Exec(
			f.ID, testRunID, f.Category, f.Severity, f.Endpoint, f.HTTPMethod,
			f.AffectedIdentity, f.Resource, f.ExpectedBehavior, f.ObservedBehavior,
			string(f.Confidence), string(f.ValidationStatus), string(evJSON),
			f.Reproduction, f.Remediation, ts,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetFindings retrieves all findings (optionally filtered by test run).
func (s *Storage) GetFindings(testRunID string) ([]*validator.Finding, error) {
	query := `
		SELECT id, category, severity, endpoint, http_method,
		       affected_identity, resource, expected, observed, confidence,
		       validation_status, evidence_json, reproduction, remediation, created_at
		FROM findings
	`
	var args []interface{}
	if testRunID != "" {
		query += ` WHERE test_run_id = ?`
		args = append(args, testRunID)
	}
	query += ` ORDER BY created_at ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*validator.Finding
	for rows.Next() {
		var f validator.Finding
		var evJSON, conf, status string

		err := rows.Scan(
			&f.ID, &f.Category, &f.Severity, &f.Endpoint, &f.HTTPMethod,
			&f.AffectedIdentity, &f.Resource, &f.ExpectedBehavior, &f.ObservedBehavior,
			&conf, &status, &evJSON, &f.Reproduction, &f.Remediation, &f.Timestamp,
		)
		if err != nil {
			return nil, err
		}

		f.Confidence = validator.ConfidenceLevel(conf)
		f.ValidationStatus = validator.ValidationStatus(status)
		_ = json.Unmarshal([]byte(evJSON), &f.Evidence)

		findings = append(findings, &f)
	}

	return findings, nil
}

