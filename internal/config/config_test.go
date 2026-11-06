package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if !cfg.Scope.LocalhostOnly {
		t.Errorf("expected LocalhostOnly to be true by default")
	}
	if !cfg.Execution.ReadOnly {
		t.Errorf("expected ReadOnly to be true by default")
	}
	if cfg.Execution.RateLimitRPS <= 0 {
		t.Errorf("expected positive RateLimitRPS")
	}
	if !cfg.IsHeaderSensitive("Authorization") {
		t.Errorf("expected Authorization header to be sensitive")
	}
	if !cfg.IsKeySensitive("user_password") {
		t.Errorf("expected user_password key to be sensitive")
	}
}

func TestLoadAndSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "sub", "stateweaver.yaml")

	cfg := DefaultConfig()
	cfg.ProjectName = "test-project"
	cfg.Execution.RateLimitRPS = 10

	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loaded.ProjectName != "test-project" {
		t.Errorf("expected project name 'test-project', got %q", loaded.ProjectName)
	}
	if loaded.Execution.RateLimitRPS != 10 {
		t.Errorf("expected RateLimitRPS 10, got %d", loaded.Execution.RateLimitRPS)
	}
}

func TestLoadNonExistent(t *testing.T) {
	_, err := Load(filepath.Join(os.TempDir(), "non-existent-sw-config.yaml"))
	if err == nil {
		t.Errorf("expected error when loading non-existent file")
	}
}

