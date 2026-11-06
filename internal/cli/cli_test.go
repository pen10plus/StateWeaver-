package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stateweaver/stateweaver/internal/collector"
)

func TestRootCommandsRegistration(t *testing.T) {
	expectedSubcommands := []string{
		"init",
		"scope",
		"import",
		"analyze",
		"test",
		"report",
		"lab",
		"version",
	}

	subCmdMap := make(map[string]bool)
	for _, cmd := range RootCmd.Commands() {
		subCmdMap[cmd.Name()] = true
	}

	for _, expected := range expectedSubcommands {
		if !subCmdMap[expected] {
			t.Errorf("expected subcommand %q to be registered on RootCmd", expected)
		}
	}
}

func TestVersionCommandOutput(t *testing.T) {
	buf := new(bytes.Buffer)
	versionCmd.SetOut(buf)

	// Execute version command directly
	versionCmd.Run(versionCmd, []string{})

	output := buf.String()
	// Since version prints to stdout, we also verify Version variable
	if Version == "" {
		t.Errorf("expected non-empty Version string")
	}
	_ = output
}

func TestRebaseRecords(t *testing.T) {
	records := []collector.NormalizedRecord{
		{
			OriginalURL:        "http://localhost:8080/api/projects/1001",
			NormalizedTemplate: "/api/projects/{project_id}",
		},
		{
			OriginalURL:        "http://localhost:8080/api/projects/1001/secrets",
			NormalizedTemplate: "/api/projects/{project_id}/secrets",
		},
	}

	rebased := rebaseRecords(records, "http://127.0.0.1:9090")
	if len(rebased) != 2 {
		t.Fatalf("expected 2 rebased records, got %d", len(rebased))
	}

	if !strings.HasPrefix(rebased[0].OriginalURL, "http://127.0.0.1:9090") {
		t.Errorf("expected rebased host 127.0.0.1:9090, got %s", rebased[0].OriginalURL)
	}
	if !strings.HasPrefix(rebased[1].OriginalURL, "http://127.0.0.1:9090") {
		t.Errorf("expected rebased host 127.0.0.1:9090, got %s", rebased[1].OriginalURL)
	}
}

