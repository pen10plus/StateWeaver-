package graph

import (
	"strings"
	"testing"

	"github.com/stateweaver/stateweaver/internal/collector"
)

func TestRelationshipGraph(t *testing.T) {
	rg := NewRelationshipGraph()
	rg.AddNode(EntityNode{
		ID:         "user:alice",
		Type:       "user",
		Label:      "Alice",
		Provenance: ProvenanceObserved,
	})
	rg.AddNode(EntityNode{
		ID:         "project:1001",
		Type:       "project",
		Label:      "Project 1001",
		Provenance: ProvenanceObserved,
	})
	rg.AddEdge(RelationshipEdge{
		Source:     "user:alice",
		Target:     "project:1001",
		Relation:   "OWNER",
		Provenance: ProvenanceObserved,
	})

	dot := rg.ExportDOT()
	if !strings.Contains(dot, "\"user:alice\" -> \"project:1001\"") {
		t.Errorf("expected DOT to contain edge, got:\n%s", dot)
	}
	if !strings.Contains(dot, "label=\"OWNER\"") {
		t.Errorf("expected DOT to contain OWNER label")
	}

	jsonBytes, err := rg.ExportJSON()
	if err != nil {
		t.Fatalf("failed to export JSON: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "user:alice") {
		t.Errorf("expected JSON to contain user:alice")
	}
}

func TestWorkflowGraph(t *testing.T) {
	records := []collector.NormalizedRecord{
		{
			Method:             "POST",
			NormalizedTemplate: "/api/projects",
			ExtractedEntities:  map[string]string{"project": "1001"},
		},
		{
			Method:             "GET",
			NormalizedTemplate: "/api/projects/{project_id}",
			ExtractedEntities:  map[string]string{"project": "1001"},
		},
		{
			Method:             "DELETE",
			NormalizedTemplate: "/api/projects/{project_id}",
			ExtractedEntities:  map[string]string{"project": "1001"},
		},
	}

	wg := NewWorkflowGraph()
	wg.BuildFromRecords(records)

	if len(wg.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(wg.Nodes))
	}

	// Should have 2 sequence edges + 2 data dependency edges
	if len(wg.Edges) < 2 {
		t.Errorf("expected at least 2 edges, got %d", len(wg.Edges))
	}

	dot := wg.ExportDOT()
	if !strings.Contains(dot, "depends on project") {
		t.Errorf("expected DOT to include data dependency edge, got:\n%s", dot)
	}
}

