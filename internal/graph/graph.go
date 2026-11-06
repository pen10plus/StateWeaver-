package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/stateweaver/stateweaver/internal/collector"
)

// Provenance tracks whether a relationship was directly observed or inferred.
type Provenance string

const (
	ProvenanceObserved Provenance = "Observed"
	ProvenanceInferred Provenance = "Inferred"
)

// EntityNode represents an entity in the application model (User, Tenant, Project, etc.).
type EntityNode struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // e.g. "user", "organization", "project", "role"
	Label      string                 `json:"label"`
	Provenance Provenance             `json:"provenance"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// RelationshipEdge represents a directed association between two entities.
type RelationshipEdge struct {
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Relation   string                 `json:"relation"` // e.g. "OWNER", "VIEWER", "BELONGS_TO", "MEMBER"
	Provenance Provenance             `json:"provenance"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// RelationshipGraph captures entities and their authorization/ownership relationships.
type RelationshipGraph struct {
	Nodes map[string]EntityNode      `json:"nodes"`
	Edges []RelationshipEdge         `json:"edges"`
}

// NewRelationshipGraph initializes an empty RelationshipGraph.
func NewRelationshipGraph() *RelationshipGraph {
	return &RelationshipGraph{
		Nodes: make(map[string]EntityNode),
		Edges: make([]RelationshipEdge, 0),
	}
}

// AddNode adds or updates an entity node.
func (g *RelationshipGraph) AddNode(node EntityNode) {
	if node.Metadata == nil {
		node.Metadata = make(map[string]interface{})
	}
	g.Nodes[node.ID] = node
}

// AddEdge adds a directed relationship edge.
func (g *RelationshipGraph) AddEdge(edge RelationshipEdge) {
	if edge.Metadata == nil {
		edge.Metadata = make(map[string]interface{})
	}
	// Avoid duplicates
	for _, e := range g.Edges {
		if e.Source == edge.Source && e.Target == edge.Target && e.Relation == edge.Relation {
			return
		}
	}
	g.Edges = append(g.Edges, edge)
}

// ExportDOT renders the RelationshipGraph as a Graphviz DOT script.
func (g *RelationshipGraph) ExportDOT() string {
	var sb strings.Builder
	sb.WriteString("digraph RelationshipGraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=rounded, fontname=\"Helvetica\"];\n")
	sb.WriteString("  edge [fontname=\"Helvetica\", fontsize=10];\n\n")

	// Sort nodes for deterministic output
	nodeIDs := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	for _, id := range nodeIDs {
		n := g.Nodes[id]
		color := "#2b5797"
		if n.Provenance == ProvenanceInferred {
			color = "#b9770e"
		}
		sb.WriteString(fmt.Sprintf("  %q [label=%q, color=%q];\n", n.ID, fmt.Sprintf("%s\\n(%s)", n.Label, n.Type), color))
	}

	sb.WriteString("\n")
	for _, e := range g.Edges {
		style := "solid"
		if e.Provenance == ProvenanceInferred {
			style = "dashed"
		}
		sb.WriteString(fmt.Sprintf("  %q -> %q [label=%q, style=%q];\n", e.Source, e.Target, e.Relation, style))
	}

	sb.WriteString("}\n")
	return sb.String()
}

// ExportJSON serializes the relationship graph to JSON.
func (g *RelationshipGraph) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(g, "", "  ")
}

// WorkflowNode represents an observed API operation state.
type WorkflowNode struct {
	ID          string     `json:"id"`
	Method      string     `json:"method"`
	Template    string     `json:"template"`
	Description string     `json:"description"`
	Provenance  Provenance `json:"provenance"`
}

// WorkflowEdge represents a transition or dependency between two operations.
type WorkflowEdge struct {
	Source         string     `json:"source"`
	Target         string     `json:"target"`
	TransitionType string     `json:"transition_type"` // e.g. "Sequence", "DataDependency"
	DependencyKey  string     `json:"dependency_key,omitempty"`
	Provenance     Provenance `json:"provenance"`
}

// WorkflowGraph models the lifecycle sequence and data dependencies of API calls.
type WorkflowGraph struct {
	Nodes []WorkflowNode `json:"nodes"`
	Edges []WorkflowEdge `json:"edges"`
}

// NewWorkflowGraph initializes an empty WorkflowGraph.
func NewWorkflowGraph() *WorkflowGraph {
	return &WorkflowGraph{
		Nodes: make([]WorkflowNode, 0),
		Edges: make([]WorkflowEdge, 0),
	}
}

// BuildFromRecords analyzes recorded HTTP traffic to build the workflow graph.
func (w *WorkflowGraph) BuildFromRecords(records []collector.NormalizedRecord) {
	if len(records) == 0 {
		return
	}

	nodeMap := make(map[string]WorkflowNode)
	var orderedNodes []string

	// Track created entities (e.g. POST /api/projects -> project_id)
	createdEntities := make(map[string]string) // entityName -> nodeID

	for i, rec := range records {
		nodeID := fmt.Sprintf("step_%d_%s_%s", i+1, rec.Method, sanitizeNodeID(rec.NormalizedTemplate))
		desc := fmt.Sprintf("%s %s", rec.Method, rec.NormalizedTemplate)

		wNode := WorkflowNode{
			ID:          nodeID,
			Method:      rec.Method,
			Template:    rec.NormalizedTemplate,
			Description: desc,
			Provenance:  ProvenanceObserved,
		}

		if _, exists := nodeMap[nodeID]; !exists {
			nodeMap[nodeID] = wNode
			w.Nodes = append(w.Nodes, wNode)
			orderedNodes = append(orderedNodes, nodeID)
		}

		// Connect sequential operations
		if i > 0 {
			prevID := orderedNodes[i-1]
			w.Edges = append(w.Edges, WorkflowEdge{
				Source:         prevID,
				Target:         nodeID,
				TransitionType: "Sequence",
				Provenance:     ProvenanceObserved,
			})
		}

		// Data dependency heuristic:
		// If rec is POST, record created entities
		if rec.Method == "POST" {
			for entityName := range rec.ExtractedEntities {
				createdEntities[entityName] = nodeID
			}
		}

		// If current operation uses path parameter previously created, add DataDependency edge
		for entityName := range rec.ExtractedEntities {
			if creatorID, found := createdEntities[entityName]; found && creatorID != nodeID {
				w.Edges = append(w.Edges, WorkflowEdge{
					Source:         creatorID,
					Target:         nodeID,
					TransitionType: "DataDependency",
					DependencyKey:  entityName,
					Provenance:     ProvenanceInferred,
				})
			}
		}
	}
}

// ExportDOT renders WorkflowGraph in Graphviz DOT format.
func (w *WorkflowGraph) ExportDOT() string {
	var sb strings.Builder
	sb.WriteString("digraph WorkflowGraph {\n")
	sb.WriteString("  rankdir=TB;\n")
	sb.WriteString("  node [shape=rectangle, style=\"rounded,filled\", fillcolor=\"#f0f4f8\", fontname=\"Helvetica\"];\n")
	sb.WriteString("  edge [fontname=\"Helvetica\", fontsize=9];\n\n")

	for _, n := range w.Nodes {
		fill := "#e8f4f8"
		if n.Method == "DELETE" {
			fill = "#fce8e6"
		} else if n.Method == "POST" {
			fill = "#e6f4ea"
		}
		sb.WriteString(fmt.Sprintf("  %q [label=%q, fillcolor=%q];\n", n.ID, n.Description, fill))
	}

	sb.WriteString("\n")
	for _, e := range w.Edges {
		style := "solid"
		color := "#333333"
		label := e.TransitionType
		if e.TransitionType == "DataDependency" {
			style = "dashed"
			color = "#1a73e8"
			label = fmt.Sprintf("depends on %s", e.DependencyKey)
		}
		sb.WriteString(fmt.Sprintf("  %q -> %q [label=%q, style=%q, color=%q];\n", e.Source, e.Target, label, style, color))
	}

	sb.WriteString("}\n")
	return sb.String()
}

// ExportJSON serializes the workflow graph to JSON.
func (w *WorkflowGraph) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(w, "", "  ")
}

func sanitizeNodeID(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")
	s = strings.ReplaceAll(s, "-", "_")
	return strings.Trim(s, "_")
}

