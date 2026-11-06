package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/stateweaver/stateweaver/internal/config"
	"github.com/stateweaver/stateweaver/internal/graph"
	"github.com/stateweaver/stateweaver/internal/identity"
	"github.com/stateweaver/stateweaver/internal/storage"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze traffic flows and construct relationship & workflow graphs",
	Long:  "Inspects stored HTTP transactions, maps entity relationships (Users, Tenants, Resources), derives operation workflow state transitions, and exports Graphviz DOT and JSON graphs.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			cfg = config.DefaultConfig()
		}

		store, err := storage.Open(cfg.Paths.DatabasePath)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer store.Close()

		records, err := store.GetImportedRecords()
		if err != nil {
			return fmt.Errorf("failed to load imported records: %w", err)
		}

		if len(records) == 0 {
			return fmt.Errorf("no imported records found. Run 'stateweaver import <file.har>' first")
		}

		fmt.Printf("[*] Analyzing %d imported transactions...\n", len(records))

		// 1. Build Relationship Graph
		relGraph := graph.NewRelationshipGraph()

		// Load identities to enrich entity graph
		if idMgr, err := identity.Load(cfg.Identities); err == nil {
			for _, idObj := range idMgr.All() {
				relGraph.AddNode(graph.EntityNode{
					ID:         "user:" + idObj.ID,
					Type:       "user",
					Label:      idObj.Name,
					Provenance: graph.ProvenanceObserved,
				})
				if idObj.TenantID != "" {
					relGraph.AddNode(graph.EntityNode{
						ID:         "tenant:" + idObj.TenantID,
						Type:       "organization",
						Label:      "Tenant " + idObj.TenantID,
						Provenance: graph.ProvenanceObserved,
					})
					relGraph.AddEdge(graph.RelationshipEdge{
						Source:     "user:" + idObj.ID,
						Target:     "tenant:" + idObj.TenantID,
						Relation:   "BELONGS_TO",
						Provenance: graph.ProvenanceObserved,
					})
				}
			}
		}

		// Extract entities and relationships from traffic records
		for _, rec := range records {
			for entityType, entityID := range rec.ExtractedEntities {
				nodeID := fmt.Sprintf("%s:%s", entityType, entityID)
				relGraph.AddNode(graph.EntityNode{
					ID:         nodeID,
					Type:       entityType,
					Label:      fmt.Sprintf("%s %s", entityType, entityID),
					Provenance: graph.ProvenanceObserved,
				})
			}
		}

		// 2. Build Workflow Graph
		wfGraph := graph.NewWorkflowGraph()
		wfGraph.BuildFromRecords(records)

		// 3. Export graphs
		graphsDir := cfg.Paths.GraphsDir
		_ = os.MkdirAll(graphsDir, 0750)

		relDotPath := filepath.Join(graphsDir, "relationship_graph.dot")
		relJSONPath := filepath.Join(graphsDir, "relationship_graph.json")
		wfDotPath := filepath.Join(graphsDir, "workflow_graph.dot")
		wfJSONPath := filepath.Join(graphsDir, "workflow_graph.json")

		_ = os.WriteFile(relDotPath, []byte(relGraph.ExportDOT()), 0644)
		if relJSON, err := relGraph.ExportJSON(); err == nil {
			_ = os.WriteFile(relJSONPath, relJSON, 0644)
		}

		_ = os.WriteFile(wfDotPath, []byte(wfGraph.ExportDOT()), 0644)
		if wfJSON, err := wfGraph.ExportJSON(); err == nil {
			_ = os.WriteFile(wfJSONPath, wfJSON, 0644)
		}

		fmt.Println("[✓] Traffic Analysis Complete!")
		fmt.Printf("    • Relationship Entities: %d | Edges: %d\n", len(relGraph.Nodes), len(relGraph.Edges))
		fmt.Printf("    • Workflow Operation Nodes: %d | Transitions: %d\n", len(wfGraph.Nodes), len(wfGraph.Edges))

		if len(wfGraph.Nodes) > 0 {
			fmt.Println("\nObserved Application Workflow Progression:")
			for idx, n := range wfGraph.Nodes {
				if idx == 0 {
					fmt.Printf("  [1] %s\n", n.Description)
				} else {
					fmt.Printf("       │\n       ▼\n  [%d] %s\n", idx+1, n.Description)
				}
			}
		}

		fmt.Printf("\nExported Visualizations:\n")
		fmt.Printf("    - DOT:  %s\n", relDotPath)
		fmt.Printf("    - JSON: %s\n", relJSONPath)
		fmt.Printf("    - DOT:  %s\n", wfDotPath)
		fmt.Printf("    - JSON: %s\n", wfJSONPath)

		return nil
	},
}

