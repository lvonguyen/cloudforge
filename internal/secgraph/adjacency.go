package secgraph

import (
	"context"
	"database/sql"
	"fmt"
)

// AdjacencySet is an in-memory set of resource pairs that have an explicit
// relationship in the security graph. Used by the attack path BFS engine
// to replace heuristic co-location checks with evidence-based edge lookups.
type AdjacencySet struct {
	edges map[string]map[string]EdgeType // resourceID → {resourceID → edgeType}
}

// NewAdjacencySet creates an empty adjacency set.
func NewAdjacencySet() *AdjacencySet {
	return &AdjacencySet{edges: make(map[string]map[string]EdgeType)}
}

// Add registers a bidirectional edge between two resource IDs.
func (a *AdjacencySet) Add(from, to string, edgeType EdgeType) {
	if a.edges[from] == nil {
		a.edges[from] = make(map[string]EdgeType)
	}
	a.edges[from][to] = edgeType

	if a.edges[to] == nil {
		a.edges[to] = make(map[string]EdgeType)
	}
	a.edges[to][from] = edgeType
}

// Connected returns true if two resource IDs have an explicit edge.
func (a *AdjacencySet) Connected(from, to string) bool {
	if a == nil || a.edges == nil {
		return false
	}
	neighbors, ok := a.edges[from]
	if !ok {
		return false
	}
	_, connected := neighbors[to]
	return connected
}

// EdgeBetween returns the edge type between two resources, or empty string if none.
func (a *AdjacencySet) EdgeBetween(from, to string) EdgeType {
	if a == nil || a.edges == nil {
		return ""
	}
	if neighbors, ok := a.edges[from]; ok {
		return neighbors[to]
	}
	return ""
}

// Neighbors returns all resource IDs connected to the given resource.
func (a *AdjacencySet) Neighbors(id string) []string {
	if a == nil || a.edges == nil {
		return nil
	}
	neighbors := a.edges[id]
	result := make([]string, 0, len(neighbors))
	for n := range neighbors {
		result = append(result, n)
	}
	return result
}

// Size returns the total number of unique edges.
func (a *AdjacencySet) Size() int {
	count := 0
	for _, neighbors := range a.edges {
		count += len(neighbors)
	}
	return count / 2 // bidirectional
}

// LoadAdjacencyFromDB builds an AdjacencySet from resource-to-resource edges
// in graph_edges (same_region, same_account). Also includes finding→resource
// affects edges for chain building. Returns nil if DB is nil.
func LoadAdjacencyFromDB(ctx context.Context, db *sql.DB) (*AdjacencySet, error) {
	if db == nil {
		return nil, nil
	}

	adj := NewAdjacencySet()

	// Load resource-to-resource edges (same_region, same_account)
	rows, err := db.QueryContext(ctx, `
		SELECT source_id, target_id, edge_type
		FROM graph_edges
		WHERE source_type = 'resource' AND target_type = 'resource'
		  AND edge_type IN ('same_region', 'same_account')`)
	if err != nil {
		return nil, fmt.Errorf("load resource adjacency: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var from, to, et string
		if err := rows.Scan(&from, &to, &et); err != nil {
			continue
		}
		adj.Add(from, to, EdgeType(et))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resource adjacency: %w", err)
	}

	return adj, nil
}
