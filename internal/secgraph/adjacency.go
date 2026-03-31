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

// BlastRadius returns the count of unique resources reachable within maxHops
// from the given resource ID. Capped at maxVisited (default 1000) to prevent
// unbounded memory growth on dense graphs.
func (a *AdjacencySet) BlastRadius(resourceID string, maxHops int) int {
	if a == nil || a.edges == nil {
		return 0
	}
	if maxHops <= 0 {
		maxHops = 2
	}
	const maxVisited = 1000
	visited := map[string]bool{resourceID: true}
	frontier := []string{resourceID}
	for hop := 0; hop < maxHops && len(frontier) > 0; hop++ {
		var next []string
		for _, id := range frontier {
			for neighbor := range a.edges[id] {
				if !visited[neighbor] {
					visited[neighbor] = true
					next = append(next, neighbor)
					if len(visited) >= maxVisited {
						return len(visited) - 1
					}
				}
			}
		}
		frontier = next
	}
	return len(visited) - 1 // exclude the seed
}

// Size returns the total number of unique edges.
func (a *AdjacencySet) Size() int {
	count := 0
	for _, neighbors := range a.edges {
		count += len(neighbors)
	}
	return count / 2 // bidirectional
}

// LoadAdjacencyFromDB builds an AdjacencySet from persisted resource-to-resource
// graph edges. It intentionally ignores other edge families because callers use
// this structure for resource neighborhood and blast-radius calculations.
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
