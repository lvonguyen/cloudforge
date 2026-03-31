package secgraph

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// GraphQueryResult is the typed response for structured graph queries.
type GraphQueryResult struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdgeView `json:"edges"`
}

// GraphNode is a vertex returned by structured graph queries.
type GraphNode struct {
	ID       string            `json:"id"`
	Type     NodeType          `json:"type"`
	Label    string            `json:"label"`
	Props    map[string]string `json:"props,omitempty"`
}

// GraphEdgeView is an edge returned by structured graph queries.
type GraphEdgeView struct {
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Type     EdgeType `json:"type"`
}

// GraphStats summarizes the security graph contents.
type GraphStats struct {
	Vertices     map[string]int64 `json:"vertices"`
	Edges        map[string]int64 `json:"edges"`
	TotalVertices int64           `json:"total_vertices"`
	TotalEdges    int64           `json:"total_edges"`
}

// Querier executes structured graph queries against the security graph.
type Querier interface {
	Neighborhood(ctx context.Context, nodeType NodeType, nodeID string, hops int, limit int) (*GraphQueryResult, error)
	Stats(ctx context.Context) (*GraphStats, error)
}

// PostgresQuerier queries the security graph via Postgres CTEs over graph_edges.
type PostgresQuerier struct {
	db *sql.DB
}

// NewPostgresQuerier creates a Postgres-backed graph querier.
func NewPostgresQuerier(db *sql.DB) *PostgresQuerier {
	return &PostgresQuerier{db: db}
}

// Neighborhood returns all nodes and edges within `hops` of the given node.
// Uses a recursive CTE over graph_edges for BFS expansion.
func (q *PostgresQuerier) Neighborhood(ctx context.Context, nodeType NodeType, nodeID string, hops int, limit int) (*GraphQueryResult, error) {
	if hops <= 0 {
		hops = 1
	}
	if hops > 3 {
		hops = 3
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	// Recursive CTE: BFS from seed node through graph_edges up to N hops.
	// Collects all discovered (type, id) pairs, then fetches labels.
	rows, err := q.db.QueryContext(ctx, `
		WITH RECURSIVE neighborhood AS (
			-- Seed: the starting node
			SELECT $1::text AS node_type, $2::text AS node_id, 0 AS depth
			UNION
			-- Expand: follow edges in both directions
			SELECT
				CASE WHEN e.source_type = n.node_type AND e.source_id = n.node_id
				     THEN e.target_type ELSE e.source_type END,
				CASE WHEN e.source_type = n.node_type AND e.source_id = n.node_id
				     THEN e.target_id ELSE e.source_id END,
				n.depth + 1
			FROM neighborhood n
			JOIN graph_edges e ON
				(e.source_type = n.node_type AND e.source_id = n.node_id)
				OR (e.target_type = n.node_type AND e.target_id = n.node_id)
			WHERE n.depth < $3
		),
		distinct_nodes AS (
			SELECT DISTINCT node_type, node_id FROM neighborhood LIMIT $4
		)
		SELECT node_type, node_id FROM distinct_nodes`,
		string(nodeType), nodeID, hops, limit)
	if err != nil {
		return nil, fmt.Errorf("neighborhood query: %w", err)
	}
	defer rows.Close()

	nodeIDs := make(map[NodeType][]string)
	for rows.Next() {
		var nt, nid string
		if err := rows.Scan(&nt, &nid); err != nil {
			return nil, fmt.Errorf("scanning neighborhood node: %w", err)
		}
		nodeIDs[NodeType(nt)] = append(nodeIDs[NodeType(nt)], nid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating neighborhood nodes: %w", err)
	}

	// Fetch labels for discovered nodes
	nodes, err := q.resolveNodeLabels(ctx, nodeIDs)
	if err != nil {
		return nil, err
	}

	// Fetch edges between discovered nodes
	allIDs := make([]string, 0)
	for _, ids := range nodeIDs {
		allIDs = append(allIDs, ids...)
	}
	edges, err := q.fetchEdgesBetween(ctx, allIDs, limit*2)
	if err != nil {
		return nil, err
	}

	return &GraphQueryResult{Nodes: nodes, Edges: edges}, nil
}

// Stats returns vertex and edge counts grouped by type.
func (q *PostgresQuerier) Stats(ctx context.Context) (*GraphStats, error) {
	stats := &GraphStats{
		Vertices: make(map[string]int64),
		Edges:    make(map[string]int64),
	}

	// Vertex counts from source tables
	vertexQueries := []struct {
		label string
		table string
	}{
		{"finding", "findings"},
		{"resource", "resources"},
		{"account", "accounts"},
		{"control", "controls"},
		{"issue", "issues"},
		{"compliance_framework", "compliance_frameworks"},
	}

	for _, vq := range vertexQueries {
		var count int64
		err := q.db.QueryRowContext(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM %s", vq.table)).Scan(&count)
		if err != nil {
			// Table may not exist yet — treat as 0
			stats.Vertices[vq.label] = 0
			continue
		}
		stats.Vertices[vq.label] = count
		stats.TotalVertices += count
	}

	// Edge counts from graph_edges
	edgeRows, err := q.db.QueryContext(ctx,
		`SELECT edge_type, COUNT(*) FROM graph_edges GROUP BY edge_type`)
	if err != nil {
		return stats, nil // partial result is acceptable
	}
	defer edgeRows.Close()

	for edgeRows.Next() {
		var edgeType string
		var count int64
		if err := edgeRows.Scan(&edgeType, &count); err != nil {
			continue
		}
		stats.Edges[edgeType] = count
		stats.TotalEdges += count
	}

	return stats, nil
}

func (q *PostgresQuerier) resolveNodeLabels(ctx context.Context, nodeIDs map[NodeType][]string) ([]GraphNode, error) {
	var nodes []GraphNode

	for nodeType, ids := range nodeIDs {
		if len(ids) == 0 {
			continue
		}

		var query string
		switch nodeType {
		case NodeFinding:
			query = `SELECT id, title, severity FROM findings WHERE id = ANY($1)`
		case NodeResource:
			query = `SELECT id, COALESCE(name, id), COALESCE(resource_type, 'unknown') FROM resources WHERE id = ANY($1)`
		case NodeAccount:
			query = `SELECT id, COALESCE(name, id), cloud_provider FROM accounts WHERE id = ANY($1)`
		case NodeControl:
			query = `SELECT id, title, severity FROM controls WHERE id = ANY($1)`
		case NodeIssue:
			query = `SELECT id, title, severity FROM issues WHERE id = ANY($1)`
		case NodeComplianceFramework:
			query = `SELECT id, name, COALESCE(category, '') FROM compliance_frameworks WHERE id = ANY($1)`
		default:
			for _, id := range ids {
				nodes = append(nodes, GraphNode{ID: id, Type: nodeType, Label: id})
			}
			continue
		}

		rows, err := q.db.QueryContext(ctx, query, pq.Array(ids))
		if err != nil {
			// Fallback: return IDs without labels
			for _, id := range ids {
				nodes = append(nodes, GraphNode{ID: id, Type: nodeType, Label: id})
			}
			continue
		}

		for rows.Next() {
			var id, label, prop string
			if err := rows.Scan(&id, &label, &prop); err != nil {
				continue
			}
			node := GraphNode{ID: id, Type: nodeType, Label: label}
			if prop != "" {
				node.Props = map[string]string{"detail": prop}
			}
			nodes = append(nodes, node)
		}
		rows.Close()
	}

	return nodes, nil
}

func (q *PostgresQuerier) fetchEdgesBetween(ctx context.Context, nodeIDs []string, limit int) ([]GraphEdgeView, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}

	rows, err := q.db.QueryContext(ctx, `
		SELECT source_id, target_id, edge_type
		FROM graph_edges
		WHERE source_id = ANY($1) AND target_id = ANY($1)
		LIMIT $2`,
		pq.Array(nodeIDs), limit)
	if err != nil {
		return nil, fmt.Errorf("fetch edges between nodes: %w", err)
	}
	defer rows.Close()

	var edges []GraphEdgeView
	for rows.Next() {
		var source, target, edgeType string
		if err := rows.Scan(&source, &target, &edgeType); err != nil {
			continue
		}
		edges = append(edges, GraphEdgeView{
			Source: source,
			Target: target,
			Type:   EdgeType(edgeType),
		})
	}

	return edges, nil
}

// BuildNeighborhoodGremlin generates a Gremlin query for neighborhood expansion.
// Used when PuppyGraph is available as an alternative to the Postgres CTE.
func BuildNeighborhoodGremlin(nodeType NodeType, nodeID string, hops int) string {
	if hops <= 0 {
		hops = 1
	}
	if hops > 3 {
		hops = 3
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("g.V().hasLabel('%s').has('id', '%s')",
		sanitizeGremlinValue(string(nodeType)),
		sanitizeGremlinValue(nodeID)))
	sb.WriteString(fmt.Sprintf(".repeat(both().simplePath()).times(%d)", hops))
	sb.WriteString(".path().limit(100)")
	return sb.String()
}

// BuildStatsGremlin generates a Gremlin query for vertex/edge type counts.
func BuildStatsGremlin() string {
	return "g.V().groupCount().by(label)"
}

// sanitizeGremlinValue escapes single quotes in Gremlin string literals.
func sanitizeGremlinValue(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}
