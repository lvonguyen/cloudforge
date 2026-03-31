package secgraph

import (
	"strings"
	"testing"
)

func TestBuildNeighborhoodGremlin(t *testing.T) {
	tests := []struct {
		name     string
		nodeType NodeType
		nodeID   string
		hops     int
		contains []string
	}{
		{
			name:     "basic finding neighborhood",
			nodeType: NodeFinding,
			nodeID:   "F-001",
			hops:     1,
			contains: []string{"hasLabel('finding')", "has('id', 'F-001')", ".times(1)"},
		},
		{
			name:     "resource 2-hop",
			nodeType: NodeResource,
			nodeID:   "arn:aws:s3:::my-bucket",
			hops:     2,
			contains: []string{"hasLabel('resource')", ".times(2)"},
		},
		{
			name:     "clamps negative hops to 1",
			nodeType: NodeFinding,
			nodeID:   "F-002",
			hops:     -1,
			contains: []string{".times(1)"},
		},
		{
			name:     "clamps hops above 3",
			nodeType: NodeFinding,
			nodeID:   "F-003",
			hops:     10,
			contains: []string{".times(3)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := BuildNeighborhoodGremlin(tt.nodeType, tt.nodeID, tt.hops)
			for _, substr := range tt.contains {
				if !strings.Contains(query, substr) {
					t.Errorf("query %q missing expected substring %q", query, substr)
				}
			}
		})
	}
}

func TestBuildStatsGremlin(t *testing.T) {
	query := BuildStatsGremlin()
	if !strings.Contains(query, "groupCount") {
		t.Errorf("stats query %q should contain groupCount", query)
	}
}

func TestSanitizeGremlinValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal-id", "normal-id"},
		{"it's a trap", "it\\'s a trap"},
		{"no'quotes'here", "no\\'quotes\\'here"},
		{"", ""},
	}

	for _, tt := range tests {
		result := sanitizeGremlinValue(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeGremlinValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGraphStatsStructure(t *testing.T) {
	stats := &GraphStats{
		Vertices:      map[string]int64{"finding": 100, "resource": 50},
		Edges:         map[string]int64{"affects": 200},
		TotalVertices: 150,
		TotalEdges:    200,
	}

	if stats.Vertices["finding"] != 100 {
		t.Errorf("expected 100 findings, got %d", stats.Vertices["finding"])
	}
	if stats.TotalEdges != 200 {
		t.Errorf("expected 200 total edges, got %d", stats.TotalEdges)
	}
}

func TestGraphNodeViewTypes(t *testing.T) {
	node := GraphNode{
		ID:    "F-001",
		Type:  NodeFinding,
		Label: "S3 bucket public",
		Props: map[string]string{"detail": "CRITICAL"},
	}

	if node.Type != NodeFinding {
		t.Errorf("expected NodeFinding, got %v", node.Type)
	}

	edge := GraphEdgeView{
		Source: "F-001",
		Target: "R-001",
		Type:   EdgeAffects,
	}
	if edge.Type != EdgeAffects {
		t.Errorf("expected EdgeAffects, got %v", edge.Type)
	}
}
