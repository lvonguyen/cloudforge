package secgraph

import "testing"

func TestAdjacencySetBasics(t *testing.T) {
	adj := NewAdjacencySet()
	adj.Add("r-001", "r-002", EdgeSameRegion)
	adj.Add("r-001", "r-003", EdgeSameAccount)

	if !adj.Connected("r-001", "r-002") {
		t.Error("r-001 and r-002 should be connected")
	}
	if !adj.Connected("r-002", "r-001") {
		t.Error("bidirectional: r-002 should connect to r-001")
	}
	if !adj.Connected("r-001", "r-003") {
		t.Error("r-001 and r-003 should be connected")
	}
	if adj.Connected("r-002", "r-003") {
		t.Error("r-002 and r-003 should NOT be connected")
	}
}

func TestAdjacencySetEdgeBetween(t *testing.T) {
	adj := NewAdjacencySet()
	adj.Add("r-001", "r-002", EdgeSameRegion)

	if et := adj.EdgeBetween("r-001", "r-002"); et != EdgeSameRegion {
		t.Errorf("expected same_region, got %q", et)
	}
	if et := adj.EdgeBetween("r-001", "r-999"); et != "" {
		t.Errorf("expected empty, got %q", et)
	}
}

func TestAdjacencySetNeighbors(t *testing.T) {
	adj := NewAdjacencySet()
	adj.Add("r-001", "r-002", EdgeSameRegion)
	adj.Add("r-001", "r-003", EdgeSameAccount)

	neighbors := adj.Neighbors("r-001")
	if len(neighbors) != 2 {
		t.Errorf("expected 2 neighbors, got %d", len(neighbors))
	}

	neighbors = adj.Neighbors("r-999")
	if len(neighbors) != 0 {
		t.Errorf("expected 0 neighbors for unknown node, got %d", len(neighbors))
	}
}

func TestAdjacencySetSize(t *testing.T) {
	adj := NewAdjacencySet()
	if adj.Size() != 0 {
		t.Errorf("empty set should have size 0, got %d", adj.Size())
	}

	adj.Add("r-001", "r-002", EdgeSameRegion)
	if adj.Size() != 1 {
		t.Errorf("expected size 1, got %d", adj.Size())
	}

	adj.Add("r-001", "r-003", EdgeSameAccount)
	if adj.Size() != 2 {
		t.Errorf("expected size 2, got %d", adj.Size())
	}
}

func TestAdjacencySetNilSafe(t *testing.T) {
	var adj *AdjacencySet
	if adj.Connected("a", "b") {
		t.Error("nil adjacency should return false")
	}
	if et := adj.EdgeBetween("a", "b"); et != "" {
		t.Error("nil adjacency should return empty edge type")
	}
	if neighbors := adj.Neighbors("a"); len(neighbors) != 0 {
		t.Error("nil adjacency should return empty neighbors")
	}
}
