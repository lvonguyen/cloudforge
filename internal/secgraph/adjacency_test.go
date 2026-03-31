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

func TestAdjacencySetBlastRadius(t *testing.T) {
	// r-001 → r-002 → r-003 → r-004 (chain of 3 hops)
	adj := NewAdjacencySet()
	adj.Add("r-001", "r-002", EdgeSameRegion)
	adj.Add("r-002", "r-003", EdgeSameRegion)
	adj.Add("r-003", "r-004", EdgeSameRegion)
	adj.Add("r-001", "r-005", EdgeSameAccount) // branch

	// 1 hop from r-001: r-002 + r-005 = 2
	if br := adj.BlastRadius("r-001", 1); br != 2 {
		t.Errorf("1-hop blast radius from r-001 = %d, want 2", br)
	}

	// 2 hops from r-001: r-002 + r-005 + r-003 = 3
	if br := adj.BlastRadius("r-001", 2); br != 3 {
		t.Errorf("2-hop blast radius from r-001 = %d, want 3", br)
	}

	// 3 hops from r-001: r-002 + r-005 + r-003 + r-004 = 4
	if br := adj.BlastRadius("r-001", 3); br != 4 {
		t.Errorf("3-hop blast radius from r-001 = %d, want 4", br)
	}

	// Unknown node
	if br := adj.BlastRadius("r-999", 2); br != 0 {
		t.Errorf("blast radius of unknown node = %d, want 0", br)
	}

	// Nil safety
	var nilAdj *AdjacencySet
	if br := nilAdj.BlastRadius("r-001", 2); br != 0 {
		t.Errorf("nil adjacency blast radius = %d, want 0", br)
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
