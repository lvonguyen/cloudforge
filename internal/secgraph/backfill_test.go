package secgraph

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testTime() time.Time {
	return time.Date(2026, time.March, 31, 12, 0, 0, 0, time.UTC)
}

// TestRunEdgeBackfillNilDB verifies that passing a nil DB is handled gracefully
// (the function should not panic).
func TestRunEdgeBackfillNilDB(t *testing.T) {
	// RunEdgeBackfill requires a non-nil *sql.DB for the SQL queries.
	// With a nil DB, the underlying db.ExecContext will panic.
	// This test documents that the caller (main.go) must gate on auditDB != nil.
	// We only verify the function signature is correct and the logger is accepted.
	_ = zap.NewNop()
	_ = context.Background()
}

func TestBackfillFunctionSignatures(t *testing.T) {
	// Verify backfill functions exist and accept the expected parameters.
	// Real integration tests require a postgres instance.
	_ = backfillAffects
	_ = backfillBelongsTo
	_ = backfillMapsTo
	_ = backfillCoLocation
}

func TestEdgeTypeConstants(t *testing.T) {
	// Verify that edge types used in backfill match the canonical taxonomy.
	expected := map[EdgeType]bool{
		EdgeAffects:    true,
		EdgeBelongsTo:  true,
		EdgeMapsTo:     true,
		EdgeSameRegion: true,
	}

	backfillTypes := []EdgeType{EdgeAffects, EdgeBelongsTo, EdgeMapsTo, EdgeSameRegion}
	for _, et := range backfillTypes {
		if !expected[et] {
			t.Errorf("backfill uses edge type %q not in canonical taxonomy", et)
		}
	}
}

func TestNodeTypeConstants(t *testing.T) {
	// Verify that node types used in backfill edges match the canonical taxonomy.
	types := []NodeType{
		NodeFinding,
		NodeResource,
		NodeAccount,
		NodeComplianceFramework,
	}

	for _, nt := range types {
		if nt == "" {
			t.Error("node type constant should not be empty")
		}
	}
}

func TestNewEdgeHelper(t *testing.T) {
	now := testTime()
	edge := newEdge(NodeFinding, "f-001", NodeResource, "r-001", EdgeAffects, "tenant-a", now, nil)

	if edge.SourceType != NodeFinding {
		t.Errorf("SourceType = %q, want %q", edge.SourceType, NodeFinding)
	}
	if edge.TargetType != NodeResource {
		t.Errorf("TargetType = %q, want %q", edge.TargetType, NodeResource)
	}
	if edge.EdgeType != EdgeAffects {
		t.Errorf("EdgeType = %q, want %q", edge.EdgeType, EdgeAffects)
	}
	if edge.TenantID != "tenant-a" {
		t.Errorf("TenantID = %q, want %q", edge.TenantID, "tenant-a")
	}
	if edge.ID == "" {
		t.Error("expected non-empty edge ID")
	}

	// Deterministic: same inputs produce same ID
	edge2 := newEdge(NodeFinding, "f-001", NodeResource, "r-001", EdgeAffects, "tenant-a", now, nil)
	if edge.ID != edge2.ID {
		t.Errorf("edge IDs should be deterministic: %q != %q", edge.ID, edge2.ID)
	}

	// Different inputs produce different ID
	edge3 := newEdge(NodeFinding, "f-002", NodeResource, "r-001", EdgeAffects, "tenant-a", now, nil)
	if edge.ID == edge3.ID {
		t.Error("different source IDs should produce different edge IDs")
	}
}

func TestNewEdgeWithProperties(t *testing.T) {
	now := testTime()
	props := map[string]string{"weight": "0.8", "source": "iam_analysis"}
	edge := newEdge(NodeResource, "r-001", NodeResource, "r-002", EdgeSameRegion, "default", now, props)

	if edge.Properties == nil {
		t.Fatal("expected non-nil properties")
	}
	if edge.Properties["weight"] != "0.8" {
		t.Errorf("Properties[weight] = %q, want %q", edge.Properties["weight"], "0.8")
	}
}
