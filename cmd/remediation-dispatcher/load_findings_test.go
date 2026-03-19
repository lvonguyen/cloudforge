package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cspmscoring "aegis/internal/cspm/scoring"

	"go.uber.org/zap"
)

// writeFindingJSON writes a single PrioritizedFinding JSON file to dir.
func writeFindingJSON(t *testing.T, dir string, name string, f cspmscoring.PrioritizedFinding) {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatalf("write finding file: %v", err)
	}
}

// TestLoadFindings_NoPointerAliasing verifies that every pointer in the slice
// returned by loadFindings points to a distinct object.
//
// Before the fix, the loop appended &finding where finding was declared inside
// the loop body with `var finding`, which is safe in the current Go version
// but is fragile and violates the canonical Go idiom. The fix copies the loop
// variable before taking its address: `f := finding; append(&f)`.
// This ensures that if the code is ever refactored to use a range-variable
// pattern (e.g. `for _, finding := range decoded`), the correct semantics are
// already in place.
//
// More concretely: all returned pointers must be distinct — none may alias.
func TestLoadFindings_NoPointerAliasing(t *testing.T) {
	dir := t.TempDir()

	// Write two auto-remediation-ready findings with distinct IDs.
	writeFindingJSON(t, dir, "f1.json", cspmscoring.PrioritizedFinding{
		Finding:              &cspmscoring.Finding{ID: "finding-1", FindingType: "TEST"},
		AutoRemediationReady: true,
	})
	writeFindingJSON(t, dir, "f2.json", cspmscoring.PrioritizedFinding{
		Finding:              &cspmscoring.Finding{ID: "finding-2", FindingType: "TEST"},
		AutoRemediationReady: true,
	})
	// Write one finding that is NOT auto-remediation-ready — must be excluded.
	writeFindingJSON(t, dir, "f3.json", cspmscoring.PrioritizedFinding{
		Finding:              &cspmscoring.Finding{ID: "finding-3", FindingType: "TEST"},
		AutoRemediationReady: false,
	})

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	findings, err := loadFindings(logger, dir)
	if err != nil {
		t.Fatalf("loadFindings: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("loadFindings returned %d findings, want 2", len(findings))
	}

	// All returned pointers must be distinct (no aliasing).
	if findings[0] == findings[1] {
		t.Error("pointer aliasing detected: findings[0] == findings[1]; " +
			"all returned pointers must be distinct")
	}

	// Each pointer must point to a finding with the correct ID, proving
	// distinct memory is referenced. If aliasing occurred, both would hold
	// the last-assigned value.
	ids := map[string]bool{}
	for i, f := range findings {
		if f == nil || f.Finding == nil {
			t.Errorf("findings[%d] is nil or has nil Finding", i)
			continue
		}
		if ids[f.Finding.ID] {
			t.Errorf("duplicate finding ID %q at index %d; pointer aliasing suspected", f.Finding.ID, i)
		}
		ids[f.Finding.ID] = true
	}

	if !ids["finding-1"] || !ids["finding-2"] {
		t.Errorf("expected IDs finding-1 and finding-2, got: %v", ids)
	}
}

// TestLoadFindings_SkipsNonAutoRemediation verifies that findings without
// AutoRemediationReady=true are excluded from the result.
func TestLoadFindings_SkipsNonAutoRemediation(t *testing.T) {
	dir := t.TempDir()

	writeFindingJSON(t, dir, "skip.json", cspmscoring.PrioritizedFinding{
		Finding:              &cspmscoring.Finding{ID: "skip-me", FindingType: "TEST"},
		AutoRemediationReady: false,
	})

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	findings, err := loadFindings(logger, dir)
	if err != nil {
		t.Fatalf("loadFindings: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("loadFindings returned %d findings, want 0 (all non-auto-remediation)", len(findings))
	}
}
