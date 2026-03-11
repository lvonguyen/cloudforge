package opa

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeTempPolicy writes a minimal Rego policy file to a temp directory and
// returns the file path. The caller is responsible for cleanup.
func writeTempPolicy(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp policy %s: %v", filename, err)
	}
	return path
}

const policyAllow = `
package cloudforge.ai.group_a

default allow = true
`

const policyDeny = `
package cloudforge.ai.group_b

default allow = false
`

// TestLoadPolicies_KeyCollision verifies that calling LoadPolicies twice with
// different path sets produces two independently stored queries.
//
// Before the fix, LoadPolicies always stored the compiled query under the
// hard-coded key "default", so a second call silently overwrote the first.
// After the fix, each call is keyed by paths[0] so both are independently
// retrievable — queries["pathA"] != queries["pathB"].
func TestLoadPolicies_KeyCollision(t *testing.T) {
	dir := t.TempDir()

	pathA := writeTempPolicy(t, dir, "allow.rego", policyAllow)
	pathB := writeTempPolicy(t, dir, "deny.rego", policyDeny)

	ctx := context.Background()

	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Load the first policy set (pathA).
	if err := engine.LoadPolicies(ctx, []string{pathA}); err != nil {
		t.Fatalf("LoadPolicies(pathA): %v", err)
	}

	// Load the second policy set (pathB).
	if err := engine.LoadPolicies(ctx, []string{pathB}); err != nil {
		t.Fatalf("LoadPolicies(pathB): %v", err)
	}

	// After two calls with distinct paths, there must be two entries in the
	// internal queries map, not one. Before the fix both calls write "default"
	// so only one entry exists.
	engine.mu.RLock()
	numQueries := len(engine.queries)
	engine.mu.RUnlock()

	if numQueries < 2 {
		t.Errorf("key collision: queries map has %d entry/entries after two LoadPolicies calls; "+
			"expected >= 2 (one per path set)", numQueries)
	}

	// Also verify that a path-based lookup succeeds for pathA.
	_, ok := engine.queries[pathA]
	if !ok {
		t.Errorf("queries[pathA] not found; LoadPolicies must use paths[0] as the map key")
	}

	// And for pathB.
	_, ok = engine.queries[pathB]
	if !ok {
		t.Errorf("queries[pathB] not found; LoadPolicies must use paths[0] as the map key")
	}
}

// TestLoadPolicies_EmptyPaths ensures LoadPolicies rejects empty path slices.
func TestLoadPolicies_EmptyPaths(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if err := engine.LoadPolicies(context.Background(), nil); err == nil {
		t.Error("expected error for nil paths, got nil")
	}

	if err := engine.LoadPolicies(context.Background(), []string{}); err == nil {
		t.Error("expected error for empty paths, got nil")
	}
}
