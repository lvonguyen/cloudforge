package main

import (
	"net/http"
	"testing"
)

func TestComputeAttackPaths_ProducesPaths(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/attack-paths", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var paths []AttackPath
	assertJSON(t, rr, &paths)

	if len(paths) == 0 {
		t.Fatal("expected at least 1 attack path from 80 findings")
	}

	// Verify structure of first path
	p := paths[0]
	if p.ID == "" || p.Title == "" || p.Severity == "" {
		t.Errorf("path missing required fields: id=%q title=%q severity=%q", p.ID, p.Title, p.Severity)
	}
	if len(p.Nodes) < 2 {
		t.Errorf("path should have at least 2 nodes, got %d", len(p.Nodes))
	}
	if len(p.Edges) < 1 {
		t.Errorf("path should have at least 1 edge, got %d", len(p.Edges))
	}
	if len(p.FindingIDs) < 2 {
		t.Errorf("path should reference at least 2 findings, got %d", len(p.FindingIDs))
	}
}

func TestAttackPathStats(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/attack-paths/stats", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var stats AttackPathStats
	assertJSON(t, rr, &stats)

	if stats.TotalFindings != 80 {
		t.Errorf("total findings = %d, want 80", stats.TotalFindings)
	}
	if stats.TotalPaths == 0 {
		t.Error("expected at least 1 path")
	}
	if stats.FindingsInPaths == 0 {
		t.Error("expected at least some findings in paths")
	}
	if stats.CoveragePercent <= 0 {
		t.Error("expected positive coverage percent")
	}
}

func TestGetAttackPath_Found(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// Get first path ID from list
	listRR := doRequest(t, router, "GET", "/api/v1/attack-paths", "", jwt)
	assertStatus(t, listRR, http.StatusOK)

	var paths []AttackPath
	assertJSON(t, listRR, &paths)
	if len(paths) == 0 {
		t.Fatal("no paths to test")
	}

	// Fetch by ID
	rr := doRequest(t, router, "GET", "/api/v1/attack-paths/"+paths[0].ID, "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var path AttackPath
	assertJSON(t, rr, &path)
	if path.ID != paths[0].ID {
		t.Errorf("path id = %q, want %q", path.ID, paths[0].ID)
	}
}

func TestGetAttackPath_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/attack-paths/nonexistent", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestAttackPaths_RequireAuth(t *testing.T) {
	_, router := testServer(t)

	endpoints := []string{
		"/api/v1/attack-paths",
		"/api/v1/attack-paths/stats",
		"/api/v1/attack-paths/ap-001",
	}
	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			rr := doRequest(t, router, "GET", ep, "", "")
			assertStatus(t, rr, http.StatusUnauthorized)
		})
	}
}

func TestAttackPaths_SortedBySeverity(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/attack-paths", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var paths []AttackPath
	assertJSON(t, rr, &paths)

	if len(paths) < 2 {
		t.Skip("need at least 2 paths to verify sort order")
	}

	// Verify severity is non-increasing
	for i := 1; i < len(paths); i++ {
		if severityRank[paths[i].Severity] > severityRank[paths[i-1].Severity] {
			t.Errorf("path %d severity %s ranks higher than path %d severity %s — not sorted",
				i, paths[i].Severity, i-1, paths[i-1].Severity)
		}
	}
}
