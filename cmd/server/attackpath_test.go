package main

import (
	"net/http"
	"testing"
)

// paginatedPaths is a test helper for parsing paginated attack path responses.
type paginatedPaths struct {
	Data       []AttackPath `json:"data"`
	Page       int          `json:"page"`
	PerPage    int          `json:"per_page"`
	Total      int          `json:"total"`
	TotalPages int          `json:"total_pages"`
}

func TestComputeAttackPaths_ProducesPaths(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/attack-paths?per_page=100", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp paginatedPaths
	assertJSON(t, rr, &resp)

	if resp.Total == 0 {
		t.Fatal("expected at least 1 attack path from findings")
	}
	if len(resp.Data) == 0 {
		t.Fatal("expected data to contain paths")
	}

	// Verify structure of first path
	p := resp.Data[0]
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

	if stats.TotalFindings < 100 {
		t.Errorf("total findings = %d, want >= 100", stats.TotalFindings)
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

	// Get first path ID from paginated list
	listRR := doRequest(t, router, "GET", "/api/v1/attack-paths?per_page=1", "", jwt)
	assertStatus(t, listRR, http.StatusOK)

	var resp paginatedPaths
	assertJSON(t, listRR, &resp)
	if len(resp.Data) == 0 {
		t.Fatal("no paths to test")
	}

	// Fetch by ID
	rr := doRequest(t, router, "GET", "/api/v1/attack-paths/"+resp.Data[0].ID, "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var path AttackPath
	assertJSON(t, rr, &path)
	if path.ID != resp.Data[0].ID {
		t.Errorf("path id = %q, want %q", path.ID, resp.Data[0].ID)
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

	rr := doRequest(t, router, "GET", "/api/v1/attack-paths?per_page=100", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp paginatedPaths
	assertJSON(t, rr, &resp)

	if len(resp.Data) < 2 {
		t.Skip("need at least 2 paths to verify sort order")
	}

	// Verify severity is non-increasing
	for i := 1; i < len(resp.Data); i++ {
		if severityRank[resp.Data[i].Severity] > severityRank[resp.Data[i-1].Severity] {
			t.Errorf("path %d severity %s ranks higher than path %d severity %s — not sorted",
				i, resp.Data[i].Severity, i-1, resp.Data[i-1].Severity)
		}
	}
}

func TestAttackPaths_Pagination(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// Fetch page 1 with per_page=2
	rr := doRequest(t, router, "GET", "/api/v1/attack-paths?page=1&per_page=2", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp paginatedPaths
	assertJSON(t, rr, &resp)

	if resp.Page != 1 {
		t.Errorf("page = %d, want 1", resp.Page)
	}
	if resp.PerPage != 2 {
		t.Errorf("per_page = %d, want 2", resp.PerPage)
	}
	if len(resp.Data) > 2 {
		t.Errorf("data length = %d, want <= 2", len(resp.Data))
	}
	if resp.Total < 1 {
		t.Error("expected total >= 1")
	}
	if resp.TotalPages < 1 {
		t.Error("expected total_pages >= 1")
	}
}
