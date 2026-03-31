package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegis/internal/secgraph"
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

func TestComputeAttackPaths_UsesExplicitAdjacencyForMultiHopChain(t *testing.T) {
	findings := []Finding{
		{
			ID:            "f-entry",
			Title:         "Internet-exposed workload",
			ResourceID:    "r-entry",
			ResourceName:  "edge-workload",
			ResourceType:  "compute",
			CloudProvider: "aws",
			AccountID:     "acct-1",
			Region:        "us-east-1",
			Severity:      "HIGH",
			Category:      "NETWORK",
		},
		{
			ID:            "f-mid-1",
			Title:         "Role pivot",
			ResourceID:    "r-mid-1",
			ResourceName:  "pivot-role",
			ResourceType:  "identity",
			CloudProvider: "aws",
			AccountID:     "acct-1",
			Region:        "us-east-1",
			Severity:      "HIGH",
			Category:      "IDENTITY",
		},
		{
			ID:            "f-mid-2",
			Title:         "Internal relay",
			ResourceID:    "r-mid-2",
			ResourceName:  "relay-service",
			ResourceType:  "container",
			CloudProvider: "aws",
			AccountID:     "acct-1",
			Region:        "us-east-1",
			Severity:      "MEDIUM",
			Category:      "VULNERABILITY",
		},
		{
			ID:            "f-target",
			Title:         "Sensitive database",
			ResourceID:    "r-target",
			ResourceName:  "customer-db",
			ResourceType:  "database",
			CloudProvider: "aws",
			AccountID:     "acct-1",
			Region:        "us-east-1",
			Severity:      "CRITICAL",
			Category:      "DATA",
		},
	}

	adjacency := secgraph.NewAdjacencySet()
	adjacency.Add("r-entry", "r-mid-1", secgraph.EdgeSameRegion)
	adjacency.Add("r-mid-1", "r-mid-2", secgraph.EdgeSameRegion)
	adjacency.Add("r-mid-2", "r-target", secgraph.EdgeSameAccount)

	paths, stats := computeAttackPaths(findings, adjacency)
	if len(paths) == 0 {
		t.Fatal("expected at least one attack path from explicit adjacency")
	}
	if stats.TotalPaths == 0 {
		t.Fatal("expected attack path stats to record at least one path")
	}

	path := paths[0]
	if path.HopCount != 3 {
		t.Fatalf("hop count = %d, want 3", path.HopCount)
	}
	wantFindingIDs := []string{"f-entry", "f-mid-1", "f-mid-2", "f-target"}
	for i, want := range wantFindingIDs {
		if path.FindingIDs[i] != want {
			t.Fatalf("finding_ids[%d] = %q, want %q", i, path.FindingIDs[i], want)
		}
	}
	if got := path.Edges[0].EdgeType; got != string(secgraph.EdgeSameRegion) {
		t.Fatalf("edge 0 type = %q, want %q", got, secgraph.EdgeSameRegion)
	}
	if got := path.Edges[2].EdgeType; got != string(secgraph.EdgeSameAccount) {
		t.Fatalf("edge 2 type = %q, want %q", got, secgraph.EdgeSameAccount)
	}
}

func TestComputeAttackPaths_FallsBackToHeuristicWhenAdjacencyMissing(t *testing.T) {
	findings := []Finding{
		{
			ID:            "f-entry",
			ResourceID:    "r-entry",
			ResourceName:  "edge-workload",
			ResourceType:  "compute",
			CloudProvider: "aws",
			AccountID:     "acct-1",
			Region:        "us-east-1",
			Severity:      "HIGH",
			Category:      "NETWORK",
		},
		{
			ID:            "f-target",
			ResourceID:    "r-target",
			ResourceName:  "customer-db",
			ResourceType:  "database",
			CloudProvider: "aws",
			AccountID:     "acct-1",
			Region:        "us-east-1",
			Severity:      "CRITICAL",
			Category:      "DATA",
		},
	}

	paths, _ := computeAttackPaths(findings, nil)
	if len(paths) != 1 {
		t.Fatalf("path count = %d, want 1", len(paths))
	}
	if paths[0].HopCount != 1 {
		t.Fatalf("hop count = %d, want 1", paths[0].HopCount)
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

func TestSelectDeferredAttackPathCandidates_CapsPerAccount(t *testing.T) {
	findings := []Finding{
		{
			ID:              "f-entry-1",
			AccountID:       "acct-a",
			ResourceID:      "r-entry-1",
			ResourceName:    "edge-1",
			ResourceType:    "compute",
			Region:          "us-east-1",
			Severity:        "CRITICAL",
			Category:        "NETWORK",
			EnvironmentType: "production",
			Status:          "open",
		},
		{
			ID:           "f-target-1",
			AccountID:    "acct-a",
			ResourceID:   "r-target-1",
			ResourceName: "db-1",
			ResourceType: "database",
			Region:       "us-east-1",
			Severity:     "HIGH",
			Category:     "DATA",
			Status:       "open",
		},
		{
			ID:           "f-mid-1",
			AccountID:    "acct-a",
			ResourceID:   "r-mid-1",
			ResourceName: "mid-1",
			ResourceType: "identity",
			Region:       "us-east-1",
			Severity:     "LOW",
			Category:     "IDENTITY",
			Status:       "open",
		},
		{
			ID:              "f-entry-2",
			AccountID:       "acct-b",
			ResourceID:      "r-entry-2",
			ResourceName:    "edge-2",
			ResourceType:    "compute",
			Region:          "us-west-2",
			Severity:        "CRITICAL",
			Category:        "NETWORK",
			EnvironmentType: "production",
			Status:          "open",
		},
		{
			ID:           "f-target-2",
			AccountID:    "acct-b",
			ResourceID:   "r-target-2",
			ResourceName: "db-2",
			ResourceType: "database",
			Region:       "us-west-2",
			Severity:     "HIGH",
			Category:     "DATA",
			Status:       "open",
		},
	}

	selected := selectDeferredAttackPathCandidates(findings, 4, 2)
	if len(selected) != 4 {
		t.Fatalf("candidate count = %d, want 4", len(selected))
	}

	perAccount := map[string]int{}
	for _, finding := range selected {
		perAccount[finding.AccountID]++
	}
	if perAccount["acct-a"] != 2 || perAccount["acct-b"] != 2 {
		t.Fatalf("per-account selection = %#v, want acct-a=2 acct-b=2", perAccount)
	}
}

func TestAttackPathService_EnsuresDeferredInitialization(t *testing.T) {
	svc := NewAttackPathService()
	svc.setInitializer(func(context.Context) ([]AttackPath, *AttackPathStats, error) {
		return []AttackPath{
				{
					ID:       "ap-001",
					Title:    "edge -> db",
					Severity: "CRITICAL",
					Nodes: []AttackPathNode{
						{ID: "n-1", FindingID: "f-1", AccountID: "acct-1", Region: "us-east-1", Provider: "aws"},
						{ID: "n-2", FindingID: "f-2", AccountID: "acct-1", Region: "us-east-1", Provider: "aws"},
					},
					FindingIDs: []string{"f-1", "f-2"},
				},
			}, &AttackPathStats{
				TotalFindings:     100,
				FindingsInPaths:   2,
				IsolatedFindings:  98,
				TotalPaths:        1,
				CriticalPaths:     1,
				Mode:              "sampled",
				CandidateFindings: 25,
				ByProvider:        map[string]int{"aws": 1},
			}, nil
	}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attack-paths", nil)
	svc.listAttackPaths(rr, req)
	assertStatus(t, rr, http.StatusOK)

	var resp paginatedPaths
	assertJSON(t, rr, &resp)
	if resp.Total != 1 {
		t.Fatalf("path total = %d, want 1", resp.Total)
	}
	if resp.Data[0].ID != "ap-001" {
		t.Fatalf("path id = %q, want ap-001", resp.Data[0].ID)
	}
}

func TestComputeDeferredAttackPaths_FallsBackToHeuristicWhenAdjacencyYieldsNoPaths(t *testing.T) {
	findings := []Finding{
		{
			ID:              "f-entry",
			AccountID:       "acct-a",
			ResourceID:      "r-entry",
			ResourceName:    "edge",
			ResourceType:    "compute",
			Region:          "us-east-1",
			Severity:        "CRITICAL",
			Category:        "NETWORK",
			EnvironmentType: "production",
			Status:          "open",
		},
		{
			ID:           "f-target",
			AccountID:    "acct-a",
			ResourceID:   "r-target",
			ResourceName: "db",
			ResourceType: "database",
			Region:       "us-east-1",
			Severity:     "HIGH",
			Category:     "DATA",
			Status:       "open",
		},
	}

	adjacency := secgraph.NewAdjacencySet()
	paths, stats := computeDeferredAttackPaths(findings, adjacency)
	if len(paths) != 1 {
		t.Fatalf("path count = %d, want 1", len(paths))
	}
	if stats.Mode != "full_heuristic" {
		t.Fatalf("stats mode = %q, want full_heuristic", stats.Mode)
	}
}
