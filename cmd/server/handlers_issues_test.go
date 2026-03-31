package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"aegis/internal/api"
	"aegis/internal/secgraph"
)

type stubIssueQuerier struct {
	listFunc    func(ctx context.Context, params secgraph.IssueListParams) (*secgraph.IssueListResult, error)
	getFunc     func(ctx context.Context, tenantID, issueID string) (*secgraph.IssueDetail, error)
	listParams  secgraph.IssueListParams
	getTenantID string
	getIssueID  string
}

func (s *stubIssueQuerier) ListIssues(ctx context.Context, params secgraph.IssueListParams) (*secgraph.IssueListResult, error) {
	s.listParams = params
	if s.listFunc == nil {
		return &secgraph.IssueListResult{}, nil
	}
	return s.listFunc(ctx, params)
}

func (s *stubIssueQuerier) GetIssue(ctx context.Context, tenantID, issueID string) (*secgraph.IssueDetail, error) {
	s.getTenantID = tenantID
	s.getIssueID = issueID
	if s.getFunc == nil {
		return nil, nil
	}
	return s.getFunc(ctx, tenantID, issueID)
}

func (s *stubIssueQuerier) UpdateIssue(_ context.Context, _ string, _ secgraph.IssueUpdate) (*secgraph.Issue, error) {
	return nil, nil
}

func (s *stubIssueQuerier) Neighborhood(_ context.Context, _ secgraph.NodeType, _ string, _ int, _ int) (*secgraph.GraphQueryResult, error) {
	return &secgraph.GraphQueryResult{}, nil
}

func (s *stubIssueQuerier) Stats(_ context.Context) (*secgraph.GraphStats, error) {
	return &secgraph.GraphStats{}, nil
}

func (s *stubIssueQuerier) IssueStats(_ context.Context) (*secgraph.IssueStats, error) {
	return &secgraph.IssueStats{}, nil
}

func (s *stubIssueQuerier) Neighborhood(_ context.Context, _ secgraph.NodeType, _ string, _ int, _ int) (*secgraph.GraphQueryResult, error) {
	return &secgraph.GraphQueryResult{}, nil
}

func (s *stubIssueQuerier) Stats(_ context.Context) (*secgraph.GraphStats, error) {
	return &secgraph.GraphStats{Vertices: map[string]int64{}, Edges: map[string]int64{}}, nil
}

func TestIssuesEndpointsRequireAuth(t *testing.T) {
	_, router := testServer(t)

	for _, path := range []string{"/api/v1/issues", "/api/v1/issues/iss-1"} {
		rr := doRequest(t, router, "GET", path, "", "")
		assertStatus(t, rr, http.StatusUnauthorized)
	}
}

func TestIssuesEndpointsRequesterForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := requesterJWT(t)

	for _, path := range []string{"/api/v1/issues", "/api/v1/issues/iss-1"} {
		rr := doRequest(t, router, "GET", path, "", jwt)
		assertStatus(t, rr, http.StatusForbidden)
	}
}

func TestListIssuesNotConfigured(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", "/api/v1/issues", "", viewerJWT(t))
	assertStatus(t, rr, http.StatusNotImplemented)
}

func TestListIssuesPropagatesFiltersAndScope(t *testing.T) {
	srv, router := testServer(t)
	querier := &stubIssueQuerier{
		listFunc: func(_ context.Context, _ secgraph.IssueListParams) (*secgraph.IssueListResult, error) {
			return &secgraph.IssueListResult{
				Data: []secgraph.IssueSummary{
					{
						Issue: secgraph.Issue{
							ID:          "iss-1",
							Title:       "Public bucket with exploitable path",
							Severity:    "CRITICAL",
							Status:      secgraph.IssueOpen,
							AccountID:   "acc-1",
							Provider:    "aws",
							TenantID:    defaultSecgraphTenantID,
							CreatedAt:   time.Date(2026, time.March, 30, 10, 0, 0, 0, time.UTC),
							UpdatedAt:   time.Date(2026, time.March, 30, 11, 0, 0, 0, time.UTC),
							RiskScore:   98.5,
							BlastRadius: 4,
						},
						ControlTitle:    "Internet-exposed exploitable storage",
						ResourceName:    "bucket-a",
						Region:          "us-east-1",
						EnvironmentType: "production",
						LineOfBusiness:  "engineering",
						FindingCount:    2,
					},
				},
				Page:       2,
				PerPage:    10,
				Total:      25,
				TotalPages: 3,
			}, nil
		},
	}
	srv.graphQuerier = querier

	jwt := makeJWT(t, api.Claims{
		Subject: "test-viewer",
		Email:   "viewer@contoso.dev",
		Groups:  []string{"aegis-viewer"},
		Scope:   "viewer",
		ResourceScope: &api.ResourceScope{
			AccountIDs:    []string{"acc-1"},
			Regions:       []string{"us-east-1"},
			Environments:  []string{"production"},
			BusinessUnits: []string{"engineering"},
		},
	})

	rr := doRequest(t, router, "GET", "/api/v1/issues?severity=critical&status=open&provider=aws&account_id=acc-1&control_id=ctrl-1&resource_id=res-1&ticketed=true&sort=updated_at&order=asc&page=2&per_page=10", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp struct {
		Data       []secgraph.IssueSummary `json:"data"`
		Page       int                     `json:"page"`
		PerPage    int                     `json:"per_page"`
		Total      int                     `json:"total"`
		TotalPages int                     `json:"total_pages"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Total != 25 || resp.Page != 2 || resp.PerPage != 10 || resp.TotalPages != 3 {
		t.Fatalf("unexpected pagination response: %+v", resp)
	}
	if len(resp.Data) != 1 || resp.Data[0].ID != "iss-1" {
		t.Fatalf("unexpected issues payload: %+v", resp.Data)
	}
	if querier.listParams.TenantID != defaultSecgraphTenantID {
		t.Fatalf("tenant_id = %q, want %q", querier.listParams.TenantID, defaultSecgraphTenantID)
	}
	if querier.listParams.Severity != "CRITICAL" || querier.listParams.Status != "OPEN" {
		t.Fatalf("unexpected severity/status filter: %+v", querier.listParams)
	}
	if querier.listParams.Provider != "aws" || querier.listParams.AccountID != "acc-1" {
		t.Fatalf("unexpected provider/account filter: %+v", querier.listParams)
	}
	if querier.listParams.ControlID != "ctrl-1" || querier.listParams.ResourceID != "res-1" {
		t.Fatalf("unexpected control/resource filter: %+v", querier.listParams)
	}
	if querier.listParams.HasTicket == nil || !*querier.listParams.HasTicket {
		t.Fatalf("expected ticketed=true filter, got %+v", querier.listParams.HasTicket)
	}
	if querier.listParams.SortBy != "updated_at" || querier.listParams.SortOrder != "asc" {
		t.Fatalf("unexpected sort filter: %+v", querier.listParams)
	}
	if querier.listParams.Page != 2 || querier.listParams.PerPage != 10 {
		t.Fatalf("pagination = (%d,%d), want (2,10)", querier.listParams.Page, querier.listParams.PerPage)
	}
	if len(querier.listParams.ScopeAccountIDs) != 1 || querier.listParams.ScopeAccountIDs[0] != "acc-1" {
		t.Fatalf("scope account_ids = %+v", querier.listParams.ScopeAccountIDs)
	}
	if len(querier.listParams.ScopeRegions) != 1 || querier.listParams.ScopeRegions[0] != "us-east-1" {
		t.Fatalf("scope regions = %+v", querier.listParams.ScopeRegions)
	}
	if len(querier.listParams.ScopeEnvironments) != 1 || querier.listParams.ScopeEnvironments[0] != "production" {
		t.Fatalf("scope environments = %+v", querier.listParams.ScopeEnvironments)
	}
	if len(querier.listParams.ScopeBusinessUnits) != 1 || querier.listParams.ScopeBusinessUnits[0] != "engineering" {
		t.Fatalf("scope business units = %+v", querier.listParams.ScopeBusinessUnits)
	}
}

func TestListIssuesRejectsInvalidTicketedFilter(t *testing.T) {
	srv, router := testServer(t)
	srv.graphQuerier = &stubIssueQuerier{}

	rr := doRequest(t, router, "GET", "/api/v1/issues?ticketed=definitely", "", viewerJWT(t))
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestGetIssueNotFound(t *testing.T) {
	srv, router := testServer(t)
	srv.graphQuerier = &stubIssueQuerier{}

	rr := doRequest(t, router, "GET", "/api/v1/issues/iss-missing", "", viewerJWT(t))
	assertStatus(t, rr, http.StatusNotFound)
}

func TestGetIssueEnforcesScope(t *testing.T) {
	srv, router := testServer(t)
	srv.graphQuerier = &stubIssueQuerier{
		getFunc: func(_ context.Context, _ string, _ string) (*secgraph.IssueDetail, error) {
			return &secgraph.IssueDetail{
				Issue: secgraph.IssueSummary{
					Issue: secgraph.Issue{
						ID:        "iss-2",
						Title:     "Cross-account issue",
						Severity:  "HIGH",
						Status:    secgraph.IssueOpen,
						AccountID: "acc-2",
						TenantID:  defaultSecgraphTenantID,
					},
					Region:          "us-east-1",
					EnvironmentType: "production",
					LineOfBusiness:  "engineering",
				},
				FindingIDs: []string{"f-1"},
			}, nil
		},
	}

	jwt := makeJWT(t, api.Claims{
		Subject: "test-viewer",
		Email:   "viewer@contoso.dev",
		Groups:  []string{"aegis-viewer"},
		Scope:   "viewer",
		ResourceScope: &api.ResourceScope{
			AccountIDs:    []string{"acc-1"},
			Regions:       []string{"us-east-1"},
			Environments:  []string{"production"},
			BusinessUnits: []string{"engineering"},
		},
	})

	rr := doRequest(t, router, "GET", "/api/v1/issues/iss-2", "", jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestGetIssueReturnsDetail(t *testing.T) {
	srv, router := testServer(t)
	srv.graphQuerier = &stubIssueQuerier{
		getFunc: func(_ context.Context, tenantID, issueID string) (*secgraph.IssueDetail, error) {
			if tenantID != defaultSecgraphTenantID {
				t.Fatalf("tenant_id = %q, want %q", tenantID, defaultSecgraphTenantID)
			}
			if issueID != "iss-3" {
				t.Fatalf("issue_id = %q, want iss-3", issueID)
			}
			return &secgraph.IssueDetail{
				Issue: secgraph.IssueSummary{
					Issue: secgraph.Issue{
						ID:            "iss-3",
						Title:         "Exploit path to data store",
						Severity:      "CRITICAL",
						Status:        secgraph.IssueOpen,
						AccountID:     "acc-1",
						TenantID:      defaultSecgraphTenantID,
						ExposurePaths: 3,
					},
					ControlTitle:    "Externally exposed exploitable data path",
					ResourceName:    "db-prod",
					Region:          "us-east-1",
					EnvironmentType: "production",
					LineOfBusiness:  "engineering",
					FindingCount:    2,
				},
				FindingIDs: []string{"f-1", "f-2"},
			}, nil
		},
	}

	rr := doRequest(t, router, "GET", "/api/v1/issues/iss-3", "", viewerJWT(t))
	assertStatus(t, rr, http.StatusOK)

	var detail secgraph.IssueDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if detail.Issue.ID != "iss-3" || detail.Issue.ControlTitle == "" || len(detail.FindingIDs) != 2 {
		t.Fatalf("unexpected issue detail: %+v", detail)
	}
}
