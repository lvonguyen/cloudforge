package secgraph

import (
	"testing"
)

func TestIssueListParamsDefaults(t *testing.T) {
	params := IssueListParams{}
	if params.Page != 0 {
		t.Errorf("expected zero page, got %d", params.Page)
	}
	// ListIssues normalizes 0 → 1 internally
}

func TestIssueUpdateValidation(t *testing.T) {
	// Empty update should have all nil fields
	update := IssueUpdate{}
	if update.Status != nil {
		t.Error("expected nil status on empty update")
	}
	if update.AssigneeID != nil {
		t.Error("expected nil assignee on empty update")
	}

	// Populated update
	status := IssueResolved
	assignee := "user-123"
	update = IssueUpdate{
		Status:     &status,
		AssigneeID: &assignee,
	}
	if *update.Status != IssueResolved {
		t.Errorf("expected RESOLVED, got %v", *update.Status)
	}
	if *update.AssigneeID != "user-123" {
		t.Errorf("expected user-123, got %s", *update.AssigneeID)
	}
}

func TestIssueStatsStructure(t *testing.T) {
	stats := &IssueStats{
		BySeverity:     map[string]int{"CRITICAL": 5, "HIGH": 10},
		ByStatus:       map[string]int{"OPEN": 12, "RESOLVED": 3},
		ByProvider:     map[string]int{"aws": 8, "azure": 7},
		Total:          15,
		OpenCount:      12,
		SLABreachCount: 2,
	}

	if stats.Total != 15 {
		t.Errorf("expected 15 total, got %d", stats.Total)
	}
	if stats.OpenCount != 12 {
		t.Errorf("expected 12 open, got %d", stats.OpenCount)
	}
	if stats.SLABreachCount != 2 {
		t.Errorf("expected 2 SLA breaches, got %d", stats.SLABreachCount)
	}
	if stats.BySeverity["CRITICAL"] != 5 {
		t.Errorf("expected 5 CRITICAL, got %d", stats.BySeverity["CRITICAL"])
	}
}

func TestIssueDetailStructure(t *testing.T) {
	detail := &IssueDetail{
		Issue: Issue{
			ID:       "ISS-001",
			Title:    "S3 encryption missing",
			Severity: "HIGH",
			Status:   IssueOpen,
		},
		FindingIDs: []string{"F-001", "F-002"},
	}

	if detail.Issue.ID != "ISS-001" {
		t.Errorf("expected ISS-001, got %s", detail.Issue.ID)
	}
	if len(detail.FindingIDs) != 2 {
		t.Errorf("expected 2 finding IDs, got %d", len(detail.FindingIDs))
	}
}

func TestIssueListResultPagination(t *testing.T) {
	result := &IssueListResult{
		Data:       []Issue{{ID: "ISS-001"}, {ID: "ISS-002"}},
		Page:       1,
		PerPage:    25,
		Total:      50,
		TotalPages: 2,
	}

	if len(result.Data) != 2 {
		t.Errorf("expected 2 issues, got %d", len(result.Data))
	}
	if result.TotalPages != 2 {
		t.Errorf("expected 2 total pages, got %d", result.TotalPages)
	}
}

func TestIssueQuerierInterfaceCompliance(t *testing.T) {
	// Compile-time check that PostgresQuerier implements IssueQuerier
	var _ IssueQuerier = (*PostgresQuerier)(nil)
}
