package secgraph

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// IssueListParams controls filtering and pagination for ListIssues.
type IssueListParams struct {
	TenantID           string
	Severity           string // filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
	Status             string // filter by status (OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, SUPPRESSED)
	ControlID          string // filter by control
	AccountID          string // filter by account
	ResourceID         string // filter by resource
	Provider           string // filter by cloud provider
	HasTicket          *bool
	SortBy             string
	SortOrder          string
	ScopeAccountIDs    []string
	ScopeRegions       []string
	ScopeEnvironments  []string
	ScopeBusinessUnits []string
	Page               int
	PerPage            int
}

// IssueListResult is a paginated list of issues.
type IssueListResult struct {
	Data       []IssueSummary `json:"data"`
	Page       int            `json:"page"`
	PerPage    int            `json:"per_page"`
	Total      int            `json:"total"`
	TotalPages int            `json:"total_pages"`
}

// IssueDetail is an issue with its related finding IDs.
type IssueDetail struct {
	Issue      IssueSummary `json:"issue"`
	FindingIDs []string     `json:"finding_ids"`
}

// IssueStats summarizes issue counts by severity and status.
type IssueStats struct {
	BySeverity     map[string]int `json:"by_severity"`
	ByStatus       map[string]int `json:"by_status"`
	ByProvider     map[string]int `json:"by_provider"`
	Total          int            `json:"total"`
	OpenCount      int            `json:"open_count"`
	SLABreachCount int            `json:"sla_breach_count"`
}

// IssueUpdate is the set of mutable fields on an issue.
type IssueUpdate struct {
	Status     *IssueStatus `json:"status,omitempty"`
	AssigneeID *string      `json:"assignee_id,omitempty"`
	TicketID   *string      `json:"ticket_id,omitempty"`
	TicketURL  *string      `json:"ticket_url,omitempty"`
}

// IssueQuerier reads and writes issues.
type IssueQuerier interface {
	ListIssues(ctx context.Context, params IssueListParams) (*IssueListResult, error)
	GetIssue(ctx context.Context, tenantID, id string) (*IssueDetail, error)
	UpdateIssue(ctx context.Context, tenantID, id string, update IssueUpdate) (*Issue, error)
	IssueStats(ctx context.Context, tenantID string) (*IssueStats, error)
}

// Ensure PostgresQuerier implements IssueQuerier.
var _ IssueQuerier = (*PostgresQuerier)(nil)

// ListIssues returns a paginated, filterable list of issues.
func (q *PostgresQuerier) ListIssues(ctx context.Context, params IssueListParams) (*IssueListResult, error) {
	issues, total, err := NewStore(q.db).ListIssues(ctx, IssueListFilter{
		TenantID:           params.TenantID,
		Severity:           params.Severity,
		Status:             params.Status,
		Provider:           params.Provider,
		AccountID:          params.AccountID,
		ControlID:          params.ControlID,
		ResourceID:         params.ResourceID,
		HasTicket:          params.HasTicket,
		SortBy:             params.SortBy,
		SortOrder:          params.SortOrder,
		ScopeAccountIDs:    params.ScopeAccountIDs,
		ScopeRegions:       params.ScopeRegions,
		ScopeEnvironments:  params.ScopeEnvironments,
		ScopeBusinessUnits: params.ScopeBusinessUnits,
	}, params.Page, params.PerPage)
	if err != nil {
		return nil, fmt.Errorf("list issues: %w", err)
	}

	page := params.Page
	if page <= 0 {
		page = 1
	}
	perPage := params.PerPage
	if perPage <= 0 || perPage > 200 {
		perPage = 50
	}
	totalPages := total / perPage
	if total%perPage > 0 {
		totalPages++
	}
	if totalPages == 0 {
		totalPages = 1
	}

	return &IssueListResult{
		Data:       issues,
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}, nil
}

// GetIssue returns a single issue with its related finding IDs.
func (q *PostgresQuerier) GetIssue(ctx context.Context, tenantID, id string) (*IssueDetail, error) {
	detail, err := NewStore(q.db).GetIssue(ctx, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("get issue %s: %w", id, err)
	}
	return detail, nil
}

// UpdateIssue applies partial updates to an issue and returns the updated row.
func (q *PostgresQuerier) UpdateIssue(ctx context.Context, tenantID, id string, update IssueUpdate) (*Issue, error) {
	var setClauses []string
	var args []interface{}
	argN := 1

	if update.Status != nil {
		switch *update.Status {
		case IssueOpen, IssueAcknowledged, IssueInProgress, IssueResolved, IssueSuppressed:
			// valid
		default:
			return nil, fmt.Errorf("invalid issue status: %q", *update.Status)
		}
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argN))
		args = append(args, string(*update.Status))
		argN++

		if *update.Status == IssueResolved {
			now := time.Now().UTC()
			setClauses = append(setClauses, fmt.Sprintf("resolved_at = $%d", argN))
			args = append(args, now)
			argN++
		}
	}
	if update.AssigneeID != nil {
		setClauses = append(setClauses, fmt.Sprintf("assignee_id = $%d", argN))
		args = append(args, *update.AssigneeID)
		argN++
	}
	if update.TicketID != nil {
		setClauses = append(setClauses, fmt.Sprintf("ticket_id = $%d", argN))
		args = append(args, *update.TicketID)
		argN++
	}
	if update.TicketURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("ticket_url = $%d", argN))
		args = append(args, *update.TicketURL)
		argN++
	}

	if len(setClauses) == 0 {
		return nil, fmt.Errorf("no fields to update")
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argN))
	args = append(args, time.Now().UTC())
	argN++

	if tenantID == "" {
		tenantID = "default"
	}
	args = append(args, id, tenantID)
	query := fmt.Sprintf("UPDATE issues SET %s WHERE id = $%d AND tenant_id = $%d RETURNING id, title, description, severity, risk_score, blast_radius, status, COALESCE(control_id,''), COALESCE(resource_id,''), COALESCE(account_id,''), COALESCE(provider,''), COALESCE(assignee_id,''), COALESCE(ticket_id,''), COALESCE(ticket_url,''), sla_breach_at, exposure_paths, tenant_id, created_at, updated_at, resolved_at", //nolint:gosec // G201: setClauses built from allowlisted field names, argN is an integer counter — no user input in SQL
		strings.Join(setClauses, ", "), argN, argN+1)

	var iss Issue
	err := q.db.QueryRowContext(ctx, query, args...).Scan(
		&iss.ID, &iss.Title, &iss.Description, &iss.Severity, &iss.RiskScore,
		&iss.BlastRadius, &iss.Status, &iss.ControlID, &iss.ResourceID,
		&iss.AccountID, &iss.Provider, &iss.AssigneeID, &iss.TicketID,
		&iss.TicketURL, &iss.SLABreachAt, &iss.ExposurePaths, &iss.TenantID,
		&iss.CreatedAt, &iss.UpdatedAt, &iss.ResolvedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update issue %s: %w", id, err)
	}

	return &iss, nil
}

// IssueStats returns aggregate counts by severity, status, and provider.
func (q *PostgresQuerier) IssueStats(ctx context.Context, tenantID string) (*IssueStats, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	stats := &IssueStats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
		ByProvider: make(map[string]int),
	}

	// Severity counts
	sevRows, err := q.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM issues WHERE tenant_id = $1 GROUP BY severity`, tenantID)
	if err != nil {
		return stats, nil
	}
	for sevRows.Next() {
		var sev string
		var count int
		if sevRows.Scan(&sev, &count) == nil {
			stats.BySeverity[sev] = count
			stats.Total += count
		}
	}
	sevRows.Close()

	// Status counts
	statRows, err := q.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM issues WHERE tenant_id = $1 GROUP BY status`, tenantID)
	if err != nil {
		return stats, nil
	}
	for statRows.Next() {
		var status string
		var count int
		if statRows.Scan(&status, &count) == nil {
			stats.ByStatus[status] = count
			if status == string(IssueOpen) {
				stats.OpenCount = count
			}
		}
	}
	statRows.Close()

	// Provider counts
	provRows, err := q.db.QueryContext(ctx,
		`SELECT COALESCE(provider,'unknown'), COUNT(*) FROM issues WHERE tenant_id = $1 GROUP BY provider`, tenantID)
	if err != nil {
		return stats, nil
	}
	for provRows.Next() {
		var prov string
		var count int
		if provRows.Scan(&prov, &count) == nil {
			stats.ByProvider[prov] = count
		}
	}
	provRows.Close()

	// SLA breach count
	_ = q.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM issues WHERE tenant_id = $1 AND sla_breach_at IS NOT NULL AND sla_breach_at < NOW() AND status != 'RESOLVED'`, tenantID).
		Scan(&stats.SLABreachCount)

	return stats, nil
}
