package secgraph

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// IssueListParams controls filtering and pagination for ListIssues.
type IssueListParams struct {
	Severity  string // filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
	Status    string // filter by status (OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, SUPPRESSED)
	ControlID string // filter by control
	AccountID string // filter by account
	Provider  string // filter by cloud provider
	Page      int
	PerPage   int
}

// IssueListResult is a paginated list of issues.
type IssueListResult struct {
	Data       []Issue `json:"data"`
	Page       int     `json:"page"`
	PerPage    int     `json:"per_page"`
	Total      int     `json:"total"`
	TotalPages int     `json:"total_pages"`
}

// IssueDetail is an issue with its related finding IDs.
type IssueDetail struct {
	Issue      Issue    `json:"issue"`
	FindingIDs []string `json:"finding_ids"`
}

// IssueStats summarizes issue counts by severity and status.
type IssueStats struct {
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
	ByProvider map[string]int `json:"by_provider"`
	Total      int            `json:"total"`
	OpenCount  int            `json:"open_count"`
	SLABreachCount int        `json:"sla_breach_count"`
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
	GetIssue(ctx context.Context, id string) (*IssueDetail, error)
	UpdateIssue(ctx context.Context, id string, update IssueUpdate) (*Issue, error)
	IssueStats(ctx context.Context) (*IssueStats, error)
}

// Ensure PostgresQuerier implements IssueQuerier.
var _ IssueQuerier = (*PostgresQuerier)(nil)

// ListIssues returns a paginated, filterable list of issues.
func (q *PostgresQuerier) ListIssues(ctx context.Context, params IssueListParams) (*IssueListResult, error) {
	if params.Page <= 0 {
		params.Page = 1
	}
	if params.PerPage <= 0 || params.PerPage > 100 {
		params.PerPage = 25
	}

	var where []string
	var args []interface{}
	argN := 1

	if params.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", argN))
		args = append(args, params.Severity)
		argN++
	}
	if params.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", argN))
		args = append(args, params.Status)
		argN++
	}
	if params.ControlID != "" {
		where = append(where, fmt.Sprintf("control_id = $%d", argN))
		args = append(args, params.ControlID)
		argN++
	}
	if params.AccountID != "" {
		where = append(where, fmt.Sprintf("account_id = $%d", argN))
		args = append(args, params.AccountID)
		argN++
	}
	if params.Provider != "" {
		where = append(where, fmt.Sprintf("provider = $%d", argN))
		args = append(args, params.Provider)
		argN++
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM issues " + whereClause
	if err := q.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count issues: %w", err)
	}

	// Fetch page
	offset := (params.Page - 1) * params.PerPage
	args = append(args, params.PerPage, offset)
	dataQuery := fmt.Sprintf(`SELECT id, title, description, severity, risk_score, blast_radius,
		status, COALESCE(control_id,''), COALESCE(resource_id,''), COALESCE(account_id,''),
		COALESCE(provider,''), COALESCE(assignee_id,''), COALESCE(ticket_id,''),
		COALESCE(ticket_url,''), sla_breach_at, exposure_paths, tenant_id,
		created_at, updated_at, resolved_at
		FROM issues %s ORDER BY risk_score DESC, created_at DESC LIMIT $%d OFFSET $%d`,
		whereClause, argN, argN+1)

	rows, err := q.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("list issues: %w", err)
	}
	defer rows.Close()

	issues := make([]Issue, 0)
	for rows.Next() {
		var iss Issue
		if err := rows.Scan(
			&iss.ID, &iss.Title, &iss.Description, &iss.Severity, &iss.RiskScore,
			&iss.BlastRadius, &iss.Status, &iss.ControlID, &iss.ResourceID,
			&iss.AccountID, &iss.Provider, &iss.AssigneeID, &iss.TicketID,
			&iss.TicketURL, &iss.SLABreachAt, &iss.ExposurePaths, &iss.TenantID,
			&iss.CreatedAt, &iss.UpdatedAt, &iss.ResolvedAt,
		); err != nil {
			return nil, fmt.Errorf("scan issue: %w", err)
		}
		issues = append(issues, iss)
	}

	totalPages := total / params.PerPage
	if total%params.PerPage > 0 {
		totalPages++
	}

	return &IssueListResult{
		Data:       issues,
		Page:       params.Page,
		PerPage:    params.PerPage,
		Total:      total,
		TotalPages: totalPages,
	}, nil
}

// GetIssue returns a single issue with its related finding IDs.
func (q *PostgresQuerier) GetIssue(ctx context.Context, id string) (*IssueDetail, error) {
	var iss Issue
	err := q.db.QueryRowContext(ctx, `SELECT id, title, description, severity, risk_score, blast_radius,
		status, COALESCE(control_id,''), COALESCE(resource_id,''), COALESCE(account_id,''),
		COALESCE(provider,''), COALESCE(assignee_id,''), COALESCE(ticket_id,''),
		COALESCE(ticket_url,''), sla_breach_at, exposure_paths, tenant_id,
		created_at, updated_at, resolved_at
		FROM issues WHERE id = $1`, id).Scan(
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
		return nil, fmt.Errorf("get issue %s: %w", id, err)
	}

	// Fetch related finding IDs
	rows, err := q.db.QueryContext(ctx,
		`SELECT finding_id FROM issue_findings WHERE issue_id = $1 ORDER BY created_at`, id)
	if err != nil {
		return &IssueDetail{Issue: iss}, nil // partial result
	}
	defer rows.Close()

	var findingIDs []string
	for rows.Next() {
		var fid string
		if err := rows.Scan(&fid); err != nil {
			continue
		}
		findingIDs = append(findingIDs, fid)
	}

	return &IssueDetail{Issue: iss, FindingIDs: findingIDs}, nil
}

// UpdateIssue applies partial updates to an issue and returns the updated row.
func (q *PostgresQuerier) UpdateIssue(ctx context.Context, id string, update IssueUpdate) (*Issue, error) {
	var setClauses []string
	var args []interface{}
	argN := 1

	if update.Status != nil {
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

	args = append(args, id)
	query := fmt.Sprintf("UPDATE issues SET %s WHERE id = $%d RETURNING id, title, description, severity, risk_score, blast_radius, status, COALESCE(control_id,''), COALESCE(resource_id,''), COALESCE(account_id,''), COALESCE(provider,''), COALESCE(assignee_id,''), COALESCE(ticket_id,''), COALESCE(ticket_url,''), sla_breach_at, exposure_paths, tenant_id, created_at, updated_at, resolved_at",
		strings.Join(setClauses, ", "), argN)

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
func (q *PostgresQuerier) IssueStats(ctx context.Context) (*IssueStats, error) {
	stats := &IssueStats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
		ByProvider: make(map[string]int),
	}

	// Severity counts
	sevRows, err := q.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM issues GROUP BY severity`)
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
		`SELECT status, COUNT(*) FROM issues GROUP BY status`)
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
		`SELECT COALESCE(provider,'unknown'), COUNT(*) FROM issues GROUP BY provider`)
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
		`SELECT COUNT(*) FROM issues WHERE sla_breach_at IS NOT NULL AND sla_breach_at < NOW() AND status != 'RESOLVED'`).
		Scan(&stats.SLABreachCount)

	return stats, nil
}

// Compile-time unused import guard for pq
var _ = pq.Array
