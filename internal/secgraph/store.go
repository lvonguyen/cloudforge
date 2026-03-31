package secgraph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// IssueReader exposes secgraph issues as a first-class operator surface.
type IssueReader interface {
	ListIssues(ctx context.Context, filter IssueListFilter, page, perPage int) ([]IssueSummary, int, error)
	GetIssue(ctx context.Context, tenantID, issueID string) (*IssueDetail, error)
}

// Store persists secgraph controls, evaluations, issues, and edges.
// Runtime wiring can depend on this without embedding SQL strings elsewhere.
type Store struct {
	db *sql.DB
}

// NewStore creates a secgraph store backed by a SQL database handle.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// UpsertControls persists control definitions into the controls table.
func (s *Store) UpsertControls(ctx context.Context, controls []Control) error {
	if s == nil || s.db == nil || len(controls) == 0 {
		return nil
	}

	const query = `
		INSERT INTO controls (
			id, framework_id, title, description, category, severity, provider,
			resource_types, eval_logic_ref, auto_remediable, remediation_ref,
			keywords, status, tenant_id, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			$12, $13, $14, $15, $16
		)
		ON CONFLICT (id) DO UPDATE SET
			framework_id = EXCLUDED.framework_id,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			category = EXCLUDED.category,
			severity = EXCLUDED.severity,
			provider = EXCLUDED.provider,
			resource_types = EXCLUDED.resource_types,
			eval_logic_ref = EXCLUDED.eval_logic_ref,
			auto_remediable = EXCLUDED.auto_remediable,
			remediation_ref = EXCLUDED.remediation_ref,
			keywords = EXCLUDED.keywords,
			status = EXCLUDED.status,
			tenant_id = EXCLUDED.tenant_id,
			updated_at = EXCLUDED.updated_at
	`

	for _, control := range controls {
		if _, err := s.db.ExecContext(ctx, query,
			control.ID,
			control.FrameworkID,
			control.Title,
			control.Description,
			control.Category,
			control.Severity,
			control.Provider,
			pq.Array(control.ResourceTypes),
			control.EvalLogicRef,
			control.AutoRemediable,
			control.RemediationRef,
			pq.Array(control.Keywords),
			string(control.Status),
			control.TenantID,
			control.CreatedAt,
			control.UpdatedAt,
		); err != nil {
			return fmt.Errorf("upserting control %s: %w", control.ID, err)
		}
	}

	return nil
}

// UpsertMaterialization persists evaluations, issues, issue-finding links, and graph edges.
func (s *Store) UpsertMaterialization(ctx context.Context, result MaterializationResult) error {
	if s == nil || s.db == nil {
		return nil
	}

	for _, evaluation := range result.Evaluations {
		if err := s.upsertEvaluation(ctx, evaluation); err != nil {
			return err
		}
	}
	for _, issue := range result.Issues {
		if err := s.upsertIssue(ctx, issue); err != nil {
			return err
		}
	}
	for _, link := range result.IssueFindings {
		if err := s.upsertIssueFinding(ctx, link); err != nil {
			return err
		}
	}
	for _, edge := range result.Edges {
		if err := s.upsertEdge(ctx, edge); err != nil {
			return err
		}
	}

	return nil
}

// ReconcileStaleMaterialization prunes stale finding->issue links for a tenant
// after a full sync and resolves any issues that no longer have source findings.
func (s *Store) ReconcileStaleMaterialization(ctx context.Context, tenantID string, activeFindingIDs []string, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = "default"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin stale materialization reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		deleteIssueFindingsQuery string
		deleteEdgesQuery         string
		args                     []any
	)
	if len(activeFindingIDs) == 0 {
		deleteIssueFindingsQuery = `
			DELETE FROM issue_findings ifl
			USING issues i
			WHERE i.id = ifl.issue_id
			  AND i.tenant_id = $1
		`
		deleteEdgesQuery = `
			DELETE FROM graph_edges ge
			USING issues i
			WHERE ge.target_type = 'issue'
			  AND ge.edge_type = 'materializes_to'
			  AND ge.target_id = i.id
			  AND ge.tenant_id = $1
			  AND i.tenant_id = $1
		`
		args = []any{tenantID}
	} else {
		deleteIssueFindingsQuery = `
			DELETE FROM issue_findings ifl
			USING issues i
			WHERE i.id = ifl.issue_id
			  AND i.tenant_id = $1
			  AND NOT (ifl.finding_id = ANY($2))
		`
		deleteEdgesQuery = `
			DELETE FROM graph_edges ge
			USING issues i
			WHERE ge.target_type = 'issue'
			  AND ge.edge_type = 'materializes_to'
			  AND ge.target_id = i.id
			  AND ge.tenant_id = $1
			  AND i.tenant_id = $1
			  AND NOT (ge.source_id = ANY($2))
		`
		args = []any{tenantID, pq.Array(activeFindingIDs)}
	}

	if _, err := tx.ExecContext(ctx, deleteIssueFindingsQuery, args...); err != nil {
		return fmt.Errorf("delete stale issue_finding links: %w", err)
	}
	if _, err := tx.ExecContext(ctx, deleteEdgesQuery, args...); err != nil {
		return fmt.Errorf("delete stale materializes_to edges: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE issues i
		SET status = 'RESOLVED',
		    resolved_at = COALESCE(i.resolved_at, $2),
		    updated_at = $2
		WHERE i.tenant_id = $1
		  AND i.status NOT IN ('RESOLVED', 'SUPPRESSED')
		  AND NOT EXISTS (
			SELECT 1
			FROM issue_findings ifl
			WHERE ifl.issue_id = i.id
		  )
	`, tenantID, now.UTC()); err != nil {
		return fmt.Errorf("resolve stale issues: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE control_evaluations ce
		SET status = 'PASS',
		    evidence = ARRAY[]::text[],
		    evaluated_at = $2
		WHERE ce.tenant_id = $1
		  AND NOT EXISTS (
			SELECT 1
			FROM issues i
			JOIN issue_findings ifl ON ifl.issue_id = i.id
			WHERE i.tenant_id = ce.tenant_id
			  AND i.control_id = ce.control_id
			  AND i.resource_id = ce.resource_id
		  )
	`, tenantID, now.UTC()); err != nil {
		return fmt.Errorf("resolve stale evaluations: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit stale materialization reconciliation: %w", err)
	}
	return nil
}

// ListIssues returns a paginated operator-facing issue list for a tenant.
func (s *Store) ListIssues(ctx context.Context, filter IssueListFilter, page, perPage int) ([]IssueSummary, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, nil
	}
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 200 {
		perPage = 200
	}

	whereSQL, args := buildIssueWhereClause(filter)
	countQuery := `
		SELECT COUNT(DISTINCT i.id)
		FROM issues i
		LEFT JOIN resources r ON r.id = i.resource_id
		LEFT JOIN accounts a ON a.id = i.account_id
	` + whereSQL

	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count issues: %w", err)
	}

	offset := (page - 1) * perPage
	args = append(args, perPage, offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	listQuery := `
		SELECT
			i.id, i.title, i.description, i.severity, i.risk_score, i.blast_radius, i.status,
			i.control_id, i.resource_id, i.account_id, i.provider, i.assignee_id, i.ticket_id,
			i.ticket_url, i.sla_breach_at, i.exposure_paths, i.tenant_id, i.created_at,
			i.updated_at, i.resolved_at,
			COALESCE(c.title, ''),
			COALESCE(NULLIF(r.name, ''), r.id, ''),
			COALESCE(r.region, ''),
			COALESCE(a.environment_type, ''),
			COALESCE(MAX(NULLIF(f.line_of_business, '')), ''),
			COUNT(DISTINCT ifl.finding_id)::int
		FROM issues i
		LEFT JOIN controls c ON c.id = i.control_id
		LEFT JOIN resources r ON r.id = i.resource_id
		LEFT JOIN accounts a ON a.id = i.account_id
		LEFT JOIN issue_findings ifl ON ifl.issue_id = i.id
		LEFT JOIN findings f ON f.id = ifl.finding_id
	` + whereSQL + `
		GROUP BY i.id, c.title, r.name, r.id, r.region, a.environment_type
	` + buildIssueSortClause(filter) + fmt.Sprintf(`
		LIMIT $%d OFFSET $%d
	`, limitArg, offsetArg)

	rows, err := s.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list issues: %w", err)
	}
	defer rows.Close()

	issues := make([]IssueSummary, 0, min(total, perPage))
	for rows.Next() {
		issue, err := scanIssueSummary(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan issue summary: %w", err)
		}
		issues = append(issues, issue)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate issues: %w", err)
	}

	return issues, total, nil
}

// GetIssue returns a single operator-facing issue detail payload for a tenant.
func (s *Store) GetIssue(ctx context.Context, tenantID, issueID string) (*IssueDetail, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}

	query := `
		SELECT
			i.id, i.title, i.description, i.severity, i.risk_score, i.blast_radius, i.status,
			i.control_id, i.resource_id, i.account_id, i.provider, i.assignee_id, i.ticket_id,
			i.ticket_url, i.sla_breach_at, i.exposure_paths, i.tenant_id, i.created_at,
			i.updated_at, i.resolved_at,
			COALESCE(c.title, ''),
			COALESCE(NULLIF(r.name, ''), r.id, ''),
			COALESCE(r.region, ''),
			COALESCE(a.environment_type, ''),
			COALESCE(MAX(NULLIF(f.line_of_business, '')), ''),
			COUNT(DISTINCT ifl.finding_id)::int,
			COALESCE(ARRAY_REMOVE(ARRAY_AGG(DISTINCT ifl.finding_id), NULL), ARRAY[]::text[])
		FROM issues i
		LEFT JOIN controls c ON c.id = i.control_id
		LEFT JOIN resources r ON r.id = i.resource_id
		LEFT JOIN accounts a ON a.id = i.account_id
		LEFT JOIN issue_findings ifl ON ifl.issue_id = i.id
		LEFT JOIN findings f ON f.id = ifl.finding_id
		WHERE i.tenant_id = $1 AND i.id = $2
		GROUP BY i.id, c.title, r.name, r.id, r.region, a.environment_type
	`

	var (
		detail          IssueDetail
		status          string
		assigneeID      sql.NullString
		ticketID        sql.NullString
		ticketURL       sql.NullString
		slaBreachAt     sql.NullTime
		resolvedAt      sql.NullTime
		controlTitle    string
		resourceName    string
		region          string
		environmentType string
		lineOfBusiness  string
		findingCount    int
		findingIDs      []string
	)
	row := s.db.QueryRowContext(ctx, query, tenantID, issueID)
	err := row.Scan(
		&detail.Issue.ID,
		&detail.Issue.Title,
		&detail.Issue.Description,
		&detail.Issue.Severity,
		&detail.Issue.RiskScore,
		&detail.Issue.BlastRadius,
		&status,
		&detail.Issue.ControlID,
		&detail.Issue.ResourceID,
		&detail.Issue.AccountID,
		&detail.Issue.Provider,
		&assigneeID,
		&ticketID,
		&ticketURL,
		&slaBreachAt,
		&detail.Issue.ExposurePaths,
		&detail.Issue.TenantID,
		&detail.Issue.CreatedAt,
		&detail.Issue.UpdatedAt,
		&resolvedAt,
		&controlTitle,
		&resourceName,
		&region,
		&environmentType,
		&lineOfBusiness,
		&findingCount,
		pq.Array(&findingIDs),
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query issue %s: %w", issueID, err)
	}
	detail.Issue.Status = IssueStatus(status)
	detail.Issue.ControlTitle = strings.TrimSpace(controlTitle)
	detail.Issue.ResourceName = strings.TrimSpace(resourceName)
	detail.Issue.Region = strings.TrimSpace(region)
	detail.Issue.EnvironmentType = strings.TrimSpace(environmentType)
	detail.Issue.LineOfBusiness = strings.TrimSpace(lineOfBusiness)
	detail.Issue.FindingCount = findingCount
	detail.Issue.AssigneeID = strings.TrimSpace(assigneeID.String)
	detail.Issue.TicketID = strings.TrimSpace(ticketID.String)
	detail.Issue.TicketURL = strings.TrimSpace(ticketURL.String)
	if slaBreachAt.Valid {
		value := slaBreachAt.Time.UTC()
		detail.Issue.SLABreachAt = &value
	}
	if resolvedAt.Valid {
		value := resolvedAt.Time.UTC()
		detail.Issue.ResolvedAt = &value
	}
	detail.FindingIDs = findingIDs
	return &detail, nil
}

func (s *Store) upsertEvaluation(ctx context.Context, evaluation ControlEvaluation) error {
	const query = `
		INSERT INTO control_evaluations (
			id, control_id, resource_id, status, evidence, evaluated_at, tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (control_id, resource_id, tenant_id) DO UPDATE SET
			id = EXCLUDED.id,
			status = EXCLUDED.status,
			evidence = EXCLUDED.evidence,
			evaluated_at = EXCLUDED.evaluated_at
	`

	if _, err := s.db.ExecContext(ctx, query,
		evaluation.ID,
		evaluation.ControlID,
		evaluation.ResourceID,
		string(evaluation.Status),
		pq.Array(evaluation.Evidence),
		evaluation.EvaluatedAt,
		evaluation.TenantID,
	); err != nil {
		return fmt.Errorf("upserting evaluation %s: %w", evaluation.ID, err)
	}

	return nil
}

func (s *Store) upsertIssue(ctx context.Context, issue Issue) error {
	const query = `
		INSERT INTO issues (
			id, title, description, severity, risk_score, blast_radius, status,
			control_id, resource_id, account_id, provider, assignee_id, ticket_id,
			ticket_url, sla_breach_at, exposure_paths, tenant_id, created_at,
			updated_at, resolved_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18,
			$19, $20
		)
		ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			severity = EXCLUDED.severity,
			risk_score = EXCLUDED.risk_score,
			blast_radius = EXCLUDED.blast_radius,
			status = EXCLUDED.status,
			control_id = EXCLUDED.control_id,
			resource_id = EXCLUDED.resource_id,
			account_id = EXCLUDED.account_id,
			provider = EXCLUDED.provider,
			assignee_id = EXCLUDED.assignee_id,
			ticket_id = EXCLUDED.ticket_id,
			ticket_url = EXCLUDED.ticket_url,
			sla_breach_at = EXCLUDED.sla_breach_at,
			exposure_paths = EXCLUDED.exposure_paths,
			tenant_id = EXCLUDED.tenant_id,
			updated_at = EXCLUDED.updated_at,
			resolved_at = EXCLUDED.resolved_at
	`

	if _, err := s.db.ExecContext(ctx, query,
		issue.ID,
		issue.Title,
		issue.Description,
		issue.Severity,
		issue.RiskScore,
		issue.BlastRadius,
		string(issue.Status),
		issue.ControlID,
		issue.ResourceID,
		issue.AccountID,
		issue.Provider,
		issue.AssigneeID,
		issue.TicketID,
		issue.TicketURL,
		issue.SLABreachAt,
		issue.ExposurePaths,
		issue.TenantID,
		issue.CreatedAt,
		issue.UpdatedAt,
		issue.ResolvedAt,
	); err != nil {
		return fmt.Errorf("upserting issue %s: %w", issue.ID, err)
	}

	return nil
}

func (s *Store) upsertIssueFinding(ctx context.Context, link IssueFindingLink) error {
	const query = `
		INSERT INTO issue_findings (issue_id, finding_id, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (issue_id, finding_id) DO NOTHING
	`

	if _, err := s.db.ExecContext(ctx, query, link.IssueID, link.FindingID, link.CreatedAt); err != nil {
		return fmt.Errorf("upserting issue_finding %s/%s: %w", link.IssueID, link.FindingID, err)
	}

	return nil
}

func (s *Store) upsertEdge(ctx context.Context, edge GraphEdge) error {
	const query = `
		INSERT INTO graph_edges (
			id, source_type, source_id, target_type, target_id, edge_type, properties, tenant_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (source_type, source_id, target_type, target_id, edge_type, tenant_id) DO NOTHING
	`

	payload, err := json.Marshal(edge.Properties)
	if err != nil {
		return fmt.Errorf("marshalling edge %s properties: %w", edge.ID, err)
	}
	if _, err := s.db.ExecContext(ctx, query,
		edge.ID,
		string(edge.SourceType),
		edge.SourceID,
		string(edge.TargetType),
		edge.TargetID,
		string(edge.EdgeType),
		payload,
		edge.TenantID,
		edge.CreatedAt,
	); err != nil {
		return fmt.Errorf("upserting edge %s: %w", edge.ID, err)
	}

	return nil
}

type issueSummaryScanner interface {
	Scan(dest ...any) error
}

func scanIssueSummary(scanner issueSummaryScanner) (IssueSummary, error) {
	var issue IssueSummary
	err := scanIssueSummaryInto(scanner, &issue)
	return issue, err
}

func scanIssueSummaryInto(scanner issueSummaryScanner, issue *IssueSummary) error {
	if issue == nil {
		return fmt.Errorf("issue summary destination is nil")
	}

	var (
		status          string
		assigneeID      sql.NullString
		ticketID        sql.NullString
		ticketURL       sql.NullString
		slaBreachAt     sql.NullTime
		resolvedAt      sql.NullTime
		controlTitle    string
		resourceName    string
		region          string
		environmentType string
		lineOfBusiness  string
		findingCount    int
	)
	if err := scanner.Scan(
		&issue.ID,
		&issue.Title,
		&issue.Description,
		&issue.Severity,
		&issue.RiskScore,
		&issue.BlastRadius,
		&status,
		&issue.ControlID,
		&issue.ResourceID,
		&issue.AccountID,
		&issue.Provider,
		&assigneeID,
		&ticketID,
		&ticketURL,
		&slaBreachAt,
		&issue.ExposurePaths,
		&issue.TenantID,
		&issue.CreatedAt,
		&issue.UpdatedAt,
		&resolvedAt,
		&controlTitle,
		&resourceName,
		&region,
		&environmentType,
		&lineOfBusiness,
		&findingCount,
	); err != nil {
		return err
	}

	issue.Status = IssueStatus(status)
	issue.ControlTitle = strings.TrimSpace(controlTitle)
	issue.ResourceName = strings.TrimSpace(resourceName)
	issue.Region = strings.TrimSpace(region)
	issue.EnvironmentType = strings.TrimSpace(environmentType)
	issue.LineOfBusiness = strings.TrimSpace(lineOfBusiness)
	issue.FindingCount = findingCount
	issue.AssigneeID = strings.TrimSpace(assigneeID.String)
	issue.TicketID = strings.TrimSpace(ticketID.String)
	issue.TicketURL = strings.TrimSpace(ticketURL.String)
	if slaBreachAt.Valid {
		value := slaBreachAt.Time.UTC()
		issue.SLABreachAt = &value
	}
	if resolvedAt.Valid {
		value := resolvedAt.Time.UTC()
		issue.ResolvedAt = &value
	}

	return nil
}

func buildIssueWhereClause(filter IssueListFilter) (string, []any) {
	tenantID := strings.TrimSpace(filter.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}

	clauses := []string{"i.tenant_id = $1"}
	args := []any{tenantID}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}

	if severity := strings.ToUpper(strings.TrimSpace(filter.Severity)); severity != "" {
		add("UPPER(i.severity) = $%d", severity)
	}
	if status := strings.ToUpper(strings.TrimSpace(filter.Status)); status != "" {
		add("UPPER(i.status) = $%d", status)
	}
	if provider := strings.ToLower(strings.TrimSpace(filter.Provider)); provider != "" {
		add("LOWER(i.provider) = $%d", provider)
	}
	if accountID := strings.TrimSpace(filter.AccountID); accountID != "" {
		add("i.account_id = $%d", accountID)
	}
	if controlID := strings.TrimSpace(filter.ControlID); controlID != "" {
		add("i.control_id = $%d", controlID)
	}
	if resourceID := strings.TrimSpace(filter.ResourceID); resourceID != "" {
		add("i.resource_id = $%d", resourceID)
	}
	if filter.HasTicket != nil {
		if *filter.HasTicket {
			clauses = append(clauses, "NULLIF(TRIM(COALESCE(i.ticket_id, '')), '') IS NOT NULL")
		} else {
			clauses = append(clauses, "NULLIF(TRIM(COALESCE(i.ticket_id, '')), '') IS NULL")
		}
	}
	if len(filter.ScopeAccountIDs) > 0 {
		add("i.account_id = ANY($%d)", pq.Array(filter.ScopeAccountIDs))
	}
	if len(filter.ScopeRegions) > 0 {
		add("LOWER(COALESCE(r.region, '')) = ANY($%d)", pq.Array(normalizeLowercase(filter.ScopeRegions)))
	}
	if len(filter.ScopeEnvironments) > 0 {
		add("LOWER(COALESCE(a.environment_type, '')) = ANY($%d)", pq.Array(normalizeLowercase(filter.ScopeEnvironments)))
	}
	if len(filter.ScopeBusinessUnits) > 0 {
		add(`EXISTS (
			SELECT 1
			FROM issue_findings if_scope
			JOIN findings f_scope ON f_scope.id = if_scope.finding_id
			WHERE if_scope.issue_id = i.id
			  AND LOWER(COALESCE(f_scope.line_of_business, '')) = ANY($%d)
		)`, pq.Array(normalizeLowercase(filter.ScopeBusinessUnits)))
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}

func buildIssueSortClause(filter IssueListFilter) string {
	order := "DESC"
	if strings.EqualFold(strings.TrimSpace(filter.SortOrder), "asc") {
		order = "ASC"
	}

	switch strings.ToLower(strings.TrimSpace(filter.SortBy)) {
	case "", "risk_score":
		return fmt.Sprintf(" ORDER BY i.risk_score %s, i.updated_at DESC", order)
	case "severity":
		return fmt.Sprintf(` ORDER BY CASE UPPER(i.severity)
			WHEN 'CRITICAL' THEN 4
			WHEN 'HIGH' THEN 3
			WHEN 'MEDIUM' THEN 2
			WHEN 'LOW' THEN 1
			ELSE 0
		END %s, i.updated_at DESC`, order)
	case "updated_at":
		return fmt.Sprintf(" ORDER BY i.updated_at %s", order)
	case "created_at":
		return fmt.Sprintf(" ORDER BY i.created_at %s", order)
	case "blast_radius":
		return fmt.Sprintf(" ORDER BY i.blast_radius %s, i.updated_at DESC", order)
	default:
		return " ORDER BY i.risk_score DESC, i.updated_at DESC"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func normalizeLowercase(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	return normalized
}
