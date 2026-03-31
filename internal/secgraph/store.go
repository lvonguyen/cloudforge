package secgraph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
)

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Store persists secgraph controls, evaluations, issues, and edges.
// Runtime wiring can depend on this without embedding SQL strings elsewhere.
type Store struct {
	db execer
}

// NewStore creates a secgraph store backed by a SQL execer.
func NewStore(db execer) *Store {
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
