package grc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"aegis/internal/tenant"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// PostgresGRCProvider implements GRCProvider using PostgreSQL.
// This is a good option for organizations that don't have enterprise GRC tools
// like Archer or ServiceNow, or for smaller deployments.
type PostgresGRCProvider struct {
	db *sql.DB
}

// NewPostgresGRCProvider creates a new PostgreSQL-backed GRC provider.
func NewPostgresGRCProvider(db *sql.DB) *PostgresGRCProvider {
	return &PostgresGRCProvider{db: db}
}

// tenantFromCtx extracts the tenant ID and friendly name from context.
// Returns ("default", "") when no tenant is set (single-tenant backward compat).
func tenantFromCtx(ctx context.Context) (id, name string) {
	if cfg := tenant.FromContext(ctx); cfg != nil {
		return cfg.ID, cfg.Name
	}
	return "default", ""
}

// CreateException creates a new exception request in the database.
func (p *PostgresGRCProvider) CreateException(
	ctx context.Context,
	req *ExceptionRequest,
) (*ExceptionRequest, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Generate ID if not set
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()
	req.Status = StatusPending

	tenantID, tenantName := tenantFromCtx(ctx)

	// Insert main exception record
	query := `
		INSERT INTO exception_requests (
			id, application_id, requestor_email, request_type,
			policy_violated, resource_requested, business_case,
			status, expiration_date, created_at, updated_at, metadata,
			tenant_id, tenant_name
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = tx.ExecContext(ctx, query,
		req.ID,
		req.ApplicationID,
		req.RequestorEmail,
		req.RequestType,
		req.PolicyViolated,
		req.ResourceRequested,
		req.BusinessCase,
		req.Status,
		req.ExpirationDate,
		req.CreatedAt,
		req.UpdatedAt,
		"{}",
		tenantID,
		tenantName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert exception: %w", err)
	}

	// Insert approver chain
	for i, approver := range req.ApproverChain {
		approverQuery := `
			INSERT INTO approval_chain (
				id, exception_id, sequence_order, approver_email, approver_role, tenant_id
			) VALUES ($1, $2, $3, $4, $5, $6)
		`
		_, err = tx.ExecContext(ctx, approverQuery,
			uuid.New().String(),
			req.ID,
			i,
			approver.Email,
			approver.Role,
			tenantID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert approver: %w", err)
		}
	}

	// Insert audit log entry
	auditQuery := `
		INSERT INTO exception_audit_log (
			id, exception_id, action, actor_email, new_value, timestamp, tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = tx.ExecContext(ctx, auditQuery,
		uuid.New().String(),
		req.ID,
		"CREATED",
		req.RequestorEmail,
		"{}",
		time.Now(),
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert audit log: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return req, nil
}

// GetException retrieves an exception by ID, scoped to the current tenant.
func (p *PostgresGRCProvider) GetException(ctx context.Context, id string) (*ExceptionRequest, error) {
	tenantID, _ := tenantFromCtx(ctx)

	query := `
		SELECT
			id, application_id, requestor_email, request_type,
			policy_violated, resource_requested, business_case,
			status, expiration_date, created_at, updated_at
		FROM exception_requests
		WHERE id = $1 AND tenant_id = $2
	`

	req := &ExceptionRequest{}
	var expiration sql.NullTime

	err := p.db.QueryRowContext(ctx, query, id, tenantID).Scan(
		&req.ID,
		&req.ApplicationID,
		&req.RequestorEmail,
		&req.RequestType,
		&req.PolicyViolated,
		&req.ResourceRequested,
		&req.BusinessCase,
		&req.Status,
		&expiration,
		&req.CreatedAt,
		&req.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("exception %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get exception: %w", err)
	}

	if expiration.Valid {
		req.ExpirationDate = &expiration.Time
	}

	// Load approver chain
	approverQuery := `
		SELECT approver_email, approver_role, decision, comments, decided_at
		FROM approval_chain
		WHERE exception_id = $1 AND tenant_id = $2
		ORDER BY sequence_order
	`
	rows, err := p.db.QueryContext(ctx, approverQuery, id, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to load approvers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var approver Approver
		var decision sql.NullString
		var comments sql.NullString
		var decidedAt sql.NullTime

		if err := rows.Scan(&approver.Email, &approver.Role, &decision, &comments, &decidedAt); err != nil {
			return nil, fmt.Errorf("failed to scan approver: %w", err)
		}

		if decision.Valid {
			approver.Decision = ApprovalStatus(decision.String)
		}
		if comments.Valid {
			approver.Comments = comments.String
		}
		if decidedAt.Valid {
			approver.DecidedAt = &decidedAt.Time
		}

		req.ApproverChain = append(req.ApproverChain, approver)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	// Load risk assessment
	riskQuery := `
		SELECT risk_level, impact, likelihood, residual_risk, assessed_by, assessed_at
		FROM risk_assessments
		WHERE exception_id = $1 AND tenant_id = $2
	`
	var risk RiskAssessment
	err = p.db.QueryRowContext(ctx, riskQuery, id, tenantID).Scan(
		&risk.RiskLevel,
		&risk.Impact,
		&risk.Likelihood,
		&risk.ResidualRisk,
		&risk.AssessedBy,
		&risk.AssessedAt,
	)
	switch {
	case err == nil:
		req.RiskAssessment = &risk
	case errors.Is(err, sql.ErrNoRows):
		// No risk assessment — acceptable
	default:
		return nil, fmt.Errorf("querying risk assessment: %w", err)
	}

	// Load compensating controls
	ctrlQuery := `
		SELECT control_description
		FROM compensating_controls
		WHERE exception_id = $1 AND tenant_id = $2
	`
	ctrlRows, err := p.db.QueryContext(ctx, ctrlQuery, id, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to load controls: %w", err)
	}
	defer ctrlRows.Close()

	for ctrlRows.Next() {
		var ctrl string
		if err := ctrlRows.Scan(&ctrl); err != nil {
			return nil, fmt.Errorf("failed to scan control: %w", err)
		}
		req.CompensatingCtrls = append(req.CompensatingCtrls, ctrl)
	}
	if err := ctrlRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return req, nil
}

// UpdateException updates an existing exception, scoped to the current tenant.
func (p *PostgresGRCProvider) UpdateException(ctx context.Context, req *ExceptionRequest) error {
	tenantID, _ := tenantFromCtx(ctx)
	req.UpdatedAt = time.Now()

	query := `
		UPDATE exception_requests
		SET status = $1, expiration_date = $2, updated_at = $3
		WHERE id = $4 AND tenant_id = $5
	`

	result, err := p.db.ExecContext(ctx, query,
		req.Status,
		req.ExpirationDate,
		req.UpdatedAt,
		req.ID,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to update exception: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("exception %s not found", req.ID)
	}

	return nil
}

// ValidateException checks if a valid exception exists for the given application and policy.
// This is called by OPA/policy engine before allowing provisioning of resources
// that would otherwise violate policy.
func (p *PostgresGRCProvider) ValidateException(
	ctx context.Context,
	applicationID, policyCode string,
) (*ExceptionValidation, error) {
	tenantID, _ := tenantFromCtx(ctx)

	query := `
		SELECT id, expiration_date
		FROM valid_exceptions
		WHERE application_id = $1 AND policy_violated = $2 AND tenant_id = $3
		LIMIT 1
	`

	var id string
	var expiration sql.NullTime

	err := p.db.QueryRowContext(ctx, query, applicationID, policyCode, tenantID).Scan(&id, &expiration)

	if errors.Is(err, sql.ErrNoRows) {
		return &ExceptionValidation{
			Valid:  false,
			Reason: fmt.Sprintf("No approved exception for policy %s", policyCode),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate exception: %w", err)
	}

	validation := &ExceptionValidation{
		Valid:       true,
		ExceptionID: id,
	}

	if expiration.Valid {
		validation.ExpiresAt = &expiration.Time
	}

	return validation, nil
}

// SubmitApproval records an approver's decision on an exception.
func (p *PostgresGRCProvider) SubmitApproval(
	ctx context.Context,
	exceptionID string,
	approver Approver,
) error {
	tenantID, _ := tenantFromCtx(ctx)

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()

	// Update approver decision
	approverQuery := `
		UPDATE approval_chain
		SET decision = $1, comments = $2, decided_at = $3
		WHERE exception_id = $4 AND approver_email = $5 AND tenant_id = $6
	`
	approverResult, err := tx.ExecContext(ctx, approverQuery,
		approver.Decision,
		approver.Comments,
		now,
		exceptionID,
		approver.Email,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to update approver: %w", err)
	}
	rowsAffected, _ := approverResult.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("approver %s is not in the approval chain for exception %s", approver.Email, exceptionID)
	}

	// Check if all approvers have decided
	checkQuery := `
		SELECT
			COUNT(*) FILTER (WHERE decision IS NULL) as pending,
			COUNT(*) FILTER (WHERE decision = 'REJECTED') as rejected
		FROM approval_chain
		WHERE exception_id = $1 AND tenant_id = $2
	`
	var pending, rejected int
	err = tx.QueryRowContext(ctx, checkQuery, exceptionID, tenantID).Scan(&pending, &rejected)
	if err != nil {
		return fmt.Errorf("failed to check approval status: %w", err)
	}

	// Update exception status based on approvals
	var newStatus ApprovalStatus
	if rejected > 0 {
		newStatus = StatusRejected
	} else if pending == 0 {
		newStatus = StatusApproved
	}

	if newStatus != "" {
		statusQuery := `
			UPDATE exception_requests
			SET status = $1, updated_at = $2
			WHERE id = $3 AND tenant_id = $4
		`
		_, err = tx.ExecContext(ctx, statusQuery, newStatus, now, exceptionID, tenantID)
		if err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
	}

	// Audit log
	auditQuery := `
		INSERT INTO exception_audit_log (
			id, exception_id, action, actor_email, new_value, timestamp, tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	// Use json.Marshal for safe JSON construction (prevents injection)
	commentsJSON, _ := json.Marshal(map[string]string{"comments": approver.Comments})
	_, err = tx.ExecContext(ctx, auditQuery,
		uuid.New().String(),
		exceptionID,
		fmt.Sprintf("APPROVAL_%s", approver.Decision),
		approver.Email,
		string(commentsJSON),
		now,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit log: %w", err)
	}

	return tx.Commit()
}

// batchGetExceptions fetches a list of exception IDs in two queries:
// one for the core exception rows and one for all their approval chains.
// This eliminates the N+1 query pattern present when calling GetException in a loop.
func (p *PostgresGRCProvider) batchGetExceptions(ctx context.Context, ids []string) ([]ExceptionRequest, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	tenantID, _ := tenantFromCtx(ctx)

	// Fetch all core exception rows in one query using ANY($1).
	coreQuery := `
		SELECT
			id, application_id, requestor_email, request_type,
			policy_violated, resource_requested, business_case,
			status, expiration_date, created_at, updated_at
		FROM exception_requests
		WHERE id = ANY($1) AND tenant_id = $2
	`
	coreRows, err := p.db.QueryContext(ctx, coreQuery, pq.Array(ids), tenantID)
	if err != nil {
		return nil, fmt.Errorf("batch fetching exceptions: %w", err)
	}
	defer coreRows.Close()

	excByID := make(map[string]*ExceptionRequest, len(ids))
	var order []string
	for coreRows.Next() {
		req := &ExceptionRequest{}
		var expiration sql.NullTime
		if err := coreRows.Scan(
			&req.ID, &req.ApplicationID, &req.RequestorEmail, &req.RequestType,
			&req.PolicyViolated, &req.ResourceRequested, &req.BusinessCase,
			&req.Status, &expiration, &req.CreatedAt, &req.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning exception row: %w", err)
		}
		if expiration.Valid {
			req.ExpirationDate = &expiration.Time
		}
		excByID[req.ID] = req
		order = append(order, req.ID)
	}
	if err := coreRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating exception rows: %w", err)
	}

	// Fetch all approval chain rows for the batch in one query.
	approverQuery := `
		SELECT exception_id, approver_email, approver_role, decision, comments, decided_at
		FROM approval_chain
		WHERE exception_id = ANY($1) AND tenant_id = $2
		ORDER BY exception_id, sequence_order
	`
	approverRows, err := p.db.QueryContext(ctx, approverQuery, pq.Array(ids), tenantID)
	if err != nil {
		return nil, fmt.Errorf("batch fetching approvers: %w", err)
	}
	defer approverRows.Close()

	for approverRows.Next() {
		var excID string
		var approver Approver
		var decision sql.NullString
		var comments sql.NullString
		var decidedAt sql.NullTime
		if err := approverRows.Scan(&excID, &approver.Email, &approver.Role, &decision, &comments, &decidedAt); err != nil {
			return nil, fmt.Errorf("scanning approver row: %w", err)
		}
		if decision.Valid {
			approver.Decision = ApprovalStatus(decision.String)
		}
		if comments.Valid {
			approver.Comments = comments.String
		}
		if decidedAt.Valid {
			approver.DecidedAt = &decidedAt.Time
		}
		if exc, ok := excByID[excID]; ok {
			exc.ApproverChain = append(exc.ApproverChain, approver)
		}
	}
	if err := approverRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating approver rows: %w", err)
	}

	// Return in the order we received IDs (stable output).
	results := make([]ExceptionRequest, 0, len(order))
	for _, id := range order {
		if exc, ok := excByID[id]; ok {
			results = append(results, *exc)
		}
	}
	return results, nil
}

// GetPendingApprovals returns exceptions awaiting approval from the given user.
// Uses a batch query to avoid N+1 queries when loading exception details.
func (p *PostgresGRCProvider) GetPendingApprovals(
	ctx context.Context,
	approverEmail string,
) ([]ExceptionRequest, error) {
	tenantID, _ := tenantFromCtx(ctx)

	query := `
		SELECT DISTINCT er.id
		FROM exception_requests er
		JOIN approval_chain ac ON er.id = ac.exception_id
		WHERE er.status = 'PENDING'
		  AND ac.approver_email = $1
		  AND ac.decision IS NULL
		  AND er.tenant_id = $2
	`

	rows, err := p.db.QueryContext(ctx, query, approverEmail, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending approvals: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return p.batchGetExceptions(ctx, ids)
}

// GetExceptionsByApplication returns all exceptions for an application.
// Uses a batch query to avoid N+1 queries when loading exception details.
func (p *PostgresGRCProvider) GetExceptionsByApplication(
	ctx context.Context,
	appID string,
) ([]ExceptionRequest, error) {
	tenantID, _ := tenantFromCtx(ctx)

	query := `
		SELECT id FROM exception_requests
		WHERE application_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
	`

	rows, err := p.db.QueryContext(ctx, query, appID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query exceptions: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return p.batchGetExceptions(ctx, ids)
}

// GetExpiringExceptions returns approved exceptions expiring within the given number of days.
// Uses a batch query to avoid N+1 queries when loading exception details.
func (p *PostgresGRCProvider) GetExpiringExceptions(
	ctx context.Context,
	withinDays int,
) ([]ExceptionRequest, error) {
	tenantID, _ := tenantFromCtx(ctx)
	cutoff := time.Now().AddDate(0, 0, withinDays)

	query := `
		SELECT id FROM exception_requests
		WHERE status = 'APPROVED'
		  AND expiration_date IS NOT NULL
		  AND expiration_date <= $1
		  AND expiration_date > NOW()
		  AND tenant_id = $2
		ORDER BY expiration_date ASC
	`

	rows, err := p.db.QueryContext(ctx, query, cutoff, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring exceptions: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return p.batchGetExceptions(ctx, ids)
}

// GetExceptionsByRequestor returns all exceptions created by the given user.
// Uses a batch query to avoid N+1 queries when loading exception details.
func (p *PostgresGRCProvider) GetExceptionsByRequestor(
	ctx context.Context,
	email string,
) ([]ExceptionRequest, error) {
	tenantID, _ := tenantFromCtx(ctx)

	query := `
		SELECT id FROM exception_requests
		WHERE requestor_email = $1 AND tenant_id = $2
		ORDER BY created_at DESC
	`

	rows, err := p.db.QueryContext(ctx, query, email, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query exceptions by requestor: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return p.batchGetExceptions(ctx, ids)
}
