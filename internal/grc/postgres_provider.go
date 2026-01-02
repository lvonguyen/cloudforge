package grc

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
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

// CreateException creates a new exception request in the database.
func (p *PostgresGRCProvider) CreateException(
	ctx context.Context,
	req *ExceptionRequest,
) (*ExceptionRequest, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Generate ID if not set
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()
	req.Status = StatusPending

	// Insert main exception record
	query := `
		INSERT INTO exception_requests (
			id, application_id, requestor_email, request_type,
			policy_violated, resource_requested, business_case,
			status, expiration_date, created_at, updated_at, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert exception: %w", err)
	}

	// Insert approver chain
	for i, approver := range req.ApproverChain {
		approverQuery := `
			INSERT INTO approval_chain (
				id, exception_id, sequence_order, approver_email, approver_role
			) VALUES ($1, $2, $3, $4, $5)
		`
		_, err = tx.ExecContext(ctx, approverQuery,
			uuid.New().String(),
			req.ID,
			i,
			approver.Email,
			approver.Role,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert approver: %w", err)
		}
	}

	// Insert audit log entry
	auditQuery := `
		INSERT INTO exception_audit_log (
			id, exception_id, action, actor_email, new_value, timestamp
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err = tx.ExecContext(ctx, auditQuery,
		uuid.New().String(),
		req.ID,
		"CREATED",
		req.RequestorEmail,
		"{}",
		time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert audit log: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return req, nil
}

// GetException retrieves an exception by ID.
func (p *PostgresGRCProvider) GetException(ctx context.Context, id string) (*ExceptionRequest, error) {
	query := `
		SELECT 
			id, application_id, requestor_email, request_type,
			policy_violated, resource_requested, business_case,
			status, expiration_date, created_at, updated_at
		FROM exception_requests
		WHERE id = $1
	`

	req := &ExceptionRequest{}
	var expiration sql.NullTime

	err := p.db.QueryRowContext(ctx, query, id).Scan(
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
	if err == sql.ErrNoRows {
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
		WHERE exception_id = $1
		ORDER BY sequence_order
	`
	rows, err := p.db.QueryContext(ctx, approverQuery, id)
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

	// Load risk assessment
	riskQuery := `
		SELECT risk_level, impact, likelihood, residual_risk, assessed_by, assessed_at
		FROM risk_assessments
		WHERE exception_id = $1
	`
	var risk RiskAssessment
	err = p.db.QueryRowContext(ctx, riskQuery, id).Scan(
		&risk.RiskLevel,
		&risk.Impact,
		&risk.Likelihood,
		&risk.ResidualRisk,
		&risk.AssessedBy,
		&risk.AssessedAt,
	)
	if err == nil {
		req.RiskAssessment = &risk
	}

	// Load compensating controls
	ctrlQuery := `
		SELECT control_description
		FROM compensating_controls
		WHERE exception_id = $1
	`
	ctrlRows, err := p.db.QueryContext(ctx, ctrlQuery, id)
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

	return req, nil
}

// UpdateException updates an existing exception.
func (p *PostgresGRCProvider) UpdateException(ctx context.Context, req *ExceptionRequest) error {
	req.UpdatedAt = time.Now()

	query := `
		UPDATE exception_requests
		SET status = $1, expiration_date = $2, updated_at = $3
		WHERE id = $4
	`

	result, err := p.db.ExecContext(ctx, query,
		req.Status,
		req.ExpirationDate,
		req.UpdatedAt,
		req.ID,
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
	query := `
		SELECT id, expiration_date 
		FROM valid_exceptions 
		WHERE application_id = $1 AND policy_violated = $2
		LIMIT 1
	`

	var id string
	var expiration sql.NullTime

	err := p.db.QueryRowContext(ctx, query, applicationID, policyCode).Scan(&id, &expiration)

	if err == sql.ErrNoRows {
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
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now()

	// Update approver decision
	approverQuery := `
		UPDATE approval_chain
		SET decision = $1, comments = $2, decided_at = $3
		WHERE exception_id = $4 AND approver_email = $5
	`
	_, err = tx.ExecContext(ctx, approverQuery,
		approver.Decision,
		approver.Comments,
		now,
		exceptionID,
		approver.Email,
	)
	if err != nil {
		return fmt.Errorf("failed to update approver: %w", err)
	}

	// Check if all approvers have decided
	checkQuery := `
		SELECT 
			COUNT(*) FILTER (WHERE decision IS NULL) as pending,
			COUNT(*) FILTER (WHERE decision = 'REJECTED') as rejected
		FROM approval_chain
		WHERE exception_id = $1
	`
	var pending, rejected int
	err = tx.QueryRowContext(ctx, checkQuery, exceptionID).Scan(&pending, &rejected)
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
			WHERE id = $3
		`
		_, err = tx.ExecContext(ctx, statusQuery, newStatus, now, exceptionID)
		if err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
	}

	// Audit log
	auditQuery := `
		INSERT INTO exception_audit_log (
			id, exception_id, action, actor_email, new_value, timestamp
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err = tx.ExecContext(ctx, auditQuery,
		uuid.New().String(),
		exceptionID,
		fmt.Sprintf("APPROVAL_%s", approver.Decision),
		approver.Email,
		fmt.Sprintf(`{"comments": "%s"}`, approver.Comments),
		now,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit log: %w", err)
	}

	return tx.Commit()
}

// GetPendingApprovals returns exceptions awaiting approval from the given user.
func (p *PostgresGRCProvider) GetPendingApprovals(
	ctx context.Context,
	approverEmail string,
) ([]ExceptionRequest, error) {
	query := `
		SELECT DISTINCT er.id
		FROM exception_requests er
		JOIN approval_chain ac ON er.id = ac.exception_id
		WHERE er.status = 'PENDING'
		  AND ac.approver_email = $1
		  AND ac.decision IS NULL
	`

	rows, err := p.db.QueryContext(ctx, query, approverEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending approvals: %w", err)
	}
	defer rows.Close()

	var results []ExceptionRequest
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan id: %w", err)
		}

		exc, err := p.GetException(ctx, id)
		if err != nil {
			return nil, err
		}
		results = append(results, *exc)
	}

	return results, nil
}

// GetExceptionsByApplication returns all exceptions for an application.
func (p *PostgresGRCProvider) GetExceptionsByApplication(
	ctx context.Context,
	appID string,
) ([]ExceptionRequest, error) {
	query := `
		SELECT id FROM exception_requests
		WHERE application_id = $1
		ORDER BY created_at DESC
	`

	rows, err := p.db.QueryContext(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query exceptions: %w", err)
	}
	defer rows.Close()

	var results []ExceptionRequest
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan id: %w", err)
		}

		exc, err := p.GetException(ctx, id)
		if err != nil {
			return nil, err
		}
		results = append(results, *exc)
	}

	return results, nil
}

// GetExpiringExceptions returns approved exceptions expiring within the given number of days.
func (p *PostgresGRCProvider) GetExpiringExceptions(
	ctx context.Context,
	withinDays int,
) ([]ExceptionRequest, error) {
	cutoff := time.Now().AddDate(0, 0, withinDays)

	query := `
		SELECT id FROM exception_requests
		WHERE status = 'APPROVED'
		  AND expiration_date IS NOT NULL
		  AND expiration_date <= $1
		  AND expiration_date > NOW()
		ORDER BY expiration_date ASC
	`

	rows, err := p.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring exceptions: %w", err)
	}
	defer rows.Close()

	var results []ExceptionRequest
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan id: %w", err)
		}

		exc, err := p.GetException(ctx, id)
		if err != nil {
			return nil, err
		}
		results = append(results, *exc)
	}

	return results, nil
}
