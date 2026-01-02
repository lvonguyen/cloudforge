// Package grc provides abstraction layer for GRC (Governance, Risk, Compliance) platform integrations.
// This allows CloudForge to work with various enterprise GRC tools like RSA Archer, ServiceNow GRC,
// or a simple PostgreSQL-based solution for smaller organizations.
package grc

import (
	"context"
	"time"
)

// ExceptionRequest represents an out-of-band policy exception request.
// When a user requests resources that violate policy (e.g., unapproved region,
// oversized instance), they must submit an exception request that goes through
// a risk assessment and approval workflow.
type ExceptionRequest struct {
	ID                string            `json:"id"`
	ApplicationID     string            `json:"application_id"`
	RequestorEmail    string            `json:"requestor_email"`
	RequestType       ExceptionType     `json:"request_type"`
	PolicyViolated    string            `json:"policy_violated"`    // e.g., "REGION-001", "COST-002"
	ResourceRequested string            `json:"resource_requested"` // what they want
	BusinessCase      string            `json:"business_case"`      // justification
	RiskAssessment    *RiskAssessment   `json:"risk_assessment,omitempty"`
	CompensatingCtrls []string          `json:"compensating_controls,omitempty"`
	Status            ApprovalStatus    `json:"status"`
	ApproverChain     []Approver        `json:"approver_chain"`
	ExpirationDate    *time.Time        `json:"expiration_date,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// ExceptionType categorizes the type of policy exception being requested.
type ExceptionType string

const (
	ExceptionTypeRegion       ExceptionType = "UNAPPROVED_REGION"
	ExceptionTypeInstanceSize ExceptionType = "OVERSIZED_INSTANCE"
	ExceptionTypeService      ExceptionType = "RESTRICTED_SERVICE"
	ExceptionTypeNetwork      ExceptionType = "NETWORK_EXPOSURE"
	ExceptionTypeData         ExceptionType = "DATA_RESIDENCY"
	ExceptionTypeOther        ExceptionType = "OTHER"
)

// ApprovalStatus represents the current state of an exception request.
type ApprovalStatus string

const (
	StatusPending  ApprovalStatus = "PENDING"
	StatusApproved ApprovalStatus = "APPROVED"
	StatusRejected ApprovalStatus = "REJECTED"
	StatusExpired  ApprovalStatus = "EXPIRED"
	StatusRevoked  ApprovalStatus = "REVOKED"
)

// RiskAssessment captures the security/compliance risk evaluation of an exception.
type RiskAssessment struct {
	RiskLevel    string    `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
	Impact       string    `json:"impact"`
	Likelihood   string    `json:"likelihood"`
	ResidualRisk string    `json:"residual_risk"`
	AssessedBy   string    `json:"assessed_by"`
	AssessedAt   time.Time `json:"assessed_at"`
}

// Approver represents a person in the approval chain for an exception.
type Approver struct {
	Email     string         `json:"email"`
	Role      string         `json:"role"` // e.g., "SECURITY_LEAD", "GRC_ANALYST", "CISO"
	Decision  ApprovalStatus `json:"decision"`
	Comments  string         `json:"comments,omitempty"`
	DecidedAt *time.Time     `json:"decided_at,omitempty"`
}

// ExceptionValidation is the result of checking if an exception is valid.
// This is called by the policy engine before provisioning to verify
// that an approved, non-expired exception exists for the policy violation.
type ExceptionValidation struct {
	Valid       bool       `json:"valid"`
	ExceptionID string     `json:"exception_id,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
}

// GRCProvider abstracts GRC platform integrations.
// Implementations exist for RSA Archer, ServiceNow GRC, PostgreSQL, and in-memory.
type GRCProvider interface {
	// Exception lifecycle
	CreateException(ctx context.Context, req *ExceptionRequest) (*ExceptionRequest, error)
	GetException(ctx context.Context, id string) (*ExceptionRequest, error)
	UpdateException(ctx context.Context, req *ExceptionRequest) error

	// Approval workflow
	SubmitApproval(ctx context.Context, exceptionID string, approver Approver) error
	GetPendingApprovals(ctx context.Context, approverEmail string) ([]ExceptionRequest, error)

	// Validation - called by policy engine before provisioning
	ValidateException(ctx context.Context, applicationID, policyCode string) (*ExceptionValidation, error)

	// Audit & reporting
	GetExceptionsByApplication(ctx context.Context, appID string) ([]ExceptionRequest, error)
	GetExpiringExceptions(ctx context.Context, withinDays int) ([]ExceptionRequest, error)
}
