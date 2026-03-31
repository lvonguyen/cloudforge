// Package secgraph defines the Security Graph domain model: controls, issues,
// graph edges, and the taxonomy of node/edge types that form the live
// tenant-scoped security graph (ADR-020).
package secgraph

import "time"

// NodeType enumerates the vertex labels in the security graph.
type NodeType string

const (
	NodeFinding             NodeType = "finding"
	NodeResource            NodeType = "resource"
	NodeControl             NodeType = "control"
	NodeIssue               NodeType = "issue"
	NodeAccount             NodeType = "account"
	NodeComplianceFramework NodeType = "compliance_framework"
)

// EdgeType enumerates the relationship labels in the security graph.
type EdgeType string

const (
	EdgeAffects        EdgeType = "affects"         // finding → resource
	EdgeViolates       EdgeType = "violates"        // finding → control
	EdgeMapsTo         EdgeType = "maps_to"         // control → compliance_framework
	EdgeEvaluatedBy    EdgeType = "evaluated_by"    // resource → control
	EdgeMaterializesTo EdgeType = "materializes_to" // finding → issue
	EdgeBelongsTo      EdgeType = "belongs_to"      // resource → account
	EdgeSameAccount    EdgeType = "same_account"    // resource → resource (co-located)
	EdgeSameRegion     EdgeType = "same_region"     // resource → resource (co-located + same region)
)

// ControlStatus represents the lifecycle state of a control definition.
type ControlStatus string

const (
	ControlActive     ControlStatus = "ACTIVE"
	ControlDisabled   ControlStatus = "DISABLED"
	ControlDeprecated ControlStatus = "DEPRECATED"
)

// EvalStatus represents the outcome of evaluating a control against a resource.
type EvalStatus string

const (
	EvalPass          EvalStatus = "PASS"
	EvalFail          EvalStatus = "FAIL"
	EvalError         EvalStatus = "ERROR"
	EvalNotApplicable EvalStatus = "NOT_APPLICABLE"
)

// IssueStatus represents the lifecycle state of a security issue.
type IssueStatus string

const (
	IssueOpen         IssueStatus = "OPEN"
	IssueAcknowledged IssueStatus = "ACKNOWLEDGED"
	IssueInProgress   IssueStatus = "IN_PROGRESS"
	IssueResolved     IssueStatus = "RESOLVED"
	IssueSuppressed   IssueStatus = "SUPPRESSED"
)

// Control is an evaluable security rule derived from a compliance framework.
// It represents a single check (e.g., "S3 buckets must have encryption enabled")
// that can be evaluated against resources to produce pass/fail results.
type Control struct {
	ID             string        `json:"id" db:"id"`
	FrameworkID    string        `json:"framework_id" db:"framework_id"`
	Title          string        `json:"title" db:"title"`
	Description    string        `json:"description" db:"description"`
	Category       string        `json:"category" db:"category"`
	Severity       string        `json:"severity" db:"severity"`
	Provider       string        `json:"provider" db:"provider"`
	ResourceTypes  []string      `json:"resource_types" db:"resource_types"`
	EvalLogicRef   string        `json:"eval_logic_ref" db:"eval_logic_ref"`
	AutoRemediable bool          `json:"auto_remediable" db:"auto_remediable"`
	RemediationRef string        `json:"remediation_ref" db:"remediation_ref"`
	Keywords       []string      `json:"keywords" db:"keywords"`
	Status         ControlStatus `json:"status" db:"status"`
	TenantID       string        `json:"tenant_id" db:"tenant_id"`
	CreatedAt      time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at" db:"updated_at"`
}

// ControlEvaluation records the result of evaluating a control against a
// specific resource. One row per (control, resource, tenant) tuple.
type ControlEvaluation struct {
	ID          string     `json:"id" db:"id"`
	ControlID   string     `json:"control_id" db:"control_id"`
	ResourceID  string     `json:"resource_id" db:"resource_id"`
	Status      EvalStatus `json:"status" db:"status"`
	Evidence    []string   `json:"evidence" db:"evidence"` // finding IDs
	EvaluatedAt time.Time  `json:"evaluated_at" db:"evaluated_at"`
	TenantID    string     `json:"tenant_id" db:"tenant_id"`
}

// Issue is a materialized, prioritized security issue that aggregates one or
// more findings violating the same control on the same resource. Issues are
// the primary unit of work for security operators.
type Issue struct {
	ID            string      `json:"id" db:"id"`
	Title         string      `json:"title" db:"title"`
	Description   string      `json:"description" db:"description"`
	Severity      string      `json:"severity" db:"severity"`
	RiskScore     float64     `json:"risk_score" db:"risk_score"`
	BlastRadius   int         `json:"blast_radius" db:"blast_radius"`
	Status        IssueStatus `json:"status" db:"status"`
	ControlID     string      `json:"control_id,omitempty" db:"control_id"`
	ResourceID    string      `json:"resource_id,omitempty" db:"resource_id"`
	AccountID     string      `json:"account_id,omitempty" db:"account_id"`
	Provider      string      `json:"provider,omitempty" db:"provider"`
	AssigneeID    string      `json:"assignee_id,omitempty" db:"assignee_id"`
	TicketID      string      `json:"ticket_id,omitempty" db:"ticket_id"`
	TicketURL     string      `json:"ticket_url,omitempty" db:"ticket_url"`
	SLABreachAt   *time.Time  `json:"sla_breach_at,omitempty" db:"sla_breach_at"`
	ExposurePaths int         `json:"exposure_paths" db:"exposure_paths"`
	TenantID      string      `json:"tenant_id" db:"tenant_id"`
	CreatedAt     time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at" db:"updated_at"`
	ResolvedAt    *time.Time  `json:"resolved_at,omitempty" db:"resolved_at"`
}

// IssueListFilter constrains issue list queries for the operator surface.
type IssueListFilter struct {
	TenantID           string   `json:"tenant_id,omitempty"`
	Severity           string   `json:"severity,omitempty"`
	Status             string   `json:"status,omitempty"`
	Provider           string   `json:"provider,omitempty"`
	AccountID          string   `json:"account_id,omitempty"`
	ControlID          string   `json:"control_id,omitempty"`
	ResourceID         string   `json:"resource_id,omitempty"`
	HasTicket          *bool    `json:"has_ticket,omitempty"`
	SortBy             string   `json:"sort_by,omitempty"`
	SortOrder          string   `json:"sort_order,omitempty"`
	ScopeAccountIDs    []string `json:"scope_account_ids,omitempty"`
	ScopeRegions       []string `json:"scope_regions,omitempty"`
	ScopeEnvironments  []string `json:"scope_environments,omitempty"`
	ScopeBusinessUnits []string `json:"scope_business_units,omitempty"`
}

// IssueSummary is the operator-facing issue view returned by list queries.
// It enriches the materialized issue row with control/resource metadata and
// scope-relevant fields used by API-side authorization checks.
type IssueSummary struct {
	Issue
	ControlTitle    string `json:"control_title,omitempty"`
	ResourceName    string `json:"resource_name,omitempty"`
	Region          string `json:"region,omitempty"`
	EnvironmentType string `json:"environment_type,omitempty"`
	LineOfBusiness  string `json:"line_of_business,omitempty"`
	FindingCount    int    `json:"finding_count"`
}

// GetAccountID returns the account dimension for scope enforcement.
func (i IssueSummary) GetAccountID() string { return i.AccountID }

// GetRegion returns the region dimension for scope enforcement.
func (i IssueSummary) GetRegion() string { return i.Region }

// GetEnvironmentType returns the environment dimension for scope enforcement.
func (i IssueSummary) GetEnvironmentType() string { return i.EnvironmentType }

// GetLineOfBusiness returns the business-unit dimension for scope enforcement.
func (i IssueSummary) GetLineOfBusiness() string { return i.LineOfBusiness }

// IssueFindingLink links a materialized issue to the findings that produced it.
type IssueFindingLink struct {
	IssueID   string    `json:"issue_id" db:"issue_id"`
	FindingID string    `json:"finding_id" db:"finding_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Account represents a cloud account, GCP project, or Azure subscription.
type Account struct {
	ID              string    `json:"id" db:"id"`
	Name            string    `json:"name" db:"name"`
	CloudProvider   string    `json:"cloud_provider" db:"cloud_provider"`
	EnvironmentType string    `json:"environment_type" db:"environment_type"`
	TenantID        string    `json:"tenant_id" db:"tenant_id"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// GraphEdge is an explicit typed relationship between two vertices in the
// security graph. PuppyGraph projects each distinct edge_type value as a
// native graph edge label.
type GraphEdge struct {
	ID         string            `json:"id" db:"id"`
	SourceType NodeType          `json:"source_type" db:"source_type"`
	SourceID   string            `json:"source_id" db:"source_id"`
	TargetType NodeType          `json:"target_type" db:"target_type"`
	TargetID   string            `json:"target_id" db:"target_id"`
	EdgeType   EdgeType          `json:"edge_type" db:"edge_type"`
	Properties map[string]string `json:"properties,omitempty" db:"properties"`
	TenantID   string            `json:"tenant_id" db:"tenant_id"`
	CreatedAt  time.Time         `json:"created_at" db:"created_at"`
}

// MaterializationResult captures the graph-native artifacts derived from one
// or more findings for downstream persistence.
type MaterializationResult struct {
	Controls      []Control
	Evaluations   []ControlEvaluation
	Issues        []Issue
	IssueFindings []IssueFindingLink
	Edges         []GraphEdge
}
