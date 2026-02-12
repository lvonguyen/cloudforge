// Package findings defines the finding types consumed by the remediation dispatcher.
//
// These types mirror cspm-aggregator's internal/scoring package to maintain JSON
// compatibility. When the aggregator is merged into this repo, this bridge package
// will be removed and handlers will import internal/scoring directly.
package findings

import "time"

// Finding represents a security finding from any CSP source.
type Finding struct {
	ID           string    `json:"id"`
	Source       string    `json:"source"`        // aws-securityhub, azure-defender, gcp-scc
	Severity     string    `json:"severity"`      // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	FindingType  string    `json:"finding_type"`  // e.g., S3_PUBLIC_ACCESS, OPEN_SSH_PORT
	ResourceID   string    `json:"resource_id"`
	ResourceType string    `json:"resource_type"` // e.g., AWS::S3::Bucket
	Region       string    `json:"region"`
	AccountID    string    `json:"account_id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	FirstSeen    time.Time `json:"first_seen"`
	DaysOpen     int       `json:"days_open"`
	Context      FindingContext `json:"context"`
}

// FindingContext provides business and technical context for risk assessment.
type FindingContext struct {
	AssetTier          string   `json:"asset_tier"`
	EnvType            string   `json:"env_type"`
	DataClassification string   `json:"data_classification"`
	InternetFacing     bool     `json:"internet_facing"`
	ComplianceScopes   []string `json:"compliance_scopes,omitempty"`
	BusinessCriticality string  `json:"business_criticality"`
	ApplicationOwner   string   `json:"application_owner"`
}

// RiskAssessment is the output of contextual risk scoring.
type RiskAssessment struct {
	OriginalSeverity   string   `json:"original_severity"`
	AdjustedSeverity   string   `json:"adjusted_severity"`
	RiskScore          int      `json:"risk_score"`
	Confidence         float64  `json:"confidence"`
	Rationale          string   `json:"rationale"`
	MitigatingFactors  []string `json:"mitigating_factors,omitempty"`
	AggravatingFactors []string `json:"aggravating_factors,omitempty"`
	RecommendedAction  string   `json:"recommended_action"`
}

// ComplexityAssessment is the output of remediation complexity analysis.
type ComplexityAssessment struct {
	Tier                int    `json:"tier"`
	TierName            string `json:"tier_name"`
	ComplexityScore     int    `json:"complexity_score"`
	AutomationCandidate bool   `json:"automation_candidate"`
	RequiresChangeWindow bool  `json:"requires_change_window"`
	ServiceImpact       string `json:"service_impact"`
	EstimatedEffortHours float64 `json:"estimated_effort_hours"`
	Rationale           string `json:"rationale"`
}

// PrioritizedFinding contains the full assessment for a finding.
// This is the primary type consumed by remediation handlers.
type PrioritizedFinding struct {
	Finding              *Finding              `json:"finding"`
	RiskAssessment       *RiskAssessment       `json:"risk_assessment,omitempty"`
	ComplexityAssessment *ComplexityAssessment  `json:"complexity_assessment,omitempty"`
	Priority             string                `json:"priority"`
	PriorityScore        int                   `json:"priority_score"`
	AutoRemediationReady bool                  `json:"auto_remediation_ready"`
	RecommendedAction    string                `json:"recommended_action"`
	AssignedQueue        string                `json:"assigned_queue"`
	RequiresApproval     bool                  `json:"requires_approval"`
	AssessedAt           time.Time             `json:"assessed_at"`
}
