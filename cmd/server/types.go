package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type FindingAssignee struct {
	UserID      string `json:"user_id,omitempty"`
	UserEmail   string `json:"user_email,omitempty"`
	UserName    string `json:"user_name,omitempty"`
	Team        string `json:"team,omitempty"`
	AssignedAt  string `json:"assigned_at,omitempty"`
	AssignedBy  string `json:"assigned_by,omitempty"`
	DueDate     string `json:"due_date,omitempty"`
	Escalated   bool   `json:"escalated,omitempty"`
	EscalatedTo string `json:"escalated_to,omitempty"`
	EscalatedAt string `json:"escalated_at,omitempty"`
}

type FindingContact struct {
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	Team      string `json:"team,omitempty"`
	Phone     string `json:"phone,omitempty"`
	SlackID   string `json:"slack_id,omitempty"`
	OnCallURL string `json:"on_call_url,omitempty"`
}

// Finding represents a security finding from CSPM scanners.
type Finding struct {
	ID                  string              `json:"id"`
	Source              string              `json:"source"`
	SourceFindingID     string              `json:"source_finding_id"`
	Type                string              `json:"type"`
	Title               string              `json:"title"`
	Description         string              `json:"description"`
	ResourceType        string              `json:"resource_type"`
	ResourceID          string              `json:"resource_id"`
	ResourceName        string              `json:"resource_name"`
	ResourceARN         string              `json:"resource_arn,omitempty"`
	Platform            string              `json:"platform"`
	CloudProvider       string              `json:"cloud_provider"`
	Region              string              `json:"region"`
	AccountID           string              `json:"account_id"`
	AccountName         string              `json:"account_name"`
	EnvironmentType     string              `json:"environment_type"`
	StaticSeverity      string              `json:"static_severity"`
	Severity            string              `json:"severity"`
	AIRiskScore         float64             `json:"ai_risk_score"`
	AIRiskLevel         string              `json:"ai_risk_level"`
	AIRiskRationale     string              `json:"ai_risk_rationale"`
	AIContextualFactors []string            `json:"ai_contextual_factors"`
	CVSS                *float64            `json:"cvss,omitempty"`
	CVSSVector          string              `json:"cvss_vector,omitempty"`
	EPSS                *float64            `json:"epss,omitempty"`
	ExploitAvailable    bool                `json:"exploit_available"`
	CVEs                []CVE               `json:"cves"`
	MITRETactics        []string            `json:"mitre_tactics"`
	MITRETechniques     []string            `json:"mitre_techniques"`
	ComplianceMappings  []ComplianceMapping `json:"compliance_mappings"`
	Remediation         string              `json:"remediation"`
	AutoRemediatable    bool                `json:"auto_remediatable"`
	Category            string              `json:"category"`
	Status              string              `json:"status"`
	WorkflowStatus      string              `json:"workflow_status"`
	Assignee            *FindingAssignee    `json:"assignee,omitempty"`
	Suppressed          bool                `json:"suppressed"`
	TechnicalContact    *FindingContact     `json:"technical_contact,omitempty"`
	BusinessOwner       *FindingContact     `json:"business_owner,omitempty"`
	ServiceName         string              `json:"service_name"`
	LineOfBusiness      string              `json:"line_of_business"`
	Team                string              `json:"team,omitempty"`
	FirstFoundAt        string              `json:"first_found_at"`
	LastSeenAt          string              `json:"last_seen_at"`
	SLABreachDate       string              `json:"sla_breach_date,omitempty"`
	DueDate             string              `json:"due_date"`
	DeduplicationKey    string              `json:"deduplication_key"`
	CanonicalRuleID     string              `json:"canonical_rule_id"`
	IntegrityHash       string              `json:"integrity_hash,omitempty"`
	Tags                map[string]string   `json:"tags,omitempty"`
	IPs                 []string            `json:"ips,omitempty"`
	Emails              []string            `json:"emails,omitempty"`
}

// ComputeIntegrityHash computes a tamper-evident SHA-256 hash over the
// canonical identity and content fields of the finding.
func (f *Finding) ComputeIntegrityHash() string {
	h := sha256.New()
	for _, s := range []string{
		f.ID, f.Source, f.SourceFindingID, f.ResourceID,
		f.AccountID, f.Region, f.Severity, f.Title, f.Status,
	} {
		h.Write([]byte(s))
		h.Write([]byte{0}) // null delimiter
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GetAccountID implements api.Scopeable.
func (f *Finding) GetAccountID() string { return f.AccountID }

// GetRegion implements api.Scopeable.
func (f *Finding) GetRegion() string { return f.Region }

// GetEnvironmentType implements api.Scopeable.
func (f *Finding) GetEnvironmentType() string { return f.EnvironmentType }

// GetLineOfBusiness implements api.Scopeable.
func (f *Finding) GetLineOfBusiness() string { return f.LineOfBusiness }

// CVE holds vulnerability identifiers.
type CVE struct {
	ID                 string   `json:"id"`
	URL                string   `json:"url"`
	NVDURL             string   `json:"nvd_url"`
	MitreURL           string   `json:"mitre_url"`
	Description        string   `json:"description"`
	CVSS               *float64 `json:"cvss,omitempty"`
	CVSSVector         string   `json:"cvss_vector,omitempty"`
	CVSSVersion        string   `json:"cvss_version,omitempty"`
	EPSS               *float64 `json:"epss,omitempty"`
	CISAKnownExploited bool     `json:"cisa_known_exploited"`
	Published          string   `json:"published"`
	Modified           string   `json:"modified"`
}

// ComplianceMapping links a finding to a framework control.
type ComplianceMapping struct {
	FrameworkID   string `json:"framework_id"`
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
	ControlTitle  string `json:"control_title"`
	Section       string `json:"section"`
	Severity      string `json:"severity"`
	URL           string `json:"url"`
}

// Agent represents an AI agent in the platform.
type Agent struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Framework    string          `json:"framework"`
	Version      string          `json:"version"`
	Owner        string          `json:"owner"`
	Team         string          `json:"team"`
	Environment  string          `json:"environment"`
	Capabilities json.RawMessage `json:"capabilities"`
	Tools        json.RawMessage `json:"tools"`
	Policies     []string        `json:"policies"`
	RiskLevel    string          `json:"risk_level"`
	Status       string          `json:"status"`
	LastActiveAt string          `json:"last_active_at"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

// AgentTrace represents an execution trace for an agent run.
type AgentTrace struct {
	TraceID         string          `json:"trace_id"`
	AgentID         string          `json:"agent_id"`
	SessionID       string          `json:"session_id"`
	UserID          string          `json:"user_id"`
	StartTime       string          `json:"start_time"`
	EndTime         string          `json:"end_time"`
	DurationMS      int64           `json:"duration_ms"`
	Status          string          `json:"status"`
	Spans           json.RawMessage `json:"spans"`
	SecuritySignals json.RawMessage `json:"security_signals,omitempty"`
	Metrics         json.RawMessage `json:"metrics,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
}

// ComplianceFramework represents a compliance framework with scoring.
type ComplianceFramework struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Version         string              `json:"version"`
	Category        string              `json:"category"`
	TotalControls   int                 `json:"total_controls"`
	ControlsPassing int                 `json:"controls_passing"`
	ControlsFailing int                 `json:"controls_failing"`
	Score           float64             `json:"score"`
	RelevantFor     []string            `json:"relevant_for"`
	Categories      []FrameworkCategory `json:"categories"`
}

// FrameworkCategory is a control category within a compliance framework.
type FrameworkCategory struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Passing int     `json:"passing"`
	Failing int     `json:"failing"`
	Score   float64 `json:"score"`
}

// CostSummary matches the top-level costs.json structure.
type CostSummary struct {
	Period                    string                    `json:"period"`
	Total                     float64                   `json:"total"`
	ByProvider                map[string]float64        `json:"by_provider"`
	ByService                 map[string]float64        `json:"by_service"`
	MonthOverMonth            []CostPeriod              `json:"month_over_month"`
	Daily                     []CostDaily               `json:"daily"`
	Anomalies                 []CostAnomaly             `json:"anomalies"`
	OptimizationOpportunities []OptimizationOpportunity `json:"optimization_opportunities"`
	Chargeback                *Chargeback               `json:"chargeback,omitempty"`
}

// CostPeriod is a monthly cost breakdown by provider.
type CostPeriod struct {
	Period string  `json:"period"`
	Total  float64 `json:"total"`
	AWS    float64 `json:"aws"`
	Azure  float64 `json:"azure"`
	GCP    float64 `json:"gcp"`
}

// CostDaily is a daily cost breakdown by provider.
type CostDaily struct {
	Date  string  `json:"date"`
	AWS   float64 `json:"aws"`
	Azure float64 `json:"azure"`
	GCP   float64 `json:"gcp"`
	Total float64 `json:"total"`
}

// CostAnomaly represents a detected cost anomaly.
type CostAnomaly struct {
	ID               string  `json:"id"`
	Provider         string  `json:"provider"`
	AccountID        string  `json:"account_id"`
	ServiceName      string  `json:"service_name"`
	DetectedAt       string  `json:"detected_at"`
	ExpectedCost     float64 `json:"expected_cost"`
	ActualCost       float64 `json:"actual_cost"`
	DeviationPercent float64 `json:"deviation_percent"`
	Severity         string  `json:"severity"`
}

// OptimizationOpportunity represents a cost optimization recommendation.
type OptimizationOpportunity struct {
	ID                   string  `json:"id"`
	Type                 string  `json:"type"`
	Provider             string  `json:"provider"`
	Service              string  `json:"service"`
	ResourceID           string  `json:"resource_id"`
	AccountID            string  `json:"account_id"`
	CurrentCostMonthly   float64 `json:"current_cost_monthly"`
	ProjectedCostMonthly float64 `json:"projected_cost_monthly"`
	SavingsMonthly       float64 `json:"savings_monthly"`
	SavingsPercent       float64 `json:"savings_percent"`
	Recommendation       string  `json:"recommendation"`
	Confidence           string  `json:"confidence"`
	Risk                 string  `json:"risk"`
}

// Chargeback is the cost allocation report.
type Chargeback struct {
	Period      string                 `json:"period"`
	GeneratedAt string                 `json:"generated_at"`
	TotalCost   float64                `json:"total_cost"`
	Allocations []ChargebackAllocation `json:"allocations"`
}

// ChargebackAllocation is a single cost center allocation.
type ChargebackAllocation struct {
	CostCenter string             `json:"cost_center"`
	Team       string             `json:"team"`
	TotalCost  float64            `json:"total_cost"`
	ByProvider map[string]float64 `json:"by_provider"`
	ByService  map[string]float64 `json:"by_service"`
	Percentage float64            `json:"percentage"`
}

// AuditEvent represents a single audit log entry.
type AuditEvent struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	ActorRole string `json:"actor_role"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Result    string `json:"result"`
	IP        string `json:"ip"`
}

// UserRow represents a platform user.
type UserRow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Team      string `json:"team"`
	LastLogin string `json:"last_login"`
	Status    string `json:"status"`
}

// Policy represents an OPA policy with evaluation stats.
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Status      string `json:"status"`
	Category    string `json:"category"`
	Evaluations int    `json:"evaluations"`
	Denials     int    `json:"denials"`
	LastUpdated string `json:"last_updated"`
}

// RemediationRecord represents a remediation execution with result and validation.
type RemediationRecord struct {
	ID         string          `json:"id"`
	FindingID  string          `json:"finding_id"`
	Domain     string          `json:"domain"`
	Handler    string          `json:"handler"`
	Tier       int             `json:"tier"`
	Status     string          `json:"status"`
	Result     json.RawMessage `json:"result"`
	Validation json.RawMessage `json:"validation"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}
