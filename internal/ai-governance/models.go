// Package aigovernance provides AI agent governance models for CloudForge.
//
// These models support AI agent registry, observability, threat modeling (STRIDE
// + MITRE ATLAS), and maturity assessment. Migrated from AgentGuard — only
// AI-specific models are included here; compliance framework models (Framework,
// Control, Crosswalk, GapAnalysis) already exist in internal/compliance/.
package aigovernance

import (
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// Agent Registry Models
// -----------------------------------------------------------------------------

// Agent represents a registered AI agent in the system.
type Agent struct {
	ID           uuid.UUID    `json:"id" db:"id"`
	Name         string       `json:"name" db:"name"`
	Description  string       `json:"description" db:"description"`
	Framework    string       `json:"framework" db:"framework"` // langchain, crewai, autogen
	Version      string       `json:"version" db:"version"`
	Owner        string       `json:"owner" db:"owner"`
	Team         string       `json:"team" db:"team"`
	Environment  string       `json:"environment" db:"environment"` // dev, staging, prod
	Capabilities []Capability `json:"capabilities" db:"capabilities"`
	Tools        []ToolBinding `json:"tools" db:"tools"`
	Policies     []string     `json:"policies" db:"policies"` // Policy IDs bound to agent
	RiskLevel    string       `json:"risk_level" db:"risk_level"`
	Status       AgentStatus  `json:"status" db:"status"`
	LastActiveAt *time.Time   `json:"last_active_at,omitempty" db:"last_active_at"`
	CreatedAt    time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at" db:"updated_at"`
}

// AgentStatus represents the operational status of an agent.
type AgentStatus string

const (
	AgentStatusActive     AgentStatus = "active"
	AgentStatusInactive   AgentStatus = "inactive"
	AgentStatusSuspended  AgentStatus = "suspended"
	AgentStatusDeprecated AgentStatus = "deprecated"
)

// Capability represents an agent's declared capability.
type Capability struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	DataAccess  []string `json:"data_access"`
	RiskLevel   string   `json:"risk_level"`
}

// ToolBinding represents a tool available to an agent.
type ToolBinding struct {
	ToolID      string            `json:"tool_id"`
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Permissions []string          `json:"permissions"`
	Parameters  map[string]string `json:"parameters"`
}

// -----------------------------------------------------------------------------
// Observability Models
// -----------------------------------------------------------------------------

// AgentTrace represents a complete execution trace for an agent invocation.
type AgentTrace struct {
	TraceID         string           `json:"trace_id" db:"trace_id"`
	AgentID         uuid.UUID        `json:"agent_id" db:"agent_id"`
	SessionID       string           `json:"session_id" db:"session_id"`
	UserID          string           `json:"user_id" db:"user_id"`
	StartTime       time.Time        `json:"start_time" db:"start_time"`
	EndTime         *time.Time       `json:"end_time,omitempty" db:"end_time"`
	DurationMs      int64            `json:"duration_ms" db:"duration_ms"`
	Status          TraceStatus      `json:"status" db:"status"`
	Spans           []Span           `json:"spans" db:"spans"`
	SecuritySignals []SecuritySignal `json:"security_signals" db:"security_signals"`
	Metrics         TraceMetrics     `json:"metrics" db:"metrics"`
	Metadata        map[string]any   `json:"metadata" db:"metadata"`
}

// TraceStatus represents the outcome of a trace.
type TraceStatus string

const (
	TraceStatusRunning   TraceStatus = "running"
	TraceStatusCompleted TraceStatus = "completed"
	TraceStatusFailed    TraceStatus = "failed"
	TraceStatusBlocked   TraceStatus = "blocked" // Policy blocked execution
)

// Span represents a single operation within a trace.
type Span struct {
	SpanID       string         `json:"span_id"`
	ParentSpanID *string        `json:"parent_span_id,omitempty"`
	Name         string         `json:"name"`
	Type         SpanType       `json:"type"`
	StartTime    time.Time      `json:"start_time"`
	EndTime      *time.Time     `json:"end_time,omitempty"`
	DurationMs   int64          `json:"duration_ms"`
	Status       string         `json:"status"`
	Attributes   map[string]any `json:"attributes"`
	Events       []SpanEvent    `json:"events"`
	Data         SpanData       `json:"data"`
}

// SpanType categorizes the type of operation.
type SpanType string

const (
	SpanTypeLLM       SpanType = "llm"
	SpanTypeRetrieval SpanType = "retrieval"
	SpanTypeTool      SpanType = "tool"
	SpanTypeChain     SpanType = "chain"
	SpanTypeAgent     SpanType = "agent"
	SpanTypePolicy    SpanType = "policy"
)

// SpanEvent represents a point-in-time event within a span.
type SpanEvent struct {
	Timestamp  time.Time      `json:"timestamp"`
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes"`
}

// SpanData contains type-specific span data.
type SpanData struct {
	LLM       *LLMSpanData       `json:"llm,omitempty"`
	Retrieval *RetrievalSpanData `json:"retrieval,omitempty"`
	Tool      *ToolSpanData      `json:"tool,omitempty"`
}

// LLMSpanData contains data specific to LLM calls.
type LLMSpanData struct {
	Model            string  `json:"model"`
	Provider         string  `json:"provider"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	Temperature      float64 `json:"temperature"`
	MaxTokens        int     `json:"max_tokens"`
	PromptHash       string  `json:"prompt_hash"`
	FinishReason     string  `json:"finish_reason"`
}

// RetrievalSpanData contains data specific to retrieval operations.
type RetrievalSpanData struct {
	VectorStore   string    `json:"vector_store"`
	Query         string    `json:"query"`
	NumResults    int       `json:"num_results"`
	TopScores     []float64 `json:"top_scores"`
	FilterApplied bool      `json:"filter_applied"`
}

// ToolSpanData contains data specific to tool invocations.
type ToolSpanData struct {
	ToolName       string          `json:"tool_name"`
	ToolCategory   string          `json:"tool_category"`
	InputHash      string          `json:"input_hash"`
	OutputHash     string          `json:"output_hash"`
	ParameterCount int             `json:"parameter_count"`
	ExternalCall   bool            `json:"external_call"`
	PolicyDecision *PolicyDecision `json:"policy_decision,omitempty"`
}

// PolicyDecision records a policy evaluation result.
type PolicyDecision struct {
	PolicyID   string    `json:"policy_id"`
	Decision   string    `json:"decision"` // allow, deny, warn
	Reason     string    `json:"reason"`
	EvalTimeUs int64     `json:"eval_time_us"`
	Timestamp  time.Time `json:"timestamp"`
}

// SecuritySignal represents a security-relevant event detected during execution.
type SecuritySignal struct {
	ID          string         `json:"id"`
	TraceID     string         `json:"trace_id"`
	SpanID      string         `json:"span_id"`
	Type        SignalType     `json:"type"`
	Severity    string         `json:"severity"` // low, medium, high, critical
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	Timestamp   time.Time      `json:"timestamp"`
	Mitigated   bool           `json:"mitigated"`
}

// SignalType categorizes security signals.
type SignalType string

const (
	SignalInjectionAttempt    SignalType = "injection_attempt"
	SignalDataExfiltration    SignalType = "data_exfiltration"
	SignalToolAbuse           SignalType = "tool_abuse"
	SignalPrivilegeEscalation SignalType = "privilege_escalation"
	SignalAnomalousBehavior   SignalType = "anomalous_behavior"
	SignalPolicyViolation     SignalType = "policy_violation"
	SignalRateLimitExceeded   SignalType = "rate_limit_exceeded"
)

// TraceMetrics contains aggregate metrics for a trace.
type TraceMetrics struct {
	TotalSpans        int     `json:"total_spans"`
	LLMCalls          int     `json:"llm_calls"`
	ToolInvocations   int     `json:"tool_invocations"`
	TotalTokens       int     `json:"total_tokens"`
	EstimatedCostUSD  float64 `json:"estimated_cost_usd"`
	PolicyEvaluations int     `json:"policy_evaluations"`
	SecuritySignals   int     `json:"security_signals"`
}

// -----------------------------------------------------------------------------
// Policy Models
// -----------------------------------------------------------------------------

// Policy represents an AI agent security policy definition.
type Policy struct {
	ID          string         `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Description string         `json:"description" db:"description"`
	Type        PolicyType     `json:"type" db:"type"`
	Version     string         `json:"version" db:"version"`
	Scope       PolicyScope    `json:"scope" db:"scope"`
	Rules       []PolicyRule   `json:"rules" db:"rules"`
	Enabled     bool           `json:"enabled" db:"enabled"`
	Priority    int            `json:"priority" db:"priority"`
	Metadata    map[string]any `json:"metadata" db:"metadata"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// PolicyType categorizes AI agent policy types.
type PolicyType string

const (
	PolicyTypeToolAccess PolicyType = "tool_access"
	PolicyTypeDataFlow   PolicyType = "data_flow"
	PolicyTypeHITL       PolicyType = "human_in_loop"
	PolicyTypeRateLimit  PolicyType = "rate_limit"
	PolicyTypeCapability PolicyType = "capability"
)

// PolicyScope defines where a policy applies.
type PolicyScope struct {
	Agents       []string `json:"agents"`       // Agent IDs or "*" for all
	Environments []string `json:"environments"` // dev, staging, prod
	Teams        []string `json:"teams"`
}

// PolicyRule represents a single rule within a policy.
type PolicyRule struct {
	ID         string            `json:"id"`
	Conditions map[string]any    `json:"conditions"`
	Actions    []PolicyAction    `json:"actions"`
	Metadata   map[string]string `json:"metadata"`
}

// PolicyAction defines what happens when a rule matches.
type PolicyAction struct {
	Type       string         `json:"type"` // allow, deny, warn, audit, require_approval
	Parameters map[string]any `json:"parameters"`
}

// -----------------------------------------------------------------------------
// Threat Modeling Models (STRIDE + MITRE ATLAS)
// -----------------------------------------------------------------------------

// ThreatModel represents a complete threat model for an AI agent or system.
type ThreatModel struct {
	ID              string          `json:"id" db:"id"`
	Name            string          `json:"name" db:"name"`
	Description     string          `json:"description" db:"description"`
	TargetAgentID   *uuid.UUID      `json:"target_agent_id,omitempty" db:"target_agent_id"`
	Scope           string          `json:"scope" db:"scope"`
	TrustBoundaries []TrustBoundary `json:"trust_boundaries"`
	Threats         []Threat        `json:"threats"`
	Mitigations     []Mitigation    `json:"mitigations"`
	RiskSummary     RiskSummary     `json:"risk_summary"`
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at" db:"updated_at"`
}

// TrustBoundary represents a security boundary in the system.
type TrustBoundary struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Components  []string `json:"components"`
}

// Threat represents an identified threat.
type Threat struct {
	ID                 string         `json:"id"`
	Title              string         `json:"title"`
	Description        string         `json:"description"`
	Category           STRIDECategory `json:"category"`
	AffectedComponents []string       `json:"affected_components"`
	TrustBoundary      string         `json:"trust_boundary"`
	EntryPoint         string         `json:"entry_point"`
	Likelihood         string         `json:"likelihood"` // low, medium, high, very_high
	Impact             string         `json:"impact"`     // low, medium, high, critical
	RiskLevel          string         `json:"risk_level"` // calculated from likelihood x impact
	ATLASTechniques    []string       `json:"atlas_techniques"`
	MitigationIDs      []string       `json:"mitigation_ids"`
}

// STRIDECategory represents STRIDE threat categories.
type STRIDECategory string

const (
	STRIDESpoofing              STRIDECategory = "spoofing"
	STRIDETampering             STRIDECategory = "tampering"
	STRIDERepudiation           STRIDECategory = "repudiation"
	STRIDEInformationDisclosure STRIDECategory = "information_disclosure"
	STRIDEDenialOfService       STRIDECategory = "denial_of_service"
	STRIDEElevationOfPrivilege  STRIDECategory = "elevation_of_privilege"
)

// Mitigation represents a mitigation control for threats.
type Mitigation struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	ControlType    string   `json:"control_type"` // preventive, detective, corrective
	Implementation string   `json:"implementation"`
	MappedControls []string `json:"mapped_controls"` // References to compliance framework controls
	Status         string   `json:"status"`           // proposed, implemented, verified
}

// RiskSummary provides aggregate risk statistics.
type RiskSummary struct {
	TotalThreats       int            `json:"total_threats"`
	ThreatsByCategory  map[string]int `json:"threats_by_category"`
	ThreatsByRisk      map[string]int `json:"threats_by_risk"`
	MitigationCoverage float64        `json:"mitigation_coverage"`
	ResidualRiskScore  float64        `json:"residual_risk_score"`
}

// -----------------------------------------------------------------------------
// Maturity Assessment Models
// -----------------------------------------------------------------------------

// MaturityAssessment represents a completed AI governance maturity assessment.
type MaturityAssessment struct {
	ID              string             `json:"id" db:"id"`
	OrganizationID  string             `json:"organization_id" db:"organization_id"`
	AssessorID      string             `json:"assessor_id" db:"assessor_id"`
	AssessmentDate  time.Time          `json:"assessment_date" db:"assessment_date"`
	Domains         []DomainAssessment `json:"domains"`
	OverallScore    float64            `json:"overall_score"`
	OverallLevel    int                `json:"overall_level"` // 1-5
	Recommendations []Recommendation   `json:"recommendations"`
	CreatedAt       time.Time          `json:"created_at" db:"created_at"`
}

// DomainAssessment represents assessment of a single maturity domain.
type DomainAssessment struct {
	DomainID     string                 `json:"domain_id"`
	DomainName   string                 `json:"domain_name"`
	Weight       float64                `json:"weight"`
	Score        float64                `json:"score"`
	Level        int                    `json:"level"`
	Capabilities []CapabilityAssessment `json:"capabilities"`
}

// CapabilityAssessment represents assessment of a capability within a domain.
type CapabilityAssessment struct {
	CapabilityID   string   `json:"capability_id"`
	CapabilityName string   `json:"capability_name"`
	CurrentLevel   int      `json:"current_level"`
	TargetLevel    int      `json:"target_level"`
	Evidence       []string `json:"evidence"`
	Notes          string   `json:"notes"`
}

// Recommendation represents an improvement recommendation.
type Recommendation struct {
	ID           string   `json:"id"`
	Priority     string   `json:"priority"` // high, medium, low
	Domain       string   `json:"domain"`
	Capability   string   `json:"capability"`
	CurrentLevel int      `json:"current_level"`
	TargetLevel  int      `json:"target_level"`
	Description  string   `json:"description"`
	Actions      []string `json:"actions"`
	Effort       string   `json:"effort"` // small, medium, large
	Impact       string   `json:"impact"` // low, medium, high
}
