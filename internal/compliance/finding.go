// Package compliance provides compliance framework mapping and assessment
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ResourceType categorizes the type of resource
type ResourceType string

const (
	ResourceTypeCompute   ResourceType = "compute"
	ResourceTypeNetwork   ResourceType = "network"
	ResourceTypeStorage   ResourceType = "storage"
	ResourceTypeDatabase  ResourceType = "database"
	ResourceTypeIdentity  ResourceType = "identity"
	ResourceTypeContainer ResourceType = "container"
	ResourceTypeServerless ResourceType = "serverless"
	ResourceTypeMessaging ResourceType = "messaging"
	ResourceTypeSecurity  ResourceType = "security"
	ResourceTypeMonitoring ResourceType = "monitoring"
	ResourceTypeOther     ResourceType = "other"
)

// Platform represents the infrastructure platform
type Platform string

const (
	PlatformOnPrem  Platform = "on-premises"
	PlatformHybrid  Platform = "hybrid"
	PlatformCloud   Platform = "cloud"
	PlatformPrivate Platform = "private-cloud"
)

// CloudProvider represents a cloud provider
type CloudProvider string

const (
	CloudProviderAWS          CloudProvider = "aws"
	CloudProviderGCP          CloudProvider = "gcp"
	CloudProviderAzure        CloudProvider = "azure"
	CloudProviderOCI          CloudProvider = "oci"
	CloudProviderAliCloud     CloudProvider = "alicloud"
	CloudProviderPrivate      CloudProvider = "private"
	CloudProviderMultiCloud   CloudProvider = "multi-cloud"
	CloudProviderNone         CloudProvider = "none"
)

// EnvironmentType represents the environment classification
type EnvironmentType string

const (
	EnvProduction    EnvironmentType = "production"
	EnvStaging       EnvironmentType = "staging"
	EnvDevelopment   EnvironmentType = "development"
	EnvQA            EnvironmentType = "qa"
	EnvUAT           EnvironmentType = "uat"
	EnvSandbox       EnvironmentType = "sandbox"
	EnvDisasterRecovery EnvironmentType = "disaster-recovery"
)

// FindingType categorizes the finding
type FindingType string

const (
	// Core finding types
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeToxicCombo       FindingType = "toxic_combination"
	FindingTypeCompliance       FindingType = "compliance_violation"
	FindingTypeSecurityGap      FindingType = "security_gap"
	FindingTypeRuntimeThreat    FindingType = "runtime_threat"
	FindingTypeDataExposure     FindingType = "data_exposure"
	FindingTypeAccessViolation  FindingType = "access_violation"

	// GCP Security Command Center compatible types
	FindingTypeOSVulnerability       FindingType = "os_vulnerability"
	FindingTypeSoftwareVulnerability FindingType = "software_vulnerability"
	FindingTypeContainerVulnerability FindingType = "container_vulnerability"
	FindingTypeWebVulnerability      FindingType = "web_vulnerability"
	FindingTypeThreatDetection       FindingType = "threat_detection"
	FindingTypeMalware               FindingType = "malware"
	FindingTypeCryptomining          FindingType = "cryptomining"
	FindingTypeDataRisk              FindingType = "data_risk"
	FindingTypeIAMAnomaly            FindingType = "iam_anomaly"
	FindingTypeNetworkAnomaly        FindingType = "network_anomaly"
	FindingTypePersistence           FindingType = "persistence"
	FindingTypePrivilegeEscalation   FindingType = "privilege_escalation"
	FindingTypeCredentialAccess      FindingType = "credential_access"
	FindingTypeDefenseEvasion        FindingType = "defense_evasion"
	FindingTypeExfiltration          FindingType = "exfiltration"
	FindingTypeInitialAccess         FindingType = "initial_access"
	FindingTypeLateralMovement       FindingType = "lateral_movement"
	FindingTypeResourceExploitation  FindingType = "resource_exploitation"

	// AWS Security Hub compatible types
	FindingTypeSensitiveDataExposure    FindingType = "sensitive_data_exposure"
	FindingTypeUnauthorizedAccess       FindingType = "unauthorized_access"
	FindingTypeUnusualBehavior          FindingType = "unusual_behavior"
	FindingTypePolicyViolation          FindingType = "policy_violation"
	FindingTypeInsecureConfiguration    FindingType = "insecure_configuration"
	FindingTypePatchRequired            FindingType = "patch_required"
	FindingTypeEncryptionMissing        FindingType = "encryption_missing"
	FindingTypeLoggingDisabled          FindingType = "logging_disabled"
	FindingTypePubliclyAccessible       FindingType = "publicly_accessible"

	// Azure Defender compatible types
	FindingTypeBruteForce           FindingType = "brute_force"
	FindingTypeSuspiciousActivity   FindingType = "suspicious_activity"
	FindingTypeFilelessAttack       FindingType = "fileless_attack"
	FindingTypeContainerEscape      FindingType = "container_escape"
	FindingTypeKubernetesAnomaly    FindingType = "kubernetes_anomaly"
)

// FindingCategory represents the high-level category
type FindingCategory string

const (
	CategoryVulnerability       FindingCategory = "VULNERABILITY"
	CategoryMisconfiguration    FindingCategory = "MISCONFIGURATION"
	CategoryThreat              FindingCategory = "THREAT"
	CategoryCompliance          FindingCategory = "COMPLIANCE"
	CategoryDataProtection      FindingCategory = "DATA_PROTECTION"
	CategoryIdentity            FindingCategory = "IDENTITY"
	CategoryNetwork             FindingCategory = "NETWORK"
	CategoryCompute             FindingCategory = "COMPUTE"
	CategoryStorage             FindingCategory = "STORAGE"
	CategoryContainer           FindingCategory = "CONTAINER"
	CategoryServerless          FindingCategory = "SERVERLESS"
	CategoryDatabase            FindingCategory = "DATABASE"
)

// AssigneeInfo represents finding assignment information
type AssigneeInfo struct {
	UserID       string    `json:"user_id" yaml:"user_id"`
	UserEmail    string    `json:"user_email" yaml:"user_email"`
	UserName     string    `json:"user_name" yaml:"user_name"`
	Team         string    `json:"team" yaml:"team"`
	AssignedAt   time.Time `json:"assigned_at" yaml:"assigned_at"`
	AssignedBy   string    `json:"assigned_by" yaml:"assigned_by"`
	DueDate      *time.Time `json:"due_date,omitempty" yaml:"due_date"`
	Escalated    bool      `json:"escalated" yaml:"escalated"`
	EscalatedTo  string    `json:"escalated_to,omitempty" yaml:"escalated_to"`
	EscalatedAt  *time.Time `json:"escalated_at,omitempty" yaml:"escalated_at"`
}

// WorkflowStatus represents the finding workflow status
type WorkflowStatus string

const (
	StatusNew          WorkflowStatus = "new"
	StatusTriaged      WorkflowStatus = "triaged"
	StatusAssigned     WorkflowStatus = "assigned"
	StatusInProgress   WorkflowStatus = "in_progress"
	StatusPendingInfo  WorkflowStatus = "pending_info"
	StatusPendingApproval WorkflowStatus = "pending_approval"
	StatusRemediated   WorkflowStatus = "remediated"
	StatusVerified     WorkflowStatus = "verified"
	StatusClosed       WorkflowStatus = "closed"
	StatusReopened     WorkflowStatus = "reopened"
	StatusSuppressed   WorkflowStatus = "suppressed"
	StatusFalsePositive WorkflowStatus = "false_positive"
	StatusRiskAccepted WorkflowStatus = "risk_accepted"
	StatusWontFix      WorkflowStatus = "wont_fix"
)

// Finding represents a comprehensive security finding
type Finding struct {
	// Core Identification
	ID                string      `json:"id" yaml:"id"`
	Source            string      `json:"source" yaml:"source"`                         // Tool/scanner that found this
	SourceFindingID   string      `json:"source_finding_id" yaml:"source_finding_id"`   // Original ID from source
	Type              FindingType `json:"type" yaml:"type"`
	Title             string      `json:"title" yaml:"title"`
	Description       string      `json:"description" yaml:"description"`

	// Resource Information
	ResourceType      ResourceType  `json:"resource_type" yaml:"resource_type"`
	ResourceID        string        `json:"resource_id" yaml:"resource_id"`             // ARN, Resource ID, etc.
	ResourceName      string        `json:"resource_name" yaml:"resource_name"`
	ResourceARN       string        `json:"resource_arn,omitempty" yaml:"resource_arn"` // AWS ARN if applicable
	
	// On-Premises Identification
	Hostname          string        `json:"hostname,omitempty" yaml:"hostname"`
	SerialNumber      string        `json:"serial_number,omitempty" yaml:"serial_number"`
	IPAddress         string        `json:"ip_address,omitempty" yaml:"ip_address"`
	MACAddress        string        `json:"mac_address,omitempty" yaml:"mac_address"`
	AssetTag          string        `json:"asset_tag,omitempty" yaml:"asset_tag"`

	// Platform & Environment
	Platform          Platform      `json:"platform" yaml:"platform"`
	CloudProvider     CloudProvider `json:"cloud_provider" yaml:"cloud_provider"`
	Region            string        `json:"region" yaml:"region"`
	AvailabilityZone  string        `json:"availability_zone,omitempty" yaml:"availability_zone"`
	VPC               string        `json:"vpc,omitempty" yaml:"vpc"`
	Subnet            string        `json:"subnet,omitempty" yaml:"subnet"`
	AccountID         string        `json:"account_id" yaml:"account_id"`
	AccountName       string        `json:"account_name,omitempty" yaml:"account_name"`
	EnvironmentType   EnvironmentType `json:"environment_type" yaml:"environment_type"`
	
	// Linked/Impacted Resources
	ImpactedResources []ImpactedResource `json:"impacted_resources,omitempty" yaml:"impacted_resources"`

	// Severity & Risk Assessment
	StaticSeverity    string      `json:"static_severity" yaml:"static_severity"`         // Original severity from scanner
	Severity          string      `json:"severity" yaml:"severity"`                       // Normalized severity
	AIRiskScore       float64     `json:"ai_risk_score" yaml:"ai_risk_score"`             // 0.0 - 10.0
	AIRiskLevel       string      `json:"ai_risk_level" yaml:"ai_risk_level"`             // critical, high, medium, low
	AIRiskRationale   string      `json:"ai_risk_rationale" yaml:"ai_risk_rationale"`     // AI explanation
	AIContextualFactors []string  `json:"ai_contextual_factors" yaml:"ai_contextual_factors"`
	CVSS              float64     `json:"cvss,omitempty" yaml:"cvss"`
	CVSSVector        string      `json:"cvss_vector,omitempty" yaml:"cvss_vector"`
	EPSS              float64     `json:"epss,omitempty" yaml:"epss"`                     // Exploit Prediction Score
	ExploitAvailable  bool        `json:"exploit_available" yaml:"exploit_available"`
	
	// Vulnerability References
	CVEs              []CVEReference `json:"cves,omitempty" yaml:"cves"`
	CWEs              []string       `json:"cwes,omitempty" yaml:"cwes"`
	
	// Compliance Mappings
	ComplianceMappings []ComplianceMapping `json:"compliance_mappings,omitempty" yaml:"compliance_mappings"`
	
	// MITRE ATT&CK Mapping
	MITRETactics      []string `json:"mitre_tactics,omitempty" yaml:"mitre_tactics"`
	MITRETechniques   []string `json:"mitre_techniques,omitempty" yaml:"mitre_techniques"`
	
	// Toxic Combination Details
	ToxicComboDetails *ToxicComboDetails `json:"toxic_combo_details,omitempty" yaml:"toxic_combo_details"`
	
	// Remediation
	Remediation       string              `json:"remediation" yaml:"remediation"`
	RemediationSteps  []RemediationStep   `json:"remediation_steps,omitempty" yaml:"remediation_steps"`
	RemediationLinks  []RemediationLink   `json:"remediation_links,omitempty" yaml:"remediation_links"`
	AutoRemediatable  bool                `json:"auto_remediatable" yaml:"auto_remediatable"`
	RemediationScript string              `json:"remediation_script,omitempty" yaml:"remediation_script"`
	
	// Category (high-level)
	Category          FindingCategory `json:"category" yaml:"category"`

	// Status & Workflow
	Status            string         `json:"status" yaml:"status"`                         // open, in_progress, resolved, suppressed
	WorkflowStatus    WorkflowStatus `json:"workflow_status" yaml:"workflow_status"`
	Assignee          *AssigneeInfo  `json:"assignee,omitempty" yaml:"assignee"`
	FalsePositive     *FalsePositiveInfo `json:"false_positive,omitempty" yaml:"false_positive"`
	Suppressed        bool          `json:"suppressed" yaml:"suppressed"`
	SuppressionReason string        `json:"suppression_reason,omitempty" yaml:"suppression_reason"`
	SuppressionExpiry *time.Time    `json:"suppression_expiry,omitempty" yaml:"suppression_expiry"`
	
	// Ownership & Organization
	TechnicalContact  *Contact      `json:"technical_contact,omitempty" yaml:"technical_contact"`
	BusinessOwner     *Contact      `json:"business_owner,omitempty" yaml:"business_owner"`
	ServiceName       string        `json:"service_name" yaml:"service_name"`
	ServiceID         string        `json:"service_id,omitempty" yaml:"service_id"`
	LineOfBusiness    string        `json:"line_of_business" yaml:"line_of_business"`
	CostCenter        string        `json:"cost_center,omitempty" yaml:"cost_center"`
	Team              string        `json:"team,omitempty" yaml:"team"`
	Application       string        `json:"application,omitempty" yaml:"application"`
	
	// Timestamps
	FirstFoundAt      time.Time     `json:"first_found_at" yaml:"first_found_at"`
	LastSeenAt        time.Time     `json:"last_seen_at" yaml:"last_seen_at"`
	ResolvedAt        *time.Time    `json:"resolved_at,omitempty" yaml:"resolved_at"`
	DueDate           *time.Time    `json:"due_date,omitempty" yaml:"due_date"`
	SLABreachDate     *time.Time    `json:"sla_breach_date,omitempty" yaml:"sla_breach_date"`
	
	// Deduplication
	DeduplicationKey  string        `json:"deduplication_key" yaml:"deduplication_key"`
	CanonicalRuleID   string        `json:"canonical_rule_id" yaml:"canonical_rule_id"`
	RelatedRules      []string      `json:"related_rules,omitempty" yaml:"related_rules"`
	DuplicateOf       string        `json:"duplicate_of,omitempty" yaml:"duplicate_of"`
	
	// Ticketing Integration
	TicketID          string        `json:"ticket_id,omitempty" yaml:"ticket_id"`
	TicketURL         string        `json:"ticket_url,omitempty" yaml:"ticket_url"`
	TicketStatus      string        `json:"ticket_status,omitempty" yaml:"ticket_status"`
	
	// Raw Data
	RawData           map[string]interface{} `json:"raw_data,omitempty" yaml:"raw_data"`
	Tags              map[string]string      `json:"tags,omitempty" yaml:"tags"`
}

// ImpactedResource represents a linked/impacted resource
type ImpactedResource struct {
	ResourceID    string       `json:"resource_id" yaml:"resource_id"`
	ResourceName  string       `json:"resource_name" yaml:"resource_name"`
	ResourceType  ResourceType `json:"resource_type" yaml:"resource_type"`
	Relationship  string       `json:"relationship" yaml:"relationship"` // depends_on, connected_to, impacts
	ImpactLevel   string       `json:"impact_level" yaml:"impact_level"` // direct, indirect
}

// CVEReference represents a CVE with hyperlink and metadata
type CVEReference struct {
	ID          string    `json:"id" yaml:"id"`
	URL         string    `json:"url" yaml:"url"`
	NVDUrl      string    `json:"nvd_url" yaml:"nvd_url"`
	MitreURL    string    `json:"mitre_url" yaml:"mitre_url"`
	Description string    `json:"description" yaml:"description"`
	CVSS        float64   `json:"cvss" yaml:"cvss"`
	CVSSVector  string    `json:"cvss_vector" yaml:"cvss_vector"`
	CVSSVersion string    `json:"cvss_version" yaml:"cvss_version"`
	EPSS        float64   `json:"epss" yaml:"epss"`
	CISAKnownExploited bool `json:"cisa_known_exploited" yaml:"cisa_known_exploited"`
	Published   time.Time `json:"published" yaml:"published"`
	Modified    time.Time `json:"modified" yaml:"modified"`
}

// BuildCVEURLs populates CVE URLs
func (c *CVEReference) BuildCVEURLs() {
	if c.ID == "" {
		return
	}
	c.NVDUrl = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", c.ID)
	c.MitreURL = fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", c.ID)
	c.URL = c.NVDUrl // Default to NVD
}

// RemediationStep represents a step in the remediation process
type RemediationStep struct {
	Order       int    `json:"order" yaml:"order"`
	Title       string `json:"title" yaml:"title"`
	Description string `json:"description" yaml:"description"`
	Command     string `json:"command,omitempty" yaml:"command"`
	Platform    string `json:"platform,omitempty" yaml:"platform"` // aws, azure, gcp, cli
	Automated   bool   `json:"automated" yaml:"automated"`
}

// RemediationLink represents a reference link for remediation
type RemediationLink struct {
	Title       string `json:"title" yaml:"title"`
	URL         string `json:"url" yaml:"url"`
	Type        string `json:"type" yaml:"type"` // vendor, cve, kb, documentation
}

// FalsePositiveInfo documents a false positive determination
type FalsePositiveInfo struct {
	IsFalsePositive bool      `json:"is_false_positive" yaml:"is_false_positive"`
	Reason          string    `json:"reason" yaml:"reason"`
	Evidence        string    `json:"evidence" yaml:"evidence"`
	DeterminedBy    string    `json:"determined_by" yaml:"determined_by"`
	DeterminedAt    time.Time `json:"determined_at" yaml:"determined_at"`
	ApprovedBy      string    `json:"approved_by,omitempty" yaml:"approved_by"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty" yaml:"approved_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty" yaml:"expires_at"`
	ReviewRequired  bool      `json:"review_required" yaml:"review_required"`
}

// Contact represents a contact person
type Contact struct {
	Name       string `json:"name" yaml:"name"`
	Email      string `json:"email" yaml:"email"`
	Team       string `json:"team,omitempty" yaml:"team"`
	Phone      string `json:"phone,omitempty" yaml:"phone"`
	SlackID    string `json:"slack_id,omitempty" yaml:"slack_id"`
	OnCallURL  string `json:"on_call_url,omitempty" yaml:"on_call_url"`
}

// ComplianceMapping maps a finding to a compliance control
type ComplianceMapping struct {
	FrameworkID   string `json:"framework_id" yaml:"framework_id"`
	FrameworkName string `json:"framework_name" yaml:"framework_name"`
	ControlID     string `json:"control_id" yaml:"control_id"`
	ControlTitle  string `json:"control_title" yaml:"control_title"`
	Section       string `json:"section" yaml:"section"`
	Subsection    string `json:"subsection,omitempty" yaml:"subsection"`
	Severity      string `json:"severity" yaml:"severity"`
	URL           string `json:"url" yaml:"url"`
}

// ToxicComboDetails describes a toxic combination of findings
type ToxicComboDetails struct {
	ComboType        string   `json:"combo_type" yaml:"combo_type"`
	Description      string   `json:"description" yaml:"description"`
	RelatedFindings  []string `json:"related_findings" yaml:"related_findings"`
	AttackVector     string   `json:"attack_vector" yaml:"attack_vector"`
	AttackPath       []string `json:"attack_path" yaml:"attack_path"`
	ExploitPotential string   `json:"exploit_potential" yaml:"exploit_potential"`
	BlastRadius      string   `json:"blast_radius" yaml:"blast_radius"`
	MITRETechniques  []string `json:"mitre_techniques" yaml:"mitre_techniques"`
}

// GenerateDeduplicationKey generates a unique key for deduplication
func (f *Finding) GenerateDeduplicationKey() string {
	// Create a composite key from resource + rule + specific finding details
	components := []string{
		string(f.ResourceType),
		f.ResourceID,
		f.CanonicalRuleID,
		f.Title,
	}
	
	// Add CVEs if present (vulnerabilities are unique per CVE)
	if len(f.CVEs) > 0 {
		for _, cve := range f.CVEs {
			components = append(components, cve.ID)
		}
	}
	
	data := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // First 16 bytes = 32 hex chars
}

// CalculateSLADueDate calculates the SLA due date based on severity
func (f *Finding) CalculateSLADueDate(slaConfig map[string]int) {
	if f.FirstFoundAt.IsZero() {
		f.FirstFoundAt = time.Now()
	}
	
	// Default SLA days by severity
	defaultSLA := map[string]int{
		"critical": 1,
		"high":     7,
		"medium":   30,
		"low":      90,
	}
	
	if slaConfig == nil {
		slaConfig = defaultSLA
	}
	
	severity := strings.ToLower(f.Severity)
	if days, ok := slaConfig[severity]; ok {
		dueDate := f.FirstFoundAt.AddDate(0, 0, days)
		f.DueDate = &dueDate
	}
}

// IsOverdue checks if the finding is past its SLA
func (f *Finding) IsOverdue() bool {
	if f.DueDate == nil || f.Status == "resolved" {
		return false
	}
	return time.Now().After(*f.DueDate)
}

// EnrichCVEReferences enriches CVE references with URLs
func (f *Finding) EnrichCVEReferences() {
	for i := range f.CVEs {
		f.CVEs[i].BuildCVEURLs()
	}
}

// MarkFalsePositive marks the finding as a false positive
func (f *Finding) MarkFalsePositive(reason, evidence, determinedBy string, expiresAt *time.Time) {
	now := time.Now()
	f.FalsePositive = &FalsePositiveInfo{
		IsFalsePositive: true,
		Reason:          reason,
		Evidence:        evidence,
		DeterminedBy:    determinedBy,
		DeterminedAt:    now,
		ExpiresAt:       expiresAt,
		ReviewRequired:  true,
	}
	f.Status = "suppressed"
	f.Suppressed = true
	f.SuppressionReason = "False positive: " + reason
}

// ApproveFalsePositive approves a false positive determination
func (f *Finding) ApproveFalsePositive(approvedBy string) {
	if f.FalsePositive != nil {
		now := time.Now()
		f.FalsePositive.ApprovedBy = approvedBy
		f.FalsePositive.ApprovedAt = &now
		f.FalsePositive.ReviewRequired = false
	}
}

// IsFalsePositiveExpired checks if false positive determination has expired
func (f *Finding) IsFalsePositiveExpired() bool {
	if f.FalsePositive == nil || f.FalsePositive.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*f.FalsePositive.ExpiresAt)
}

// GetContextualRiskFactors returns factors affecting AI risk assessment
func (f *Finding) GetContextualRiskFactors() []string {
	var factors []string
	
	// Environment-based factors
	if f.EnvironmentType == EnvProduction {
		factors = append(factors, "production_environment")
	}
	
	// Exploit availability
	if f.ExploitAvailable {
		factors = append(factors, "exploit_available")
	}
	
	// CISA KEV
	for _, cve := range f.CVEs {
		if cve.CISAKnownExploited {
			factors = append(factors, "cisa_known_exploited")
			break
		}
	}
	
	// High EPSS
	if f.EPSS > 0.5 {
		factors = append(factors, "high_epss_score")
	}
	
	// Internet-facing
	if f.ResourceType == ResourceTypeNetwork {
		factors = append(factors, "network_resource")
	}
	
	// Critical data
	if f.ResourceType == ResourceTypeDatabase || f.ResourceType == ResourceTypeStorage {
		factors = append(factors, "data_resource")
	}
	
	// Toxic combo
	if f.ToxicComboDetails != nil {
		factors = append(factors, "toxic_combination")
	}
	
	return factors
}

