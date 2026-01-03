# CloudForge — High-Level Design Document

**Version:** 1.0  
**Author:** Liem Vo-Nguyen  
**Date:** January 2026  
**Status:** Draft

---

## Executive Summary

CloudForge is an enterprise Internal Developer Platform (IDP) that enables secure, policy-governed cloud resource provisioning across AWS, Azure, and GCP. It combines self-service developer workflows with AI-powered security intelligence to balance developer velocity with compliance requirements.

**Key Differentiators:**
- AI-powered contextual risk scoring that transforms raw CVSS/severity into actionable, business-contextualized assessments
- Self-service provisioning portal with intelligent GRC routing for exception handling
- Policy-as-code guardrails using OPA/Rego enforced at provisioning time
- Gold templates defining blessed configurations with automated drift detection
- AI-assisted remediation runbooks that accelerate finding closure

**Target Scale:** 270+ cloud environments across 4 AWS Organizations, 93 GCP projects, and 45 Azure subscriptions.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CLOUDFORGE PLATFORM                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                     SELF-SERVICE PORTAL (React/Next.js)                 │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │   │
│  │  │ Provisioning│  │   Request   │  │   Finding   │  │   Runbook   │    │   │
│  │  │   Catalog   │  │   Tracker   │  │  Dashboard  │  │   Library   │    │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                        │
│                                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         API GATEWAY (Kong/NGINX)                        │   │
│  │                    AuthN: Azure AD / Okta OIDC                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                        │
│         ┌──────────────────────────────┼──────────────────────────────┐        │
│         ▼                              ▼                              ▼        │
│  ┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────┐    │
│  │   PROVISIONING  │      │    AI INTELLIGENCE  │      │  POLICY ENGINE  │    │
│  │     SERVICE     │      │       SERVICE       │      │    (OPA/Rego)   │    │
│  │                 │      │                     │      │                 │    │
│  │ • Request Queue │      │ • Risk Scoring      │      │ • Gold Template │    │
│  │ • GRC Routing   │      │ • Finding Explainer │      │   Validation    │    │
│  │ • Approval Flow │      │ • Remediation Gen   │      │ • Drift Detect  │    │
│  │ • Terraform Exec│      │ • OOB Triage        │      │ • Exception Mgmt│    │
│  └────────┬────────┘      └──────────┬──────────┘      └────────┬────────┘    │
│           │                          │                          │              │
│           └──────────────────────────┼──────────────────────────┘              │
│                                      ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    WORKFLOW ORCHESTRATION (Temporal)                    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│         ┌────────────────────────────┼────────────────────────────┐            │
│         ▼                            ▼                            ▼            │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐        │
│  │  CLOUD PROVIDERS │      │  ENTERPRISE SVC  │      │   DATA STORES   │        │
│  │                 │      │                 │      │                 │        │
│  │ • AWS (OIDC)    │      │ • ServiceNow    │      │ • PostgreSQL    │        │
│  │ • Azure (MI)    │      │ • RSA Archer    │      │ • Redis         │        │
│  │ • GCP (WIF)     │      │ • Asana         │      │ • S3/Blob/GCS   │        │
│  │                 │      │ • MS Graph      │      │                 │        │
│  └─────────────────┘      └─────────────────┘      └─────────────────┘        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
            ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
            │     AWS     │   │    Azure    │   │     GCP     │
            │ Security Hub│   │  Defender   │   │     SCC     │
            │   4 Orgs    │   │   45 Subs   │   │  93 Projects│
            └─────────────┘   └─────────────┘   └─────────────┘
```

---

## Component Specifications

### 1. Self-Service Portal

**Technology:** React 18 + Next.js 14 + TypeScript + Tailwind CSS

**Features:**

| Module | Description |
|--------|-------------|
| Provisioning Catalog | Browse gold templates, request resources, track approval status |
| Request Tracker | View pending/approved/denied requests, appeal decisions |
| Finding Dashboard | View findings with contextual risk scores, filter by CBU/Tier/Severity |
| Runbook Library | Search remediation runbooks, copy Terraform/CLI snippets |
| Admin Console | Manage gold templates, review exception requests, configure policies |

**Authentication:**
- Azure AD OIDC / Okta integration
- RBAC: Developer, Security Analyst, Security Admin, Platform Admin
- Group-based permissions mapped from IdP claims

**UX Flow — Provisioning Request:**
```
Developer → Browse Catalog → Select Gold Template → Customize Parameters
    │
    ▼
Policy Check (OPA) ──► Compliant? ──► Yes ──► Auto-Approve ──► Terraform Apply
    │                      │
    │                      ▼ No
    │              Deviation Detected
    │                      │
    │         ┌────────────┴────────────┐
    │         ▼                         ▼
    │    Minor Deviation           Major Deviation
    │    (Auto-route to            (Route to GRC for
    │    Security Review)          Risk Acceptance)
    │         │                         │
    │         ▼                         ▼
    │    Security Analyst          GRC Committee
    │    Approval (24h SLA)        Review (5-day SLA)
    │         │                         │
    └─────────┴─────────────────────────┘
                        │
                        ▼
              Approved ──► Terraform Apply
              Denied ──► Notification + Appeal Option
```

---

### 2. AI Intelligence Service

**Technology:** Go 1.22+ with LLM provider abstraction

**LLM Provider Interface:**
```go
type LLMProvider interface {
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
    Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error)
    CountTokens(text string) (int, error)
}

// Implementations: Anthropic Claude, OpenAI GPT-4, AWS Bedrock
```

#### 2.1 Contextual Risk Scoring

Transforms raw CVSS/severity from cloud security tools into business-contextualized risk assessments.

**Input Sources:**

| Signal | Source | Weight |
|--------|--------|--------|
| Raw Severity | Security Hub / Defender / SCC | Baseline |
| Asset Tier | CMDB / Resource Tags (Tier1-Prod, Tier2-Staging, Tier3-Dev) | High |
| Network Exposure | Security Groups, Firewall Rules, Load Balancer Config | High |
| Data Classification | Resource Tags (PII, PCI, Internal, Public) | High |
| Compensating Controls | WAF presence, EDR agent, Network Segmentation | Medium |
| Package In Use | SBOM, Runtime Agent, Manual Tags | Medium |
| Auto-Provisions | Deployment metadata | Low |
| Historical FPs | Past findings marked false positive for same signature | Medium |

**Data Model:**
```go
type Finding struct {
    ID              string          `json:"id"`
    Source          string          `json:"source"`           // SecurityHub, Defender, SCC
    RawSeverity     string          `json:"raw_severity"`     // CRITICAL, HIGH, MEDIUM, LOW
    CVE             string          `json:"cve,omitempty"`
    ResourceID      string          `json:"resource_id"`
    ResourceType    string          `json:"resource_type"`
    Title           string          `json:"title"`
    Description     string          `json:"description"`
    DetectedAt      time.Time       `json:"detected_at"`
    
    Context         *FindingContext `json:"context,omitempty"`
    RiskAssessment  *RiskAssessment `json:"risk_assessment,omitempty"`
}

type FindingContext struct {
    AssetTier            string   `json:"asset_tier"`             // Tier1-Prod, Tier2-Staging, Tier3-Dev
    CBU                  string   `json:"cbu"`                    // Cloud Business Unit
    EnvType              string   `json:"env_type"`               // prod, staging, dev, sandbox
    NetworkExposure      string   `json:"network_exposure"`       // public, internal, isolated
    CompensatingControls []string `json:"compensating_controls"`  // WAF, EDR, segmentation
    PackageInUse         *bool    `json:"package_in_use"`         // nil if unknown
    AutoProvisions       bool     `json:"auto_provisions"`
    HistoricalFPs        int      `json:"historical_fps"`
    DataClassification   string   `json:"data_classification"`    // PII, PCI, internal, public
    LastScanDate         time.Time `json:"last_scan_date"`
}

type RiskAssessment struct {
    AdjustedSeverity  string    `json:"adjusted_severity"`   // CRITICAL → LOW
    Confidence        float64   `json:"confidence"`          // 0.0-1.0
    Rationale         string    `json:"rationale"`           // LLM-generated explanation
    Recommendation    string    `json:"recommendation"`      // accept, remediate, escalate
    SuggestedTimeline string    `json:"suggested_timeline"`  // immediate, next_cycle, backlog
    GeneratedAt       time.Time `json:"generated_at"`
}
```

**Example Output:**
```json
{
  "finding_id": "arn:aws:securityhub:us-west-2:123456789:finding/abc123",
  "raw_severity": "CRITICAL",
  "risk_assessment": {
    "adjusted_severity": "LOW",
    "confidence": 0.87,
    "rationale": "CVE-2024-1234 affects libfoo v1.2.3 which is installed but not in the active runtime codepath based on SBOM analysis. The host is in a Tier3-Dev environment with no public network exposure (isolated VPC, no ingress rules). Compensating controls include: network segmentation, EDR agent active, no sensitive data classification. Historical data shows 3 prior FPs for this signature in similar configurations.",
    "recommendation": "accept",
    "suggested_timeline": "backlog"
  }
}
```

#### 2.2 Finding Explainer

Generates plain-English explanations of why a finding was flagged, suitable for developers who may not have deep security expertise.

**Prompt Template:**
```
You are a security analyst explaining a cloud security finding to a developer.

Finding Details:
- Title: {title}
- Severity: {raw_severity}
- Resource: {resource_type} ({resource_id})
- Description: {description}

Context:
- Environment: {env_type} ({asset_tier})
- Business Unit: {cbu}
- Network Exposure: {network_exposure}
- Data Classification: {data_classification}

Explain:
1. What this finding means in plain English
2. Why it matters (or doesn't) given the context
3. The actual risk to the organization
4. Recommended next steps

Keep the explanation concise (3-4 paragraphs max) and avoid unnecessary jargon.
```

#### 2.3 AI Remediation Runbooks

Generates remediation steps, Terraform snippets, and CLI commands for findings. Human-reviewed before being added to the runbook library.

**Data Model:**
```go
type RemediationRunbook struct {
    ID              string             `json:"id"`
    FindingType     string             `json:"finding_type"`      // public-s3-bucket, unencrypted-disk
    CloudProvider   string             `json:"cloud_provider"`    // aws, azure, gcp
    Title           string             `json:"title"`
    Description     string             `json:"description"`
    
    Steps           []RemediationStep  `json:"steps"`
    TerraformFix    string             `json:"terraform_fix,omitempty"`
    CLICommands     []string           `json:"cli_commands,omitempty"`
    RollbackSteps   []RemediationStep  `json:"rollback_steps,omitempty"`
    
    // Metadata
    GeneratedBy     string             `json:"generated_by"`      // ai-assisted, manual
    ReviewedBy      string             `json:"reviewed_by"`       // human approver
    ApprovedAt      *time.Time         `json:"approved_at,omitempty"`
    LastUpdated     time.Time          `json:"last_updated"`
    UsageCount      int                `json:"usage_count"`
}

type RemediationStep struct {
    Order       int    `json:"order"`
    Action      string `json:"action"`
    Description string `json:"description"`
    RiskNotes   string `json:"risk_notes,omitempty"`   // "30s downtime expected"
    Automated   bool   `json:"automated"`              // can CloudForge execute this?
}
```

**Runbook Generation Flow:**
```
Finding Detected
       │
       ▼
Check Runbook Library ──► Exists? ──► Yes ──► Return Existing Runbook
       │                     │
       │                     ▼ No
       │              Generate Draft (LLM)
       │                     │
       │                     ▼
       │              Queue for Human Review
       │                     │
       │                     ▼
       │              Security Analyst Reviews
       │                     │
       │         ┌───────────┴───────────┐
       │         ▼                       ▼
       │      Approve               Request Changes
       │         │                       │
       │         ▼                       ▼
       │    Add to Library         Regenerate with Feedback
       │         │
       └─────────┴─► Return Runbook
```

#### 2.4 OOB Provisioning Triage

Intelligently routes out-of-band (non-standard) provisioning requests to appropriate reviewers.

**Triage Logic:**
```go
type ProvisioningRequest struct {
    ID                string                 `json:"id"`
    Requester         string                 `json:"requester"`
    RequestedResource ResourceSpec           `json:"requested_resource"`
    GoldTemplateID    string                 `json:"gold_template_id,omitempty"`
    Deviations        []PolicyDeviation      `json:"deviations"`
    BusinessCase      string                 `json:"business_case"`
    Status            string                 `json:"status"`
    TriageResult      *TriageResult          `json:"triage_result,omitempty"`
}

type PolicyDeviation struct {
    PolicyID      string `json:"policy_id"`
    PolicyName    string `json:"policy_name"`
    Expected      string `json:"expected"`
    Actual        string `json:"actual"`
    Severity      string `json:"severity"`       // minor, major, critical
    Justification string `json:"justification"`
}

type TriageResult struct {
    Route           string   `json:"route"`           // auto_approve, security_review, grc_review
    Confidence      float64  `json:"confidence"`
    Rationale       string   `json:"rationale"`
    AssignedTo      []string `json:"assigned_to"`
    SLA             string   `json:"sla"`             // 4h, 24h, 5d
    RiskScore       int      `json:"risk_score"`      // 1-100
}
```

**Routing Rules:**

| Deviation Type | Risk Score | Route | SLA |
|----------------|------------|-------|-----|
| No deviations | 0 | Auto-approve | Immediate |
| Minor config difference (e.g., larger instance size) | 1-25 | Auto-approve with audit log | Immediate |
| Missing non-critical tag | 26-40 | Security Review | 24h |
| Non-standard region | 41-60 | Security Review | 24h |
| Public exposure requested | 61-80 | GRC Review | 5 days |
| Missing encryption | 81-90 | GRC Review | 5 days |
| Critical policy violation | 91-100 | GRC Review + CISO Escalation | 5 days |

---

### 3. Policy Engine (OPA/Rego)

**Technology:** Open Policy Agent with Rego policies

#### 3.1 Gold Templates

Define blessed configurations for common resource types.

**Data Model:**
```go
type GoldTemplate struct {
    ID              string                 `json:"id"`
    Name            string                 `json:"name"`
    Description     string                 `json:"description"`
    CloudProvider   string                 `json:"cloud_provider"`
    ResourceType    string                 `json:"resource_type"`    // google_compute_instance
    Version         string                 `json:"version"`
    
    // Blessed configuration
    RequiredTags    map[string]string      `json:"required_tags"`
    AllowedImages   []string               `json:"allowed_images"`
    AllowedRegions  []string               `json:"allowed_regions"`
    AllowedSizes    []string               `json:"allowed_sizes"`
    RequiredConfigs map[string]interface{} `json:"required_configs"`
    
    // Policy linkage
    OPAPolicyPath   string                 `json:"opa_policy_path"`
    
    // Exceptions
    Exceptions      []ExceptionRule        `json:"exceptions"`
    
    // Metadata
    Owner           string                 `json:"owner"`
    ApprovedBy      string                 `json:"approved_by"`
    CreatedAt       time.Time              `json:"created_at"`
    UpdatedAt       time.Time              `json:"updated_at"`
}

type ExceptionRule struct {
    ID               string    `json:"id"`
    Condition        string    `json:"condition"`          // "env == 'sandbox'"
    AllowedDeviation string    `json:"allowed_deviation"`
    Reason           string    `json:"reason"`
    ApprovedBy       string    `json:"approved_by"`
    ExpiresAt        time.Time `json:"expires_at"`
}
```

**Example Gold Template:**
```yaml
# gold-templates/gcp-linux-vm.yaml
id: gcp-linux-vm-standard
name: "GCP Linux VM - Standard"
description: "Approved configuration for general-purpose Linux VMs in GCP"
cloud_provider: gcp
resource_type: google_compute_instance
version: "1.2.0"

required_tags:
  owner: "*"           # Must be set, any value
  cost_center: "*"
  env_type: "prod|staging|dev|sandbox"
  data_classification: "public|internal|confidential|pii|pci"

allowed_images:
  - "projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts"
  - "projects/rhel-cloud/global/images/family/rhel-9"
  - "projects/cos-cloud/global/images/family/cos-stable"

allowed_regions:
  - "us-west1"
  - "us-central1"
  - "us-east1"

allowed_sizes:
  - "e2-micro"
  - "e2-small"
  - "e2-medium"
  - "n2-standard-2"
  - "n2-standard-4"
  - "n2-standard-8"

required_configs:
  boot_disk:
    auto_delete: true
    encryption: "CMEK"    # Customer-managed encryption key
  network_interface:
    access_config: null   # No public IP by default
  shielded_instance_config:
    enable_secure_boot: true
    enable_vtpm: true
    enable_integrity_monitoring: true
  service_account:
    scopes: ["cloud-platform"]
    
exceptions:
  - id: "sandbox-public-ip"
    condition: "env_type == 'sandbox'"
    allowed_deviation: "network_interface.access_config may be set"
    reason: "Sandbox environments may have public IPs for testing"
    approved_by: "security-team"
    expires_at: "2026-12-31T23:59:59Z"
```

**Corresponding Rego Policy:**
```rego
# policies/gcp/compute_instance.rego
package cloudforge.gcp.compute_instance

import future.keywords.in

default allow = false

allow {
    input.resource_type == "google_compute_instance"
    valid_image
    valid_region
    valid_size
    required_tags_present
    secure_boot_enabled
    no_public_ip
}

allow {
    input.resource_type == "google_compute_instance"
    sandbox_exception
}

valid_image {
    some image in data.gold_templates["gcp-linux-vm-standard"].allowed_images
    startswith(input.config.boot_disk.initialize_params.image, image)
}

valid_region {
    input.config.zone in data.gold_templates["gcp-linux-vm-standard"].allowed_regions
}

valid_size {
    input.config.machine_type in data.gold_templates["gcp-linux-vm-standard"].allowed_sizes
}

required_tags_present {
    input.config.labels.owner
    input.config.labels.cost_center
    input.config.labels.env_type
    input.config.labels.data_classification
}

secure_boot_enabled {
    input.config.shielded_instance_config.enable_secure_boot == true
    input.config.shielded_instance_config.enable_vtpm == true
}

no_public_ip {
    not input.config.network_interface[_].access_config
}

sandbox_exception {
    input.config.labels.env_type == "sandbox"
    valid_image
    valid_region
    valid_size
    required_tags_present
    secure_boot_enabled
    # Public IP allowed in sandbox
}

# Violation messages for UI
violations[msg] {
    not valid_image
    msg := sprintf("Image '%v' is not in the approved list", [input.config.boot_disk.initialize_params.image])
}

violations[msg] {
    not valid_region
    msg := sprintf("Region '%v' is not approved for this template", [input.config.zone])
}

violations[msg] {
    not no_public_ip
    input.config.labels.env_type != "sandbox"
    msg := "Public IP addresses are not allowed outside sandbox environments"
}
```

#### 3.2 Drift Detection

Compares running resources against gold templates to identify configuration drift.

**Flow:**
```
Scheduled Job (hourly)
        │
        ▼
Query Cloud APIs for Current State
        │
        ▼
Compare Against Gold Templates
        │
        ├── Compliant ──► Log + Dashboard Update
        │
        └── Drift Detected ──► Create Finding ──► AI Risk Scoring ──► Asana Task
```

---

### 4. Provisioning Service

**Technology:** Go 1.22+ with Temporal workflows

#### 4.1 Request Queue

```go
type ProvisioningWorkflow struct {
    RequestID   string
    Request     ProvisioningRequest
    State       WorkflowState
    Activities  []ActivityResult
}

// Temporal workflow definition
func ProvisioningWorkflow(ctx workflow.Context, req ProvisioningRequest) error {
    // Step 1: Validate against policy
    var policyResult PolicyCheckResult
    err := workflow.ExecuteActivity(ctx, ValidatePolicy, req).Get(ctx, &policyResult)
    
    // Step 2: Triage if deviations exist
    if len(policyResult.Deviations) > 0 {
        var triageResult TriageResult
        err = workflow.ExecuteActivity(ctx, TriageRequest, req, policyResult).Get(ctx, &triageResult)
        
        // Step 3: Wait for approval if needed
        if triageResult.Route != "auto_approve" {
            approved := workflow.AwaitWithTimeout(ctx, triageResult.SLA, ApprovalSignal)
            if !approved {
                return workflow.ExecuteActivity(ctx, NotifyDenied, req).Get(ctx, nil)
            }
        }
    }
    
    // Step 4: Execute Terraform
    var tfResult TerraformResult
    err = workflow.ExecuteActivity(ctx, ApplyTerraform, req).Get(ctx, &tfResult)
    
    // Step 5: Post-provisioning validation
    err = workflow.ExecuteActivity(ctx, ValidateProvisioned, tfResult).Get(ctx, nil)
    
    // Step 6: Notify requester
    return workflow.ExecuteActivity(ctx, NotifyComplete, req, tfResult).Get(ctx, nil)
}
```

#### 4.2 Terraform Execution

- Terraform state stored in cloud-native backends (S3/Blob/GCS)
- Plan output reviewed by service before apply
- Drift detection compares state vs. actual
- Destroy workflows require additional approval

---

### 5. Enterprise Integrations

#### 5.1 GRC Integration (ServiceNow / RSA Archer)

```go
type GRCProvider interface {
    CreateRiskAcceptance(ctx context.Context, req RiskAcceptanceRequest) (*RiskAcceptance, error)
    GetApprovalStatus(ctx context.Context, id string) (*ApprovalStatus, error)
    SyncFindings(ctx context.Context, findings []Finding) error
    CreateException(ctx context.Context, req ExceptionRequest) (*Exception, error)
}

// Implementations: ServiceNowGRCProvider, ArcherGRCProvider
```

#### 5.2 Asana Integration

Syncs findings and remediation tasks to Asana for tracking.

```go
type AsanaProvider interface {
    CreateTask(ctx context.Context, task AsanaTask) (*AsanaTask, error)
    UpdateTask(ctx context.Context, taskID string, updates AsanaTaskUpdate) error
    GetTask(ctx context.Context, taskID string) (*AsanaTask, error)
    SyncFinding(ctx context.Context, finding Finding) error
}
```

#### 5.3 Microsoft Graph Integration

Email notifications for approvals, findings, and status updates.

```go
type EmailProvider interface {
    SendEmail(ctx context.Context, email Email) error
    SendTemplatedEmail(ctx context.Context, template string, data interface{}, recipients []string) error
}
```

---

## Hosting Architecture

### Primary: Azure Kubernetes Service (AKS)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AZURE SUBSCRIPTION                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    AKS CLUSTER                              │   │
│  │                                                             │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │   │
│  │  │  System     │  │  App        │  │  AI         │        │   │
│  │  │  Node Pool  │  │  Node Pool  │  │  Node Pool  │        │   │
│  │  │  (3 nodes)  │  │  (3-10 HPA) │  │  (GPU opt)  │        │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │   │
│  │                                                             │   │
│  │  Namespaces:                                               │   │
│  │  ├── cloudforge-system (Temporal, OPA, Ingress)            │   │
│  │  ├── cloudforge-app (API, Portal, Services)                │   │
│  │  └── cloudforge-ai (AI Intelligence Service)               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│         ┌────────────────────┼────────────────────┐                │
│         ▼                    ▼                    ▼                │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐        │
│  │  Azure      │      │  Azure      │      │  Azure      │        │
│  │  PostgreSQL │      │  Redis      │      │  Blob       │        │
│  │  Flexible   │      │  Enterprise │      │  Storage    │        │
│  └─────────────┘      └─────────────┘      └─────────────┘        │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Azure Front Door (WAF + CDN + Global Load Balancing)       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Azure Key Vault (Secrets, Certificates)                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Azure Monitor + Log Analytics (Observability)              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

Cross-Cloud Identity Federation:
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  Azure AD (Primary IdP)                                             │
│       │                                                             │
│       ├──► AWS IAM (OIDC Federation) ──► Security Hub, S3, etc.    │
│       │                                                             │
│       └──► GCP Workload Identity ──► SCC, GCS, etc.                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Kubernetes Resources

```yaml
# k8s/base/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cloudforge-app
  labels:
    app.kubernetes.io/name: cloudforge
    pod-security.kubernetes.io/enforce: restricted

---
# k8s/base/deployment-api.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudforge-api
  namespace: cloudforge-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cloudforge-api
  template:
    metadata:
      labels:
        app: cloudforge-api
    spec:
      serviceAccountName: cloudforge-api
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: api
          image: cloudforge/api:latest
          ports:
            - containerPort: 8080
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: cloudforge-secrets
                  key: database-url
            - name: AZURE_CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: cloudforge-secrets
                  key: azure-client-id
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "1000m"
              memory: "1Gi"
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL

---
# k8s/base/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: cloudforge-api-hpa
  namespace: cloudforge-app
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: cloudforge-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### Infrastructure as Code (Terraform)

```hcl
# infra/azure/main.tf
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "cloudforge-tfstate"
    storage_account_name = "cloudforgetfstate"
    container_name       = "tfstate"
    key                  = "cloudforge.tfstate"
  }
}

provider "azurerm" {
  features {}
  use_oidc = true  # Workload Identity
}

module "aks" {
  source              = "./modules/aks"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  cluster_name        = "cloudforge-aks"
  
  default_node_pool = {
    name       = "system"
    node_count = 3
    vm_size    = "Standard_D4s_v5"
  }
  
  additional_node_pools = [
    {
      name       = "app"
      node_count = 3
      vm_size    = "Standard_D4s_v5"
      auto_scaling = {
        min = 3
        max = 10
      }
    },
    {
      name       = "ai"
      node_count = 1
      vm_size    = "Standard_NC6s_v3"  # GPU for local inference (optional)
      taints     = ["workload=ai:NoSchedule"]
    }
  ]
  
  workload_identity_enabled = true
  oidc_issuer_enabled       = true
}

module "postgresql" {
  source              = "./modules/postgresql"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  server_name         = "cloudforge-db"
  sku_name            = "GP_Standard_D4s_v3"
  
  high_availability = {
    mode = "ZoneRedundant"
  }
}

module "redis" {
  source              = "./modules/redis"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  name                = "cloudforge-redis"
  sku                 = "Premium"
  capacity            = 1
}

module "keyvault" {
  source              = "./modules/keyvault"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  name                = "cloudforge-kv"
  
  workload_identities = [
    module.aks.kubelet_identity_object_id
  ]
}
```

---

## Project Structure

```
cloudforge/
├── cmd/
│   ├── api/main.go                    # API server entrypoint
│   ├── worker/main.go                 # Temporal worker entrypoint
│   └── cli/main.go                    # CLI tool entrypoint
├── internal/
│   ├── config/
│   │   └── config.go                  # Configuration management
│   ├── api/
│   │   ├── router.go                  # HTTP router
│   │   ├── middleware/                # Auth, logging, rate limiting
│   │   └── handlers/
│   │       ├── provisioning.go
│   │       ├── findings.go
│   │       ├── templates.go
│   │       └── runbooks.go
│   ├── domain/
│   │   ├── finding.go                 # Finding domain model
│   │   ├── template.go                # Gold template model
│   │   ├── request.go                 # Provisioning request model
│   │   └── runbook.go                 # Remediation runbook model
│   ├── ai/
│   │   ├── provider.go                # LLM provider interface
│   │   ├── anthropic/                 # Claude implementation
│   │   ├── openai/                    # OpenAI implementation
│   │   ├── bedrock/                   # AWS Bedrock implementation
│   │   ├── risk_scorer.go             # Contextual risk scoring
│   │   ├── explainer.go               # Finding explainer
│   │   ├── runbook_generator.go       # Remediation generation
│   │   └── triage.go                  # OOB request triage
│   ├── policy/
│   │   ├── opa.go                     # OPA client
│   │   ├── evaluator.go               # Policy evaluation
│   │   └── drift.go                   # Drift detection
│   ├── cloud/
│   │   ├── provider.go                # Cloud provider interface
│   │   ├── aws/                       # AWS implementation
│   │   ├── azure/                     # Azure implementation
│   │   └── gcp/                       # GCP implementation
│   ├── grc/
│   │   ├── provider.go                # GRC provider interface
│   │   ├── servicenow/                # ServiceNow implementation
│   │   └── archer/                    # RSA Archer implementation
│   ├── integrations/
│   │   ├── asana/                     # Asana client
│   │   └── msgraph/                   # Microsoft Graph client
│   ├── workflows/
│   │   ├── provisioning.go            # Provisioning workflow
│   │   ├── remediation.go             # Remediation workflow
│   │   └── drift_detection.go         # Drift detection workflow
│   └── storage/
│       ├── postgres/                  # PostgreSQL repositories
│       └── redis/                     # Redis cache
├── pkg/
│   └── oidc/                          # Cross-cloud OIDC utilities
├── policies/
│   ├── aws/                           # AWS Rego policies
│   ├── azure/                         # Azure Rego policies
│   └── gcp/                           # GCP Rego policies
├── gold-templates/
│   ├── aws/                           # AWS gold templates
│   ├── azure/                         # Azure gold templates
│   └── gcp/                           # GCP gold templates
├── web/                               # React frontend (Next.js)
│   ├── src/
│   │   ├── app/                       # Next.js app router
│   │   ├── components/                # React components
│   │   └── lib/                       # Utilities
│   └── package.json
├── infra/
│   ├── azure/                         # Azure Terraform
│   ├── aws/                           # AWS Terraform (for cross-cloud)
│   └── gcp/                           # GCP Terraform (for cross-cloud)
├── k8s/
│   ├── base/                          # Base Kubernetes manifests
│   └── overlays/                      # Environment-specific overlays
│       ├── dev/
│       ├── staging/
│       └── prod/
├── docs/
│   ├── HLD.md                         # This document
│   ├── api.md                         # API documentation
│   └── adr/                           # Architecture Decision Records
├── configs/
│   └── config.example.yaml            # Example configuration
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── README.md
```

---

## Security Considerations

### Authentication & Authorization

| Layer | Mechanism |
|-------|-----------|
| User → Portal | Azure AD OIDC / Okta |
| Portal → API | JWT Bearer Token (short-lived) |
| API → Cloud Providers | Workload Identity (no stored credentials) |
| Service → Service | mTLS via service mesh (Istio/Linkerd) |

### Secrets Management

- All secrets in Azure Key Vault
- Kubernetes secrets synced via External Secrets Operator
- No secrets in environment variables or config files
- Rotation policy: 90 days for service accounts

### Network Security

- Private AKS cluster (no public API server)
- Azure Private Link for PaaS services
- Network policies restricting pod-to-pod traffic
- WAF rules on Azure Front Door

### Data Protection

- Encryption at rest (Azure-managed keys, CMEK optional)
- TLS 1.3 for all traffic
- PII/PCI data tagged and isolated
- Audit logging for all data access

---

## API Specification

### Provisioning Endpoints

```
POST   /api/v1/requests              # Create provisioning request
GET    /api/v1/requests              # List requests (paginated)
GET    /api/v1/requests/{id}         # Get request details
POST   /api/v1/requests/{id}/approve # Approve request
POST   /api/v1/requests/{id}/deny    # Deny request
DELETE /api/v1/requests/{id}         # Cancel request
```

### Findings Endpoints

```
GET    /api/v1/findings              # List findings (paginated, filtered)
GET    /api/v1/findings/{id}         # Get finding details + risk assessment
POST   /api/v1/findings/{id}/accept  # Accept risk
POST   /api/v1/findings/{id}/remediate # Trigger remediation workflow
GET    /api/v1/findings/{id}/explain # Get AI explanation
GET    /api/v1/findings/{id}/runbook # Get remediation runbook
```

### Templates Endpoints

```
GET    /api/v1/templates             # List gold templates
GET    /api/v1/templates/{id}        # Get template details
POST   /api/v1/templates             # Create template (admin)
PUT    /api/v1/templates/{id}        # Update template (admin)
DELETE /api/v1/templates/{id}        # Delete template (admin)
POST   /api/v1/templates/{id}/validate # Validate resource against template
```

### Runbooks Endpoints

```
GET    /api/v1/runbooks              # List runbooks
GET    /api/v1/runbooks/{id}         # Get runbook details
POST   /api/v1/runbooks              # Create runbook (manual)
POST   /api/v1/runbooks/generate     # Generate runbook (AI)
PUT    /api/v1/runbooks/{id}         # Update runbook
POST   /api/v1/runbooks/{id}/approve # Approve AI-generated runbook
```

---

## Roadmap

### Phase 1: Foundation (Current)
- [x] Project structure and Go scaffolding
- [ ] OPA/Rego policy engine integration
- [ ] Gold template CRUD and validation
- [ ] Basic provisioning workflow (Temporal)
- [ ] PostgreSQL + Redis setup

### Phase 2: AI Intelligence
- [ ] LLM provider abstraction (Anthropic, OpenAI, Bedrock)
- [ ] Contextual risk scoring
- [ ] Finding explainer
- [ ] AI remediation runbook generation
- [ ] OOB provisioning triage

### Phase 3: Self-Service Portal
- [ ] React/Next.js frontend
- [ ] Provisioning catalog UI
- [ ] Request tracker
- [ ] Finding dashboard with risk visualization
- [ ] Runbook library browser

### Phase 4: Enterprise Integrations
- [ ] ServiceNow GRC integration
- [ ] RSA Archer integration
- [ ] Asana task sync
- [ ] Microsoft Graph email notifications
- [ ] Cross-cloud identity federation

### Phase 5: Advanced Features
- [ ] Drift detection and auto-remediation
- [ ] Multi-tenant support
- [ ] Custom policy authoring UI
- [ ] Compliance reporting (SOC2, ISO, HIPAA)
- [ ] Cost allocation and chargeback

---

## Interview STAR Stories

### Story 1: Platform-Scale Security Governance

**Situation:** Organization managing 270+ cloud environments across AWS, Azure, and GCP needed centralized security governance without creating bottlenecks for developer teams.

**Task:** Design and build an Internal Developer Platform that enforces security policies at provisioning time while enabling developer self-service.

**Action:**
- Architected policy-as-code framework using OPA/Rego with gold templates
- Implemented AI-powered contextual risk scoring to reduce alert fatigue
- Built self-service portal with intelligent GRC routing for exceptions
- Designed cross-cloud identity federation eliminating stored credentials

**Result:**
- Reduced provisioning approval time from 5 days to < 4 hours for compliant requests
- Achieved 96% finding closure rate through automated Asana integration
- Zero credential exposure incidents through workload identity adoption
- Platform adopted across all business units with 95% developer satisfaction

### Story 2: AI-Enhanced Security Operations

**Situation:** Security team overwhelmed with 1,600+ findings per quarter, many lacking business context for prioritization.

**Task:** Implement intelligent triage that contextualizes raw severity with business risk factors.

**Action:**
- Built AI service that enriches findings with asset tier, network exposure, compensating controls
- Implemented contextual risk scoring reducing CRITICAL→LOW when justified
- Created finding explainer generating developer-friendly remediation guidance
- Developed runbook generation with human-in-the-loop approval

**Result:**
- Reduced actionable findings by 40% through intelligent false positive detection
- Average remediation time decreased from 14 days to 3 days
- Developer satisfaction with security guidance increased 60%
- Security team able to focus on high-impact issues vs. noise

---

## Contact

**Author:** Liem Vo-Nguyen  
**Email:** liem@vonguyen.io  
**LinkedIn:** linkedin.com/in/liemvn  
**GitHub:** github.com/lvonguyen/cloudforge
