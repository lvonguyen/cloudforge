# Detailed Design Document: CloudForge Enterprise Cloud Governance Platform

---

## Document Control

| Property | Value |
|----------|-------|
| Document ID | CF-DDD-001 |
| Version | 2.0 |
| Status | Draft |
| Classification | Internal |
| Created | January 5, 2026 |
| Last Updated | February 27, 2026 |

### Author

| Name | Role | Email |
|------|------|-------|
| Liem Vo-Nguyen | Security Architect | liem@vonguyen.io |

### Approvers

| Name | Role | Signature | Date |
|------|------|-----------|------|
| [Technical Lead] | Engineering Lead | _____________ | ______ |
| [Security Lead] | Security Director | _____________ | ______ |
| [Architecture Lead] | Principal Architect | _____________ | ______ |

### Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | Jan 2, 2026 | L. Vo-Nguyen | Initial draft |
| 0.2 | Jan 3, 2026 | L. Vo-Nguyen | Added compliance module design |
| 1.0 | Jan 5, 2026 | L. Vo-Nguyen | First release |
| 1.1 | Feb 14, 2026 | L. Vo-Nguyen | Added Section 3.4 Remediation Dispatcher |
| 1.2 | Feb 20, 2026 | L. Vo-Nguyen | Added Section 3.5 AI Governance Module (merged from AgentGuard) |
| 1.3 | Feb 25, 2026 | L. Vo-Nguyen | Added Section 3.6 IaC Deploy Layer |
| 2.0 | Feb 27, 2026 | L. Vo-Nguyen | Added Section 3.7 Risk Intelligence (Planned); SLA updates; version bump |

### Related Documents

| Document | Link |
|----------|------|
| High-Level Design | [HLD.md](./HLD.md) |
| Component Rationale | [component-rationale.md](./component-rationale.md) |
| DR/BC Plan | [../DR-BC.md](../DR-BC.md) |
| API Specification | [../api/openapi.yaml](../api/openapi.yaml) |

---

## 1. Introduction

### 1.1 Purpose

This Detailed Design Document (DDD) provides comprehensive technical specifications for implementing the CloudForge Enterprise Cloud Governance Platform. It supplements the High-Level Design (HLD) with implementation-level details.

### 1.2 Scope

This document covers:
- Detailed component specifications
- Data models and schemas
- API contracts
- Integration patterns
- Security implementation details
- Performance requirements

### 1.3 Audience

- Development Engineers
- DevOps/SRE Engineers
- Security Engineers
- QA Engineers

---

## 2. System Context

### 2.1 External Integrations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CloudForge                                      │
└─────────────────────────────────────────────────────────────────────────────┘
         │              │              │              │              │
         ▼              ▼              ▼              ▼              ▼
    ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
    │   VCS   │   │  SAST   │   │   IdP   │   │   GRC   │   │  Cloud  │
    │ GitHub  │   │ Sonar   │   │ Entra   │   │ SNOW    │   │  AWS    │
    │ GitLab  │   │ Veracode│   │ Okta    │   │ Archer  │   │ Azure   │
    │ ADO     │   │ Checkov │   │         │   │         │   │ GCP     │
    └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘
```

### 2.2 Integration Authentication

| System | Auth Method | Credential Storage |
|--------|-------------|-------------------|
| GitHub | OAuth App / PAT | AWS Secrets Manager |
| GitLab | Personal Access Token | AWS Secrets Manager |
| Azure DevOps | PAT / Service Principal | Azure Key Vault |
| SonarQube | API Token | AWS Secrets Manager |
| Veracode | HMAC API Credentials | AWS Secrets Manager |
| Entra ID | OIDC / Client Credentials | Azure Key Vault |
| Okta | API Token / OAuth | AWS Secrets Manager |
| ServiceNow | Basic Auth / OAuth | AWS Secrets Manager |
| Archer | Session Token | AWS Secrets Manager |
| AWS | OIDC Federation (WIF) | None (IAM Roles) |
| Azure | Workload Identity | None (Managed Identity) |
| GCP | Workload Identity | None (Service Account) |

---

## 3. Component Detailed Design

### 3.1 Compliance Framework Engine

#### 3.1.1 Package Structure

```
internal/compliance/
├── framework.go           # Framework manager and core types
├── finding.go             # Finding schema and methods
├── deduplication.go       # Deduplication logic
├── ai_analyzer.go         # AI-powered analysis
├── frameworks_builtin.go  # CIS, NIST, ISO, PCI-DSS
├── frameworks_sector.go   # HIPAA, SOX, GLBA, FFIEC
├── frameworks_gov_extended.go  # CMMC, ITAR, DFARS
├── frameworks_automotive.go    # ISO 21434, UN ECE R155, TISAX
└── mapper.go              # Finding-to-control mapping
```

#### 3.1.2 Finding Data Model

```go
type Finding struct {
    // Core Identification
    ID                string          `json:"id"`
    Source            string          `json:"source"`
    SourceFindingID   string          `json:"source_finding_id"`
    Type              FindingType     `json:"type"`
    Category          FindingCategory `json:"category"`
    
    // Resource Information
    ResourceType      ResourceType    `json:"resource_type"`
    ResourceID        string          `json:"resource_id"`
    ResourceName      string          `json:"resource_name"`
    
    // Platform & Environment
    Platform          Platform        `json:"platform"`
    CloudProvider     CloudProvider   `json:"cloud_provider"`
    EnvironmentType   EnvironmentType `json:"environment_type"`
    
    // Severity & Risk
    StaticSeverity    string          `json:"static_severity"`
    AIRiskScore       float64         `json:"ai_risk_score"`
    AIRiskLevel       string          `json:"ai_risk_level"`
    
    // Workflow
    WorkflowStatus    WorkflowStatus  `json:"workflow_status"`
    Assignee          *AssigneeInfo   `json:"assignee,omitempty"`
    
    // Compliance
    ComplianceMappings []ComplianceMapping `json:"compliance_mappings"`
}
```

#### 3.1.3 Deduplication Algorithm

```
Input: New Finding F, Existing Findings []E

1. Generate DeduplicationKey for F:
   Key = SHA256(ResourceType + ResourceID + CanonicalRuleID + Title + CVEs)

2. Check for exact duplicates:
   FOR each E in existing:
     IF E.DeduplicationKey == F.DeduplicationKey:
       RETURN (F, isDuplicate=true)

3. Check for equivalent rules:
   FOR each E in existing:
     IF E.ResourceID == F.ResourceID:
       IF areRulesEquivalent(E.SourceFindingID, F.SourceFindingID):
         IF shouldReplaceExisting(F, E):
           MARK E for removal
           RETURN (F, isDuplicate=false)
         ELSE:
           F.DuplicateOf = E.ID
           RETURN (F, isDuplicate=true)

4. RETURN (F, isDuplicate=false)
```

#### 3.1.4 Rule Equivalence Mappings

| Canonical Rule | Equivalent Rules |
|----------------|------------------|
| s3-bucket-public-access | S3.1, S3.2, S3.3, CKV_AWS_19, CKV_AWS_20, CKV_AWS_21 |
| ec2-security-group-open | EC2.19, EC2.2, CKV_AWS_23, CKV_AWS_24, CKV_AWS_25 |
| iam-root-access-key | IAM.4, CKV_AWS_41 |
| encryption-at-rest | S3.4, RDS.3, EBS.1, CKV_AWS_3, CKV_AWS_16 |

### 3.2 CI/CD Security Module

#### 3.2.1 Package Structure

```
internal/cicd/
├── scanner.go              # Pipeline scanner
├── dependency_scanner.go   # Dependency analysis
├── vcs/
│   ├── provider.go         # VCS interface
│   ├── github.go           # GitHub/GH Enterprise
│   ├── gitlab.go           # GitLab
│   └── azure_devops.go     # Azure DevOps
└── sast/
    ├── provider.go         # SAST interface
    ├── sonarqube.go        # SonarQube/SonarCloud
    ├── checkov.go          # Checkov IaC scanning
    └── veracode.go         # Veracode SAST/DAST
```

#### 3.2.2 VCS Provider Interface

```go
type Provider interface {
    Name() string
    GetRepositories(ctx context.Context) ([]*Repository, error)
    GetPullRequests(ctx context.Context, owner, repo, state string) ([]*PullRequest, error)
    GetPipelines(ctx context.Context, owner, repo string) ([]*Pipeline, error)
    GetSecurityAlerts(ctx context.Context, owner, repo string) ([]*SecurityAlert, error)
    CreateCheckRun(ctx context.Context, owner, repo, sha string, check *CheckRun) error
}
```

#### 3.2.3 SAST Provider Interface

```go
type Provider interface {
    Name() string
    Type() string  // sast, dast, sca, iac
    Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error)
    GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error)
    GetFindings(ctx context.Context, scanID string) ([]*Finding, error)
}
```

### 3.3 Identity & Zero Trust Module

#### 3.3.1 Package Structure

```
internal/identity/
├── provider.go       # Identity provider interface
├── entra_id.go       # Microsoft Entra ID
├── okta.go           # Okta
└── zero_trust.go     # Zero Trust policy engine
```

#### 3.3.2 Zero Trust Policy Evaluation

```go
type PolicyDecision struct {
    Allow           bool
    RequireMFA      bool
    RequireDevice   bool
    SessionDuration time.Duration
    RiskScore       float64
    Reason          string
}

func (z *ZeroTrustEnforcer) EnforcePolicy(ctx context.Context, req AccessRequest) (*PolicyDecision, error) {
    // 1. Evaluate user risk
    userRisk := z.evaluateUserRisk(req.User)
    
    // 2. Evaluate device compliance
    deviceCompliance := z.evaluateDeviceCompliance(req.Device)
    
    // 3. Evaluate resource sensitivity
    resourceSensitivity := z.evaluateResourceSensitivity(req.Resource)
    
    // 4. Apply policies
    for _, policy := range z.policies {
        if policy.Matches(req) {
            return policy.Evaluate(userRisk, deviceCompliance, resourceSensitivity)
        }
    }
    
    // 5. Default deny
    return &PolicyDecision{Allow: false, Reason: "No matching policy"}
}
```

### 3.4 Remediation Dispatcher

#### 3.4.1 Package Structure

```
pkg/remediation/
├── executor.go         # Batch executor, semaphore, dry-run routing
├── types.go            # Remediator interface, result types, RollbackState

internal/remediation/
├── network/
│   └── block_ssh.go    # BlockPublicSSHRemediator (Tier 1, AWS/GCP/Azure)
├── compute/            # (planned) EBS encryption, IMDSv2, public AMI handlers
├── identity/           # (planned) IAM root key, stale access key handlers
└── storage/            # (planned) S3 public access, versioning handlers

internal/findings/
└── finding.go          # PrioritizedFinding bridge type consumed by all handlers
```

#### 3.4.2 Remediator Interface

All remediation handlers implement the `Remediator` interface defined in
`pkg/remediation/types.go`. The interface enforces a four-method contract
covering execution, validation, tier classification, and simulation:

```go
// Remediator is the interface that all remediation handlers must implement.
type Remediator interface {
    // Remediate executes the remediation action for the given finding.
    Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*RemediationResult, error)

    // Validate verifies that the remediation was successful.
    Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*ValidationResult, error)

    // Tier returns the complexity tier (1-3) for this remediation.
    // Tier 1: Auto-safe, no approval needed (DEV/STG)
    // Tier 2: Requires verification before PROD
    // Tier 3: Requires change window
    Tier() int

    // DryRun simulates the remediation without making changes.
    DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*DryRunResult, error)
}
```

#### 3.4.3 Finding Bridge Type

The `internal/findings` package defines the primary type consumed by all
handlers. It mirrors the cspm-aggregator's scoring package schema for JSON
compatibility and will be removed once the aggregator is merged:

```go
// PrioritizedFinding contains the full assessment for a finding.
// This is the primary type consumed by remediation handlers.
type PrioritizedFinding struct {
    Finding              *Finding              `json:"finding"`
    RiskAssessment       *RiskAssessment       `json:"risk_assessment,omitempty"`
    ComplexityAssessment *ComplexityAssessment `json:"complexity_assessment,omitempty"`
    Priority             string                `json:"priority"`
    PriorityScore        int                   `json:"priority_score"`
    AutoRemediationReady bool                  `json:"auto_remediation_ready"`
    RecommendedAction    string                `json:"recommended_action"`
    AssignedQueue        string                `json:"assigned_queue"`
    RequiresApproval     bool                  `json:"requires_approval"`
    AssessedAt           time.Time             `json:"assessed_at"`
}
```

The `Finding.Context` struct carries business context — asset tier, environment
type, data classification, internet-facing flag, and compliance scopes — that
is used by handlers for bastion-host heuristics and tier gate decisions.

#### 3.4.4 Tiered Execution Model

Remediation actions are classified into three tiers that gate execution
authority:

| Tier | Name | Auto-Execute | Approval Required | Scope |
|------|------|-------------|-------------------|-------|
| T1 | Auto-safe | Yes | None | Always runs; changes are always safe (e.g., block public SSH on non-bastion) |
| T2 | Requires verification | Only if `AutoRemediationReady=true` | Pre-PROD review | Moderate blast radius; validated before applying to production |
| T3 | Change window | No | Full change approval | High blast radius; requires scheduled change window |

The executor enforces this gate at the `Execute` method level:

```go
// Tier 1 = auto-safe (always runs). Tier 2+ require AutoRemediationReady [SEC-006]
if !finding.AutoRemediationReady && handler.Tier() > 1 {
    return &RemediationResult{
        FindingID: finding.Finding.ID,
        Success:   false,
        Message:   fmt.Sprintf("Auto-remediation not approved for tier %d finding", handler.Tier()),
    }, nil
}
```

#### 3.4.5 Executor Flow

The `Executor` dispatches findings to registered handlers by `FindingType` key.
The execution sequence is:

```
PrioritizedFinding
       |
       v
[Nil guard + field validation]  -- SEC-001: prevents nil pointer panics
       |
       v
[Handler lookup by FindingType]
       |
       v
[Tier gate check]  -- T2/T3 require AutoRemediationReady=true
       |
       v
[Dry-run branch?]
   Yes --> handler.DryRun()  --> RemediationResult{Message: "DRY-RUN: ..."}
   No  --> handler.Remediate()
              |
              v
         handler.Validate()
              |
         IsCompliant?
          Yes --> result.Success = true
          No  --> result.Success = false (remediation applied but validation failed)
```

The full `Execute` method applies the sequence including post-remediation
validation:

```go
// Execute processes a finding and routes it to the appropriate handler.
func (e *Executor) Execute(ctx context.Context, finding *findings.PrioritizedFinding) (*RemediationResult, error) {
    if finding == nil || finding.Finding == nil {
        return nil, fmt.Errorf("finding or finding.Finding is nil")
    }
    if finding.Finding.ID == "" || finding.Finding.FindingType == "" {
        return nil, fmt.Errorf("finding missing required fields: ID=%q, FindingType=%q",
            finding.Finding.ID, finding.Finding.FindingType)
    }

    handler, ok := e.handlers[finding.Finding.FindingType]
    if !ok {
        return nil, fmt.Errorf("no handler registered for finding type: %s", finding.Finding.FindingType)
    }

    if !finding.AutoRemediationReady && handler.Tier() > 1 {
        return &RemediationResult{
            FindingID: finding.Finding.ID,
            Success:   false,
            Message:   fmt.Sprintf("Auto-remediation not approved for tier %d finding", handler.Tier()),
        }, nil
    }

    if e.dryRun {
        dryRunResult, err := handler.DryRun(ctx, finding)
        // ...
    }

    result, err := handler.Remediate(ctx, finding)
    // ...
    validation, err := handler.Validate(ctx, finding)
    // ...
}
```

#### 3.4.6 Batch Processing with Semaphore

`ExecuteBatch` processes multiple findings concurrently up to a configurable
`maxConcurrency` limit. Results are guaranteed to be returned in input order
regardless of goroutine completion order. Context cancellation is handled
gracefully — remaining items are marked as cancelled rather than deadlocked:

```go
// ExecuteBatch processes multiple findings concurrently (up to maxConcurrency).
// Results are returned in the same order as the input batch [SEC-002].
func (e *Executor) ExecuteBatch(ctx context.Context, batch []*findings.PrioritizedFinding, maxConcurrency int) ([]*RemediationResult, error) {
    if maxConcurrency <= 0 {
        maxConcurrency = 5
    }

    results := make([]*RemediationResult, len(batch))   // pre-allocated at fixed indices
    sem := make(chan struct{}, maxConcurrency)

    type resultPair struct {
        result *RemediationResult
        err    error
        index  int
    }

    resultChan := make(chan resultPair, len(batch))

    for i := range batch {
        select {
        case sem <- struct{}{}:
        case <-ctx.Done():
            // Mark remaining as cancelled; do not block
        }
        go func(idx int, f *findings.PrioritizedFinding) {
            defer func() { <-sem }()
            result, err := e.Execute(ctx, f)
            resultChan <- resultPair{result: result, err: err, index: idx}
        }(i, batch[i])
    }
    // Drain resultChan and place each result at its original index
    // ...
}
```

Key properties of the batch executor:
- Default concurrency: 5 (configurable via `maxConcurrency`)
- Context-aware semaphore acquisition prevents goroutine leaks on cancellation
- Index-preserving results enable deterministic audit log ordering

#### 3.4.7 Handler Registration

Handlers are registered against the `FindingType` string key used in the
finding's `FindingType` field. Multiple CSP variants can map to the same
handler:

```go
executor := remediation.NewExecutor(false) // false = live mode

sshHandler := network.NewBlockPublicSSHRemediator()
executor.Register("OPEN_SSH_PORT", sshHandler)
executor.Register("AWS.EC2.SecurityGroup.SSH", sshHandler)
executor.Register("GCP.OPEN_SSH_PORT", sshHandler)
```

The `BlockPublicSSHRemediator` dispatches internally by CSP based on
`finding.Finding.Source`:

```go
func (b *BlockPublicSSHRemediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
    switch {
    case strings.Contains(finding.Finding.Source, "aws"):
        return b.remediateAWS(ctx, finding, result)
    case strings.Contains(finding.Finding.Source, "gcp"):
        return b.remediateGCP(ctx, finding, result)
    case strings.Contains(finding.Finding.Source, "azure"):
        return b.remediateAzure(ctx, finding, result)
    }
}
```

The AWS path calls `ec2.RevokeSecurityGroupIngress` to remove the
`0.0.0.0/0:22` ingress rule, then validates via `ec2.DescribeSecurityGroups`
that no public SSH rule remains. The GCP and Azure paths are stubs pending
implementation.

#### 3.4.8 Dry-Run Mode

When `NewExecutor(dryRun: true)` is configured, every handler receives a
`DryRun()` call instead of `Remediate()`. The `DryRunResult` carries:
- `WouldSucceed bool` — whether the handler believes the action would succeed
- `PlannedActions []string` — human-readable list of changes that would be made
- `PrerequisitesMet bool` — whether all preconditions are satisfied
- `EstimatedImpact string` — operator-readable impact statement
- `Warnings []string` — conditions that block or caution against auto-execution

Example: the SSH handler heuristically detects bastion hosts and suppresses
auto-execution:

```go
// Check if this is a bastion security group (heuristic)
if strings.Contains(strings.ToLower(finding.Finding.ResourceID), "bastion") {
    dryRun.Warnings = append(dryRun.Warnings,
        "WARNING: This appears to be a bastion host security group. Public SSH may be intentional.")
    dryRun.WouldSucceed = false
}
```

#### 3.4.9 Rollback Engine

The `RollbackState` type captures pre-remediation resource state with a 48-hour
rollback window enforced at the workflow layer:

```go
// RollbackState captures pre-remediation state needed to reverse an action.
type RollbackState struct {
    FindingID  string                 `json:"finding_id"`
    ResourceID string                 `json:"resource_id"`
    Region     string                 `json:"region"`
    AccountID  string                 `json:"account_id"`
    PreState   map[string]interface{} `json:"pre_state"` // Handler-specific state
    CapturedAt time.Time              `json:"captured_at"`
}
```

`PreState` is handler-specific — for the SSH handler it stores the original
ingress rules; for future key-rotation handlers it stores the prior key ID.
The rollback window expiry check (`CapturedAt.Add(48 * time.Hour).Before(now)`)
is enforced before allowing rollback execution.

`RemediationRecord` provides the full audit trail linking findings, handlers,
results, and Asana task URLs:

```go
type RemediationRecord struct {
    ID           string             `json:"id"`
    FindingID    string             `json:"finding_id"`
    Domain       string             `json:"domain"`    // compute, identity, network, etc.
    Handler      string             `json:"handler"`   // Specific remediator name
    Tier         int                `json:"tier"`
    Status       RemediationStatus  `json:"status"`
    Result       *RemediationResult `json:"result,omitempty"`
    Validation   *ValidationResult  `json:"validation,omitempty"`
    AsanaTaskURL string             `json:"asana_task_url,omitempty"`
    CreatedAt    time.Time          `json:"created_at"`
    UpdatedAt    time.Time          `json:"updated_at"`
}
```

#### 3.4.10 Remediation State Machine

```
                  +----------+
                  |  PENDING  |
                  +----+------+
                       |
          [Execute called by dispatcher]
                       |
                       v
                +-------------+
                | IN_PROGRESS |
                +------+------+
                       |
           +-----------+-----------+
           |                       |
     [handler error]         [handler success]
           |                       |
           v                       v
       +--------+           +----------+
       | FAILED |           | validate |
       +--------+           +----+-----+
                                 |
                  +--------------+-------------+
                  |                            |
           [not compliant]              [compliant]
                  |                            |
                  v                            v
              +--------+               +-----------+
              | FAILED |               | COMPLETED |
              +--------+               +-----------+
                                            |
                                   [within 48h window]
                                            |
                                            v
                                      +----------+
                                      | (rollback |
                                      |  eligible)|
                                      +----------+
```

Valid status values: `pending`, `in_progress`, `completed`, `failed`, `skipped`.

---

### 3.5 AI Governance Module

#### 3.5.1 Package Structure

```
internal/ai-governance/
├── opa/
│   └── engine.go       # In-process OPA engine, policy loading, evaluation
└── models.go           # Agent registry, observability traces, STRIDE+ATLAS
                        # threat models, maturity assessment
```

Migrated selectively from AgentGuard. Compliance framework models
(`Framework`, `Control`, `Crosswalk`, `GapAnalysis`) are not included here
as they already exist in `internal/compliance/`.

#### 3.5.2 Dual-OPA Architecture

CloudForge runs two distinct OPA evaluation paths that are architecturally
complementary:

```
                 CloudForge Platform
                         |
          +--------------+--------------+
          |                             |
          v                             v
   [Cloud Provisioning Path]     [AI Governance Path]
   internal/policy/evaluator.go  internal/ai-governance/opa/engine.go
          |                             |
          v                             v
   HTTP REST to external         In-process (embedded)
   OPA instance                  OPA via Go library
          |                             |
   Package namespace:            Package namespace:
   terraform.*                   cloudforge.ai.*
          |                             |
   Governs:                       Governs:
   - IaC plan evaluation          - Agent tool access
   - Resource compliance          - Data flow controls
   - Infrastructure drift         - Rate limiting
   - Environment isolation        - Prompt injection detection
```

The two paths are independent and non-conflicting: `internal/policy/evaluator.go`
sends plan JSON to an external OPA HTTP endpoint; `internal/ai-governance/opa/engine.go`
embeds the OPA Go library directly and evaluates in-process with sub-millisecond
latency requirements for synchronous agent request gating.

#### 3.5.3 Embedded OPA Engine

The `Engine` type wraps the OPA Go library with a `sync.RWMutex`-protected
query cache, an in-memory data store, and lazy query preparation:

```go
// Engine is the in-process policy evaluation engine powered by OPA.
type Engine struct {
    mu      sync.RWMutex
    queries map[string]*rego.PreparedEvalQuery
    store   storage.Store
}

// Decision represents the result of a policy evaluation.
type Decision struct {
    Allow      bool           `json:"allow"`
    Reasons    []string       `json:"reasons,omitempty"`
    Violations []Violation    `json:"violations,omitempty"`
    Metadata   map[string]any `json:"metadata,omitempty"`
    EvalTimeUs int64          `json:"eval_time_us"`
}
```

Policies are loaded either as individual `.rego` files or as pre-bundled
`tar.gz` archives. The Rego namespace is `data.cloudforge.ai`:

```go
func (e *Engine) LoadPolicies(ctx context.Context, paths []string) error {
    r = rego.New(
        rego.Query("data.cloudforge.ai"),
        rego.Store(e.store),
        rego.Load([]string{path}, nil),
    )
    pq, err := r.PrepareForEval(ctx)
    e.queries["default"] = &pq
    return nil
}
```

#### 3.5.4 Evaluation Input Schema

All policy evaluation uses the `EvaluationInput` struct, which carries typed
contexts for the agent, the tool being invoked, the data being accessed, and
the originating request:

```go
// EvaluationInput is the input to policy evaluation.
type EvaluationInput struct {
    Agent       AgentContext      `json:"agent"`
    Tool        *ToolContext      `json:"tool,omitempty"`
    Data        *DataContext      `json:"data,omitempty"`
    Request     *RequestContext   `json:"request,omitempty"`
    Environment map[string]string `json:"environment,omitempty"`
}

// AgentContext provides agent information for policy evaluation.
type AgentContext struct {
    ID           string   `json:"id"`
    Name         string   `json:"name"`
    Team         string   `json:"team"`
    Environment  string   `json:"environment"`
    Capabilities []string `json:"capabilities"`
}

// ToolContext provides tool invocation information.
type ToolContext struct {
    Name       string         `json:"name"`
    Category   string         `json:"category"`
    Parameters map[string]any `json:"parameters"`
    External   bool           `json:"external"`
}

// DataContext provides data flow information.
type DataContext struct {
    Classification string   `json:"classification"`
    Source         string   `json:"source"`
    Destination    string   `json:"destination"`
    PIIFields      []string `json:"pii_fields,omitempty"`
}
```

Two convenience methods are exposed for the two primary policy domains:

```go
// EvaluateToolAccess evaluates tool access policy for an AI agent.
func (e *Engine) EvaluateToolAccess(ctx context.Context, agent *AgentContext, tool *ToolContext) (*Decision, error) {
    input := &EvaluationInput{Agent: *agent, Tool: tool}
    return e.Evaluate(ctx, "cloudforge.ai.tool_access.allow", input)
}

// EvaluateDataFlow evaluates data flow policy for an AI agent.
func (e *Engine) EvaluateDataFlow(ctx context.Context, agent *AgentContext, data *DataContext) (*Decision, error) {
    input := &EvaluationInput{Agent: *agent, Data: data}
    return e.Evaluate(ctx, "cloudforge.ai.data_flow.allow", input)
}
```

#### 3.5.5 Built-in Rego Policies

Two base policies are embedded as Go constants. Both are loaded at engine
initialization and can be overridden by environment-specific bundles.

**Tool Access Policy** (`package cloudforge.ai.tool_access`):
- Default deny; allow requires tool in allowed list, parameters passing
  forbidden-pattern regex check, and no rate-limit breach
- Generates typed `denial_reasons` for audit logs

```rego
package cloudforge.ai.tool_access

default allow = false

allow {
    tool_allowed
    parameters_valid
    not rate_limit_exceeded
}

tool_allowed {
    input.tool.name in data.policies.allowed_tools[input.agent.id]
}

contains_forbidden_pattern {
    pattern := data.policies.forbidden_patterns[_]
    regex.match(pattern, json.marshal(input.tool.parameters))
}
```

**Data Flow Policy** (`package cloudforge.ai.data_flow`):
- Controls which data classifications may flow to which destinations
- PII data to `redact_destinations` triggers field-level redaction
- `source_restricted` check blocks flows from restricted sources to
  untrusted destinations

```rego
package cloudforge.ai.data_flow

default allow_flow = false

allow_flow {
    destination_allowed
    not source_restricted
}

requires_redaction {
    input.data.classification == "PII"
    input.data.destination in data.policies.redact_destinations
}
```

#### 3.5.6 Agent Registry

The `Agent` struct is the central registry record, linking an agent's identity
to its capabilities, tool bindings, bound policy IDs, and operational status:

```go
// Agent represents a registered AI agent in the system.
type Agent struct {
    ID           uuid.UUID    `json:"id" db:"id"`
    Name         string       `json:"name" db:"name"`
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
}
```

Status lifecycle: `active` -> `suspended` (policy violation) -> `inactive`
(decommissioned) or `deprecated` (replaced by newer version).

#### 3.5.7 Observability: Agent Traces

`AgentTrace` captures the full execution tree of an agent invocation. Each
invocation produces a root trace with N child `Span` records, each typed as
`llm`, `retrieval`, `tool`, `chain`, `agent`, or `policy`:

```go
// AgentTrace represents a complete execution trace for an agent invocation.
type AgentTrace struct {
    TraceID         string           `json:"trace_id" db:"trace_id"`
    AgentID         uuid.UUID        `json:"agent_id" db:"agent_id"`
    SessionID       string           `json:"session_id" db:"session_id"`
    UserID          string           `json:"user_id" db:"user_id"`
    Status          TraceStatus      `json:"status" db:"status"`
    Spans           []Span           `json:"spans" db:"spans"`
    SecuritySignals []SecuritySignal `json:"security_signals" db:"security_signals"`
    Metrics         TraceMetrics     `json:"metrics" db:"metrics"`
}
```

`TraceStatus` includes the value `blocked` for traces terminated by a policy
denial. `SecuritySignal` records detected anomalies within a trace (signal
types: `injection_attempt`, `data_exfiltration`, `tool_abuse`,
`privilege_escalation`, `anomalous_behavior`, `policy_violation`,
`rate_limit_exceeded`).

`TraceMetrics` provides aggregate token accounting and cost estimation:

```go
type TraceMetrics struct {
    TotalSpans        int     `json:"total_spans"`
    LLMCalls          int     `json:"llm_calls"`
    ToolInvocations   int     `json:"tool_invocations"`
    TotalTokens       int     `json:"total_tokens"`
    EstimatedCostUSD  float64 `json:"estimated_cost_usd"`
    PolicyEvaluations int     `json:"policy_evaluations"`
    SecuritySignals   int     `json:"security_signals"`
}
```

#### 3.5.8 STRIDE + MITRE ATLAS Threat Models

The `ThreatModel` struct links threats to STRIDE categories and ATLAS
technique identifiers, enabling structured threat modeling for AI systems:

```go
// Threat represents an identified threat.
type Threat struct {
    ID                 string         `json:"id"`
    Title              string         `json:"title"`
    Category           STRIDECategory `json:"category"`
    Likelihood         string         `json:"likelihood"` // low, medium, high, very_high
    Impact             string         `json:"impact"`     // low, medium, high, critical
    RiskLevel          string         `json:"risk_level"` // likelihood x impact
    ATLASTechniques    []string       `json:"atlas_techniques"`
    MitigationIDs      []string       `json:"mitigation_ids"`
}
```

STRIDE categories mapped: `spoofing`, `tampering`, `repudiation`,
`information_disclosure`, `denial_of_service`, `elevation_of_privilege`.

ATLAS techniques are referenced by identifier (e.g., `AML.T0051` for LLM
prompt injection). `Mitigation.MappedControls` links mitigations back to
compliance framework control IDs in `internal/compliance/`.

#### 3.5.9 Maturity Assessment

`MaturityAssessment` provides a 1-5 level maturity scoring across governance
domains. Each `DomainAssessment` is weighted and composed of
`CapabilityAssessment` records that track current vs. target levels with
supporting evidence:

```go
type MaturityAssessment struct {
    ID             string             `json:"id" db:"id"`
    OrganizationID string             `json:"organization_id" db:"organization_id"`
    AssessmentDate time.Time          `json:"assessment_date" db:"assessment_date"`
    Domains        []DomainAssessment `json:"domains"`
    OverallScore   float64            `json:"overall_score"`
    OverallLevel   int                `json:"overall_level"` // 1-5
    Recommendations []Recommendation  `json:"recommendations"`
}
```

`Recommendation` records include current/target level delta, effort estimate
(`small`, `medium`, `large`), and impact classification.

---

### 3.6 IaC Deploy Layer

#### 3.6.1 Directory Structure

```
deploy/
├── terraform/
│   ├── modules/
│   │   ├── compute/
│   │   │   ├── main.tf         # GCP Cloud Run / AWS ECS Fargate / Azure Container Apps
│   │   │   └── variables.tf
│   │   ├── database/
│   │   │   ├── main.tf         # GCP Cloud SQL / AWS RDS / Azure PostgreSQL Flexible
│   │   │   └── variables.tf
│   │   └── redis/
│   │       ├── main.tf         # GCP Memorystore / AWS ElastiCache / Azure Cache for Redis
│   │       └── variables.tf
│   ├── environments/
│   │   ├── dev/                # Dev environment composition
│   │   └── (staging, prod planned)
│   └── policies/
│       ├── security-baseline.rego     # Encryption, public IPs, TLS, IAM wildcards
│       ├── cost-controls.rego         # (planned) Instance sizing, retention caps
│       ├── naming-conventions.rego    # (planned) Resource naming enforcement
│       ├── network-security.rego      # (planned) CIDR restrictions, subnet placement
│       └── ai-governance.rego         # (planned) AI_MODEL env var, observability
├── scripts/
│   ├── plan-with-policy.sh    # Terraform plan -> JSON -> conftest pipeline
│   └── deploy.sh              # Apply script with pre-flight checks
├── Dockerfile.api             # Multi-stage Go build
└── Dockerfile.worker          # Worker container image
```

#### 3.6.2 Multi-Cloud Module Design (count-based provider switching)

All three Terraform modules use a `count = var.cloud_provider == "X" ? 1 : 0`
pattern to select exactly one cloud provider's resources at plan time. This
produces a single module interface usable across GCP, AWS, and Azure with no
conditional logic at the environment composition layer:

**Compute module** (`modules/compute/main.tf`):
- GCP: `google_cloud_run_v2_service` — VPC egress restricted to
  `PRIVATE_RANGES_ONLY`, service account injection, Secret Manager refs
- AWS: `aws_ecs_task_definition` + `aws_ecs_service` — Fargate launch type,
  `awsvpc` networking, CloudWatch log group, Secrets Manager value references.
  `assign_public_ip = false` is hardcoded (not configurable).
- Azure: `azurerm_container_app` — delegated Container Apps environment,
  secret references via environment variable secret bindings

**Database module** (`modules/database/main.tf`):
- GCP: `google_sql_database_instance` — `ipv4_enabled = false`, private
  network only, `require_ssl = true`, PITR enabled in prod,
  `deletion_protection` in prod
- AWS: `aws_db_instance` — `storage_encrypted = true` (hardcoded),
  `manage_master_user_password = true` (Secrets Manager rotation),
  `publicly_accessible = false`, Multi-AZ in prod
- Azure: `azurerm_postgresql_flexible_server` — delegated subnet,
  geo-redundant backup in prod

Instance tier mappings are defined as `local` maps per provider:

```hcl
local {
  tier_map_gcp   = { SMALL = "db-f1-micro",         STANDARD = "db-custom-2-7680"    }
  tier_map_aws   = { SMALL = "db.t3.micro",          STANDARD = "db.t3.medium"        }
  tier_map_azure = { SMALL = "B_Standard_B1ms",      STANDARD = "GP_Standard_D2s_v3"  }
}
```

**Redis module** (`modules/redis/main.tf`):
- GCP: `google_redis_instance` — `transit_encryption_mode = "SERVER_AUTHENTICATION"`,
  `auth_enabled = true`, HA via `STANDARD_HA` tier
- AWS: `aws_elasticache_replication_group` — `at_rest_encryption_enabled = true`,
  `transit_encryption_enabled = true`, automatic failover in HA mode
- Azure: `azurerm_redis_cache` — `enable_non_ssl_port = false`,
  `minimum_tls_version = "1.2"`, subnet binding

#### 3.6.3 Security Policy Gate: conftest Pipeline

Terraform plans are validated against Rego policies using `conftest` before
any `apply` is permitted. The `plan-with-policy.sh` script implements a
four-step pipeline:

```
Step 1: terraform init -backend=false
Step 2: terraform plan -var="cloud_provider=${PROVIDER}" -out=plan.tfplan
Step 3: terraform show -json plan.tfplan > plan.json
Step 4: conftest test plan.json --policy policies/ --namespace terraform
```

Exit code semantics:
- `0` — all checks passed; safe to apply
- `1` — policy violations detected; apply blocked
- `2` — warnings only; human review required before applying

```bash
CONFTEST_EXIT=0
conftest test "${PLAN_JSON}" \
    --policy "${POLICY_DIR}" \
    --namespace "terraform" \
    --output table \
    2>&1 || CONFTEST_EXIT=$?

if [[ ${CONFTEST_EXIT} -eq 0 ]]; then
    echo "[+] All policy checks PASSED."
elif [[ ${CONFTEST_EXIT} -eq 2 ]]; then
    echo "[!] Policy checks passed with WARNINGS."
    exit 2
else
    echo "[-] Policy VIOLATIONS detected. Resolve before applying."
    exit 1
fi
```

#### 3.6.4 Security Baseline Rego Policies

The `security-baseline.rego` policy file (`package terraform.security_baseline`)
enforces eight mandatory security controls against the `terraform plan` JSON:

| Policy ID | Control | Resources Checked |
|-----------|---------|-------------------|
| SECURITY-001 | Encryption at rest | `aws_db_instance`, `aws_rds_cluster`, `google_sql_database_instance`, `azurerm_postgresql_flexible_server` |
| SECURITY-002 | S3 server-side encryption | `aws_s3_bucket` |
| SECURITY-003 | No public Cloud Run ingress | `google_cloud_run_v2_service` |
| SECURITY-004 | No public EC2 IP | `aws_instance` |
| SECURITY-005 | TLS 1.2+ on ALB listeners | `aws_lb_listener` |
| SECURITY-006 | TLS 1.2+ on GCP SSL policies | `google_compute_ssl_policy` |
| SECURITY-007 | No default VPC usage | `aws_instance`, `aws_ecs_service`, `aws_rds_instance` |
| SECURITY-008 | No wildcard IAM actions | `aws_iam_policy`, `google_project_iam_binding` |

Example denial rule:

```rego
package terraform.security_baseline

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_db_instance", "google_sql_database_instance",
                      "azurerm_postgresql_flexible_server"]
    config := resource.change.after
    not config.storage_encrypted
    msg := sprintf(
        "SECURITY-001: %s '%s' must have storage_encrypted = true",
        [resource.type, resource.name]
    )
}
```

#### 3.6.5 Three-Layer OPA Governance Architecture

When the IaC deploy layer is combined with the existing policy modules, the
full platform implements a three-layer OPA governance model:

```
Layer 1: IaC Plan Gate (pre-deploy)
   conftest + security-baseline.rego
   Triggered: before every terraform apply
   Scope: infrastructure resource properties
   Blocking: hard block on policy violations

Layer 2: Cloud Provisioning Runtime (post-deploy)
   internal/policy/evaluator.go -> HTTP OPA server
   Triggered: per API request for resource provisioning
   Scope: runtime resource state + compliance context
   Blocking: request denied if policy evaluation fails

Layer 3: AI Agent Governance (runtime)
   internal/ai-governance/opa/engine.go (in-process)
   Triggered: per tool invocation and data access by AI agents
   Scope: agent capabilities, tool parameters, data classifications
   Blocking: synchronous deny before tool execution
```

#### 3.6.6 Container Images

Two Dockerfiles are provided, both using multi-stage Go builds:

- `Dockerfile.api` — API server image, `gcr.io/distroless/base-debian12` final
  stage, runs as non-root UID 65532
- `Dockerfile.worker` — Worker/consumer image, same base, separate binary
  entrypoint for the remediation worker process

Both images bake the `VERSION` build arg as a Go linker variable
(`-ldflags "-X main.version=${VERSION}"`) for version reporting in health
endpoints.

---

### 3.7 Risk Intelligence Module (Planned)

This section describes the planned Risk Intelligence module, which will
introduce graph-based attack path analysis and threat intelligence enrichment.
Current state: design and schema complete; implementation planned as the next
major feature release.

#### 3.7.1 Design Rationale

Traditional CSPM tools evaluate findings in isolation. A misconfigured S3
bucket is "medium." An overly permissive IAM role is "medium." A known CVE on
an EC2 instance is "medium." But chain them together — internet-exposed EC2
with CVE -> lateral movement via overprivileged role -> exfiltrate from
misconfigured S3 containing PII — and the aggregate is a critical attack path.

The Risk Intelligence module implements **toxic combination detection**: the
insight that multiple low/medium-severity issues chained together create
critical risk. Findings are evaluated across 7 dimensions simultaneously:
network exposures, vulnerabilities, misconfigurations, identities, data stores,
secrets, and malware/behavioral signals.

#### 3.7.2 AttackPathContext Schema

The `AttackPathContext` struct (defined in
`cspm-aggregator/internal/normalizer/schema.go`) carries attack path metadata
enriched from cloud-native engines (Azure attack paths, GCP attack exposure
score, AWS GuardDuty attack sequences) and open-source tooling (Cartography,
PMapper):

```go
// AttackPathContext contains attack path analysis context.
type AttackPathContext struct {
    Score              float64  `json:"score,omitempty"`              // 0-100 composite attack path score
    PathNodeCount      int      `json:"path_node_count,omitempty"`    // Nodes in longest attack path
    EntryPointType     string   `json:"entry_point_type,omitempty"`   // internet, lateral, insider
    TargetType         string   `json:"target_type,omitempty"`        // data, compute, identity, network
    BlastRadiusCount   int      `json:"blast_radius_count,omitempty"` // Resources reachable from finding
    IsToxicCombination bool     `json:"is_toxic_combination,omitempty"`
    IsChokepoint       bool     `json:"is_chokepoint,omitempty"`
    IAMEscalationPath  []string `json:"iam_escalation_path,omitempty"` // Privilege escalation chain
}
```

`IsToxicCombination` is set when multiple otherwise-low-severity findings chain
into a critical path. `IsChokepoint` identifies nodes through which many attack
paths pass — remediation of a chokepoint breaks the largest number of paths
simultaneously.

#### 3.7.3 ToxicComboDetails Schema

The `FindingClass` enum in the normalizer schema includes classes specific to
graph-based analysis:

```go
const (
    ClassThreat            FindingClass = "THREAT"
    ClassVulnerability     FindingClass = "VULNERABILITY"
    ClassMisconfiguration  FindingClass = "MISCONFIGURATION"
    ClassObservation       FindingClass = "OBSERVATION"
    ClassPostureViolation  FindingClass = "POSTURE_VIOLATION"
    ClassToxicCombination  FindingClass = "TOXIC_COMBINATION"  // graph-derived
    ClassChokepoint        FindingClass = "CHOKEPOINT"          // graph-derived
    ClassSensitiveDataRisk FindingClass = "SENSITIVE_DATA_RISK"
)
```

These classes are set by the cloud-native engines: GCP SCC reports
`TOXIC_COMBINATION` and `CHOKEPOINT` natively via the `findingClass` field;
AWS GuardDuty `Detection` objects are mapped to `THREAT`; Azure Defender
assessments default to `MISCONFIGURATION`.

#### 3.7.4 Threat Intelligence Context

`ThreatIntelContext` carries enrichment from five public feeds: CISA KEV,
EPSS v4, NVD CVSS, GreyNoise, and AlienVault OTX:

```go
// ThreatIntelContext contains threat intelligence enrichment.
type ThreatIntelContext struct {
    CVEIDs         []string  `json:"cve_ids,omitempty"`
    InKEV          bool      `json:"in_kev,omitempty"`          // CISA Known Exploited Vulnerabilities
    KEVDateAdded   string    `json:"kev_date_added,omitempty"`
    EPSSScore      float64   `json:"epss_score,omitempty"`      // 0.0-1.0 exploitation probability
    EPSSPercentile float64   `json:"epss_percentile,omitempty"`
    CVSSBaseScore  float64   `json:"cvss_base_score,omitempty"`
    CVSSVector     string    `json:"cvss_vector,omitempty"`
    GreyNoiseClass string    `json:"greynoise_class,omitempty"` // benign, malicious, unknown
    OTXPulseCount  int       `json:"otx_pulse_count,omitempty"`
    EnrichedAt     time.Time `json:"enriched_at,omitempty"`
}
```

`InKEV = true` is treated as an aggravating factor in the LLM scoring prompt
regardless of CVSS base score. `EPSSScore` provides a probabilistic
exploitation likelihood that the AI scorer uses to adjust severity (high EPSS +
internet-facing asset = upgrade to next severity tier).

#### 3.7.5 LLM Scoring with Attack Path Context

The `RiskScorer.BuildPrompt()` method in `cspm-aggregator/internal/scoring/risk_scorer.go`
conditionally appends an attack path and threat intelligence section to the
Claude prompt when the relevant fields are populated:

```go
// Add threat intelligence context if present
if ctx.InKEV || ctx.EPSSScore > 0 || ctx.AttackPathScore > 0 {
    prompt += fmt.Sprintf(`
## Threat Intelligence
- In CISA KEV: %t
- EPSS Score: %.4f (percentile: %.2f)
- Attack Path Score: %.1f
- Toxic Combination: %t
- Blast Radius (reachable resources): %d
`,
        ctx.InKEV,
        ctx.EPSSScore,
        ctx.EPSSPercentile,
        ctx.AttackPathScore,
        ctx.IsToxicCombination,
        ctx.BlastRadiusCount,
    )
}
```

The prompt instructs the model to treat `InKEV`, attack path score, and
`IsToxicCombination` as aggravating factors. Business guardrails applied
post-response:
- CRITICAL severity is never downgraded for Tier1-Prod internet-facing assets
- PCI/PII findings have a minimum severity floor of MEDIUM
- Confidence is capped at 0.7 when package usage is unknown

#### 3.7.6 Planned Graph Database Layer

The planned graph layer will use Neo4j (development) and Amazon Neptune
(production AWS) as a relationship store alongside existing finding storage.
Graph schema:

```
Nodes:
  (:Asset {id, type, account, cloud, region})
  (:Finding {id, severity, source, cve})
  (:Identity {arn, type, permissions[]})
  (:DataStore {id, classification, encrypted})

Edges:
  (Asset)-[:HAS_FINDING]->(Finding)
  (Asset)-[:CAN_REACH]->(Asset)      // network reachability
  (Identity)-[:CAN_ASSUME]->(Identity) // role chaining
  (Identity)-[:CAN_ACCESS]->(DataStore)
  (Asset)-[:RUNS_AS]->(Identity)
```

Attack path templates will be defined as Cypher query patterns:

```cypher
// Internet-exposed -> vulnerable -> overprivileged -> sensitive data
MATCH path = (entry:Asset)-[:CAN_REACH*1..4]->(target:DataStore)
WHERE entry.internetExposed = true
  AND ANY(f IN [(entry)-[:HAS_FINDING]->(f) | f]
         WHERE f.severity >= 'HIGH')
  AND ANY(hop IN nodes(path)
         WHERE hop:Identity AND hop.overprivileged = true)
  AND target.classification IN ['PII', 'PHI', 'FINANCIAL']
RETURN path, length(path) as hops
ORDER BY hops ASC
```

Paths are scored by: hop count (shorter = more exploitable), severity of
findings along each hop, target asset criticality, and entry point exposure
type.

#### 3.7.7 Cross-Account Path Analysis

With environments spanning multiple cloud accounts and projects, cross-account
trust relationships represent the primary blind spot of cloud-native CSPM
tools. The graph layer will ingest:
- AWS: IAM trust policies, resource policies, cross-account roles, VPC
  peering, Transit Gateway attachments, PrivateLink connections
- GCP: Organization policies, shared VPC configurations, service account
  impersonation chains across projects
- Azure: Management group hierarchy, cross-subscription RBAC assignments,
  service principal relationships

Graph edges span account boundaries, enabling detection of lateral movement
paths invisible to any single-account tool.

#### 3.7.8 Contextual Severity Validation Design

The LLM severity adjustment output is validated against the following
guardrail rules (implemented in `applyGuardrails` in `risk_scorer.go`):

| Rule | Condition | Effect |
|------|-----------|--------|
| GR-001 | CRITICAL + Tier1-Prod + internet-facing | Never downgrade; hard floor |
| GR-002 | PCI or PII data classification | Minimum severity = MEDIUM |
| GR-003 | Package usage unknown | Cap confidence at 0.70 |
| GR-004 | Severity/score alignment | Clamp risk score to severity band |

Severity-to-score bands:

| Severity | Min Score | Max Score |
|----------|-----------|-----------|
| CRITICAL | 85 | 100 |
| HIGH | 65 | 84 |
| MEDIUM | 40 | 64 |
| LOW | 15 | 39 |

Auto-accept shortcuts (rule-based, skip LLM call):
- LOW severity in sandbox environment -> auto-accept
- FP rate for type > 30% and >= 3 historical FPs and non-CRITICAL -> downgrade to LOW

---

## 4. Data Architecture

### 4.1 Database Schema

#### 4.1.1 Core Tables

```sql
-- Findings table with partitioning
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source VARCHAR(100) NOT NULL,
    source_finding_id VARCHAR(255),
    type VARCHAR(50) NOT NULL,
    category VARCHAR(50),
    title TEXT NOT NULL,
    description TEXT,
    
    -- Resource
    resource_type VARCHAR(50),
    resource_id VARCHAR(500),
    resource_name VARCHAR(255),
    
    -- Platform
    platform VARCHAR(50),
    cloud_provider VARCHAR(50),
    region VARCHAR(100),
    account_id VARCHAR(100),
    environment_type VARCHAR(50),
    
    -- Severity
    static_severity VARCHAR(20),
    ai_risk_score DECIMAL(4,2),
    ai_risk_level VARCHAR(20),
    cvss DECIMAL(3,1),
    
    -- Workflow
    workflow_status VARCHAR(50) DEFAULT 'new',
    assignee_id VARCHAR(255),
    assignee_email VARCHAR(255),
    
    -- Ownership
    service_name VARCHAR(255),
    line_of_business VARCHAR(255),
    technical_contact_email VARCHAR(255),
    
    -- Timestamps
    first_found_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    due_date TIMESTAMPTZ,
    
    -- Deduplication
    deduplication_key VARCHAR(64) NOT NULL,
    canonical_rule_id VARCHAR(255),
    
    -- JSONB for flexible data
    cves JSONB,
    compliance_mappings JSONB,
    raw_data JSONB,
    tags JSONB,
    
    CONSTRAINT unique_dedup_key UNIQUE (deduplication_key)
) PARTITION BY RANGE (first_found_at);

-- Monthly partitions
CREATE TABLE findings_2026_01 PARTITION OF findings
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

-- Indexes
CREATE INDEX idx_findings_status ON findings (workflow_status);
CREATE INDEX idx_findings_severity ON findings (static_severity);
CREATE INDEX idx_findings_resource ON findings (resource_id);
CREATE INDEX idx_findings_assignee ON findings (assignee_email);
CREATE INDEX idx_findings_gin_cves ON findings USING GIN (cves);
CREATE INDEX idx_findings_gin_compliance ON findings USING GIN (compliance_mappings);
```

#### 4.1.2 Compliance Framework Tables

```sql
CREATE TABLE compliance_frameworks (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    sector VARCHAR(50),
    url TEXT,
    controls JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sector_profiles (
    sector VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    required_frameworks JSONB,
    optional_frameworks JSONB
);
```

### 4.2 Cache Strategy

| Cache Key Pattern | TTL | Purpose |
|-------------------|-----|---------|
| `framework:{id}` | 24h | Compliance framework data |
| `finding:{id}` | 1h | Individual finding cache |
| `dedup:{key}` | 7d | Deduplication key lookup |
| `user:{id}:session` | 8h | User session data |
| `rate:{provider}:{key}` | 1min | Rate limiting counters |

---

## 5. API Specifications

### 5.1 Finding Endpoints

#### Create Finding

```http
POST /api/v1/findings
Content-Type: application/json

{
  "source": "aws-security-hub",
  "source_finding_id": "arn:aws:securityhub:...",
  "type": "misconfiguration",
  "title": "S3 bucket allows public access",
  "resource_id": "arn:aws:s3:::my-bucket",
  "static_severity": "high",
  "environment_type": "production"
}
```

#### Response

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "deduplication_key": "abc123...",
  "workflow_status": "new",
  "compliance_mappings": [
    {
      "framework_id": "cis-benchmarks",
      "control_id": "3.1",
      "control_title": "Data Protection"
    }
  ],
  "ai_risk_score": 8.5,
  "ai_risk_level": "critical"
}
```

### 5.2 Error Responses

| Code | Error | Description |
|------|-------|-------------|
| 400 | INVALID_REQUEST | Request validation failed |
| 401 | UNAUTHORIZED | Authentication required |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 409 | DUPLICATE | Finding already exists |
| 429 | RATE_LIMITED | Too many requests |
| 500 | INTERNAL_ERROR | Server error |

---

## 6. Security Design

### 6.1 Authentication Flow

```
User → CloudForge UI → OIDC Provider (Entra/Okta)
                              ↓
                         ID Token
                              ↓
                    CloudForge API Gateway
                              ↓
                    Token Validation + RBAC
                              ↓
                      Authorized Request
```

### 6.2 Authorization Matrix

| Role | Findings Read | Findings Write | Config | Admin |
|------|--------------|----------------|--------|-------|
| Viewer | Own LoB | - | - | - |
| Analyst | All | Assign/Comment | - | - |
| Engineer | All | Remediate | - | - |
| Admin | All | All | Yes | - |
| Super Admin | All | All | Yes | Yes |

### 6.3 Encryption

| Data State | Method | Key Management |
|------------|--------|----------------|
| At Rest (DB) | AES-256 | AWS KMS |
| At Rest (S3) | AES-256 | AWS KMS |
| In Transit | TLS 1.3 | AWS ACM |
| API Keys | Envelope | AWS Secrets Manager |

---

## 7. Performance Requirements

### 7.1 SLAs

| Metric | Target | Measurement |
|--------|--------|-------------|
| API Latency (p50) | < 100ms | Prometheus histogram |
| API Latency (p99) | < 500ms | Prometheus histogram |
| Finding Ingestion | 1000/sec | Kafka consumer lag |
| Compliance Mapping | < 200ms | Per finding |
| AI Analysis | < 3s | Per finding |
| Availability | 99.9% | Uptime monitoring |
| Remediation Dispatch (T1, single finding) | < 2s end-to-end | `RemediationResult.Duration` field |
| Remediation Dispatch (T1, batch of 50) | < 30s | `ExecuteBatch` total wall time |
| Remediation Validation round-trip | < 5s | Post-remediation `Validate()` call |
| AI Governance Policy Evaluation (in-process OPA) | < 5ms (p99) | `Decision.EvalTimeUs` field |
| IaC Policy Gate (conftest full plan) | < 60s | `plan-with-policy.sh` exit time |

### 7.2 Scaling Triggers

| Component | Metric | Scale Up | Scale Down |
|-----------|--------|----------|------------|
| API Pods | CPU | > 70% | < 30% |
| Workers | Queue Depth | > 1000 | < 100 |
| Database | Connections | > 80% | Manual |

---

## 8. Observability

### 8.1 Metrics

```go
var (
    findingsProcessed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cloudforge_findings_processed_total",
            Help: "Total findings processed",
        },
        []string{"source", "type", "severity"},
    )
    
    aiAnalysisLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "cloudforge_ai_analysis_duration_seconds",
            Help:    "AI analysis latency",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
        },
        []string{"provider"},
    )
)
```

### 8.2 Logging

```go
logger.Info("Finding processed",
    zap.String("finding_id", finding.ID),
    zap.String("source", finding.Source),
    zap.String("type", string(finding.Type)),
    zap.Float64("ai_risk_score", finding.AIRiskScore),
    zap.Duration("processing_time", elapsed),
)
```

### 8.3 Tracing

```go
ctx, span := tracer.Start(ctx, "ProcessFinding",
    trace.WithAttributes(
        attribute.String("finding.id", finding.ID),
        attribute.String("finding.source", finding.Source),
    ),
)
defer span.End()
```

---

## Appendix A: Configuration Reference

### A.1 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CF_DATABASE_URL` | PostgreSQL connection string | - |
| `CF_REDIS_URL` | Redis connection string | - |
| `CF_AI_PROVIDER` | AI provider (anthropic/openai) | anthropic |
| `CF_AI_MODEL` | AI model name | claude-opus-4-6 |
| `CF_LOG_LEVEL` | Log level | info |
| `CF_METRICS_PORT` | Prometheus metrics port | 9090 |

### A.2 Configuration File

```yaml
server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

database:
  host: localhost
  port: 5432
  name: cloudforge
  max_connections: 100

redis:
  host: localhost
  port: 6379
  db: 0

ai:
  provider: anthropic
  model: claude-opus-4-6
  max_tokens: 4096
  contextual_risk_weight: 0.4

compliance:
  enabled_sectors:
    - general
    - healthcare
    - finance
    - government
    - automotive
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| CSPM | Cloud Security Posture Management |
| DDD | Detailed Design Document |
| HLD | High-Level Design |
| OPA | Open Policy Agent |
| OCSF | Open Cybersecurity Schema Framework |
| SCA | Software Composition Analysis |
| SAST | Static Application Security Testing |
| WIF | Workload Identity Federation |

---

## Appendix C: References

1. [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
2. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
3. [ISO/SAE 21434:2021](https://www.iso.org/standard/70918.html)
4. [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
5. [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/)

