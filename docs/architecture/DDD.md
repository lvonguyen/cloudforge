# Detailed Design Document: CloudForge Enterprise Cloud Governance Platform

---

## Document Control

| Property | Value |
|----------|-------|
| Document ID | CF-DDD-001 |
| Version | 1.0 |
| Status | Draft |
| Classification | Internal |
| Created | January 5, 2026 |
| Last Updated | January 5, 2026 |

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
| `CF_AI_MODEL` | AI model name | claude-opus-4-5-20250514 |
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
  model: claude-opus-4-5-20250514
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

