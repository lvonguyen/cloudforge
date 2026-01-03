# High-Level Design: CloudForge Enterprise Cloud Governance Platform

| Property | Value |
| --- | --- |
| Version | 1.0 |
| Author | Liem Vo-Nguyen |
| Date | December 22, 2024 |
| Status | Draft |

---

## 1. Executive Summary

This document describes the architecture for CloudForge, an Internal Developer Platform (IDP) that enables self-service cloud resource provisioning with built-in governance, compliance guardrails, and exception management workflows. The solution bridges the gap between developer velocity and enterprise security/compliance requirements.

### 1.1 Business Drivers

- Enable self-service infrastructure provisioning without bypassing security controls
- Enforce policy-as-code guardrails across multi-cloud environments (AWS, Azure, GCP)
- Integrate with enterprise GRC tools (RSA Archer, ServiceNow) for exception management
- Provide golden path Terraform modules to standardize infrastructure patterns
- Reduce infrastructure request ticket backlog and approval cycle times
- Maintain audit trails for compliance and regulatory requirements

---

## 2. Architecture Overview

The solution uses a layered architecture with a Go-based API server, Temporal workflows for orchestration, OPA/Rego for policy evaluation, and pluggable integrations for GRC platforms and cloud providers.

### 2.1 Architecture Diagram

```
+-----------------------------------------------------------------------------+
|                           CloudForge Platform                                |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +------------------+    +------------------+    +------------------+        |
|  |   Portal Layer   |    |   Orchestration  |    |  Policy Engine   |        |
|  |   (Backstage)    |    |   (Temporal)     |    |   (OPA/Rego)     |        |
|  +--------+---------+    +--------+---------+    +--------+---------+        |
|           |                       |                       |                  |
|           +-----------------------+-----------------------+                  |
|                                   |                                          |
|                                   v                                          |
|              +--------------------------------------------+                  |
|              |           Go API Server                    |                  |
|              |  +----------------+  +------------------+  |                  |
|              |  | GRC Providers  |  | Cloud Providers  |  |                  |
|              |  | - Archer       |  | - AWS            |  |                  |
|              |  | - ServiceNow   |  | - Azure          |  |                  |
|              |  | - PostgreSQL   |  | - GCP            |  |                  |
|              |  +----------------+  +------------------+  |                  |
|              +--------------------------------------------+                  |
|                                   |                                          |
|              +--------------------+--------------------+                     |
|              |                    |                    |                     |
|              v                    v                    v                     |
|        +----------+        +----------+        +---------------+             |
|        | Terraform|        | CMDB     |        | Audit Logs    |             |
|        | Modules  |        | (SNOW)   |        | (PostgreSQL)  |             |
|        +----------+        +----------+        +---------------+             |
|                                                                              |
+-----------------------------------------------------------------------------+
```

### 2.2 Component Summary

| Component | Purpose | Technology |
| --- | --- | --- |
| Portal Layer | Self-service UI for requests and dashboards | Backstage / React |
| Orchestration Engine | Workflow management for approvals and provisioning | Temporal |
| Policy Engine | Evaluate requests against governance rules | OPA / Rego |
| API Server | Central hub for all platform operations | Go 1.21 |
| GRC Providers | Abstract enterprise GRC tool integrations | Pluggable Go interfaces |
| Cloud Providers | Abstract cloud resource provisioning | AWS/Azure/GCP SDKs |
| Terraform Executor | Apply golden path modules | Atlantis / Terraform Cloud |
| State Store | Audit logs and request history | PostgreSQL |

---

## 3. Portal Layer

### 3.1 Self-Service Capabilities

| Feature | Description |
| --- | --- |
| Application Registration | Register apps with metadata (owner, tier, CBU, data classification) |
| Infrastructure Catalog | Browse and request from pre-approved Terraform modules |
| Exception Requests | Submit policy exception requests with business justification |
| Compliance Dashboard | View policy compliance status across resources |
| Request Tracking | Track approval and provisioning status |

### 3.2 User Roles

| Role | Capabilities |
| --- | --- |
| Developer | Submit requests, view own resources |
| Team Lead | Approve team requests, view team resources |
| Platform Admin | Manage catalog, configure policies |
| Security | Review exceptions, view compliance reports |
| Finance | View cost reports, manage budgets |

---

## 4. Orchestration Layer (Temporal)

### 4.1 Workflow Types

| Workflow | Purpose | Steps |
| --- | --- | --- |
| Registration | Onboard new application | Validate metadata -> Create CMDB entry -> Assign resource group |
| Approval | Route requests for approval | Check policy -> Route to approvers -> Collect signatures |
| Provisioning | Deploy infrastructure | Validate -> Plan Terraform -> Approval gate -> Apply -> Update CMDB |
| Compliance Scan | Periodic policy checks | Query resources -> Evaluate policies -> Generate findings |
| Exception | Handle policy exceptions | Submit to GRC -> Approval workflow -> Store decision -> Update policy |

### 4.2 Workflow Activities

```go
type ProvisioningWorkflow struct {
    RequestID     string
    ApplicationID string
    ModuleID      string
    Parameters    map[string]interface{}
}

// Activities
- ValidateRequest()      // Check request format and permissions
- EvaluatePolicies()     // OPA policy evaluation
- GenerateTerraformPlan() // Create execution plan
- AwaitApproval()        // Human approval gate
- ApplyTerraform()       // Execute infrastructure changes
- UpdateCMDB()           // Record in ServiceNow
- SendNotification()     // Notify stakeholders
```

---

## 5. Policy Engine (OPA/Rego)

### 5.1 Policy Categories

| Category | Example Rules | Enforcement |
| --- | --- | --- |
| Region Restrictions | Allow only us-east-1, us-west-2, westus2 | Hard block |
| Instance Size Limits | Max m5.xlarge for Tier 2 apps | Hard block |
| Network Exposure | No public IPs without exception | Soft block + exception |
| Tagging Requirements | Require owner, cost-center, environment | Hard block |
| Cost Controls | Max $5000/month per resource group | Soft block + approval |
| Data Residency | PII data only in approved regions | Hard block |

### 5.2 Policy Evaluation Flow

```
1. Request submitted via portal
   |
2. API Server receives request
   |
3. Build OPA input document:
   - Request parameters
   - Application metadata
   - User context
   - Active exceptions
   |
4. Query OPA policy bundle:
   POST /v1/data/cloudforge/allow
   |
5. Process result:
   - allow = true -> Continue to provisioning
   - allow = false -> Check for valid exception
   - exception required -> Route to GRC workflow
```

### 5.3 Sample Rego Policy

```rego
package cloudforge.aws

import future.keywords.in

default allow := false

# Allow if all policies pass
allow {
    region_allowed
    instance_size_allowed
    tags_complete
}

# Region policy
region_allowed {
    input.request.region in data.allowed_regions
}

# Instance size policy
instance_size_allowed {
    tier := input.application.tier
    size := input.request.instance_type
    size in data.allowed_sizes[tier]
}

# Tagging policy
tags_complete {
    required := {"owner", "cost-center", "environment", "application-id"}
    provided := {tag | input.request.tags[tag]}
    required - provided == set()
}
```

---

## 6. GRC Integration Layer

### 6.1 Provider Interface

```go
type GRCProvider interface {
    // Exception management
    CreateException(ctx context.Context, req ExceptionRequest) (*Exception, error)
    GetException(ctx context.Context, id string) (*Exception, error)
    UpdateException(ctx context.Context, id string, status ExceptionStatus) error
    ListExceptions(ctx context.Context, filter ExceptionFilter) ([]Exception, error)
    
    // Validation
    ValidateException(ctx context.Context, policyID string, exceptionID string) (bool, error)
}
```

### 6.2 Supported Providers

| Provider | Status | Features |
| --- | --- | --- |
| RSA Archer | Implemented | Full exception lifecycle, approval workflows |
| ServiceNow GRC | Implemented | Exception records, CMDB integration |
| PostgreSQL | Implemented | Lightweight, self-contained option |
| In-Memory | Implemented | Testing and demos |

### 6.3 Exception Data Model

```go
type Exception struct {
    ID              string            `json:"id"`
    PolicyID        string            `json:"policy_id"`
    ApplicationID   string            `json:"application_id"`
    RequestedBy     string            `json:"requested_by"`
    BusinessJustification string      `json:"business_justification"`
    RiskAssessment  string            `json:"risk_assessment"`
    CompensatingControls []string     `json:"compensating_controls"`
    Status          ExceptionStatus   `json:"status"`
    ApprovedBy      string            `json:"approved_by,omitempty"`
    ExpiresAt       time.Time         `json:"expires_at"`
    CreatedAt       time.Time         `json:"created_at"`
    UpdatedAt       time.Time         `json:"updated_at"`
}
```

---

## 7. Golden Path Terraform Modules

### 7.1 Module Catalog

| Module | Cloud | Description |
| --- | --- | --- |
| web-app-standard | AWS | ALB + ECS Fargate + RDS PostgreSQL |
| web-app-standard | Azure | App Gateway + AKS + Azure SQL |
| data-lake | AWS | S3 + Glue + Athena |
| data-lake | GCP | GCS + BigQuery |
| api-gateway | AWS | API Gateway + Lambda + DynamoDB |
| kubernetes-cluster | Multi | EKS / AKS / GKE with standard config |

### 7.2 Module Versioning

- Semantic versioning (v1.2.3)
- Breaking changes require major version bump
- Security patches auto-applied to minor versions
- Deprecation notices 90 days before removal

---

## 8. Security Considerations

### 8.1 Authentication and Authorization

| Layer | Mechanism |
| --- | --- |
| Portal | OIDC (Okta / Azure AD) |
| API Server | JWT validation + RBAC |
| Service-to-Service | mTLS |
| Cloud Access | Workload Identity / IRSA |
| Secrets | HashiCorp Vault |

### 8.2 Audit Logging

All actions are logged with:
- Timestamp
- Actor (user or service)
- Action type
- Resource affected
- Request/response payloads (redacted)
- Source IP

---

## 9. Data Flow

### 9.1 Infrastructure Request Flow

```
1. Developer submits request via portal
   |
2. API Server validates request format
   |
3. Temporal workflow initiated
   |
4. OPA policy evaluation:
   ├── Pass -> Continue
   └── Fail -> Check exceptions or route to GRC
   |
5. Approval workflow (if required by policy)
   |
6. Terraform plan generated
   |
7. Plan reviewed and approved
   |
8. Terraform apply executed
   |
9. Resources recorded in CMDB
   |
10. Developer notified with access details
```

---

## 10. Future Enhancements

| Enhancement | Benefit | Complexity |
| --- | --- | --- |
| Cost Estimation | Show projected costs before approval | Medium |
| Drift Detection | Alert when resources deviate from Terraform | Medium |
| Self-Healing | Auto-remediate policy violations | High |
| Backstage Integration | Native plugin for developer portal | Medium |
| FinOps Integration | Anomaly detection, showback reports | Medium |

---

## 11. Reference

### 11.1 Technology Stack

| Layer | Technology |
| --- | --- |
| Language | Go 1.21+ |
| Portal | Backstage / React |
| Workflows | Temporal |
| Policies | OPA / Rego |
| IaC | Terraform |
| Database | PostgreSQL |
| Cache | Redis |
| Messaging | NATS |

### 11.2 Reference Links

- OPA Documentation: https://www.openpolicyagent.org/docs/latest/
- Temporal Documentation: https://docs.temporal.io/
- Backstage: https://backstage.io/docs/overview/what-is-backstage
- Terraform Modules: https://developer.hashicorp.com/terraform/language/modules

---

## Contact

**Author:** Liem Vo-Nguyen  
**Email:** liem@vonguyen.io  
**LinkedIn:** linkedin.com/in/liemvn

