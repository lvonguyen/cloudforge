# CSP Finding Schema Reference

**Last Updated:** 2026-02-26
**Purpose:** Maps each cloud provider's native security finding fields to the cspm-aggregator normalized `Finding` struct. Used to validate normalizer correctness and track API schema drift.

---

## Normalized Finding Struct

| Field | Type | Source: AWS | Source: Azure | Source: GCP |
|---|---|---|---|---|
| `finding_id` | string | `Id` (ARN) | `id` (ARM path) | `name` (resource path) |
| `finding_id_short` | string | SHA-256 dedupe hash | SHA-256 dedupe hash | SHA-256 dedupe hash |
| `csp` | string | `"aws"` | `"azure"` | `"gcp"` |
| `account_id` | string | `AwsAccountId` | `subscriptionId` (parsed from path) | `projects/{id}` (parsed from `resourceName`) |
| `resource_id` | string | `Resources[0].Id` | `resourceDetails.Id` | `resourceName` |
| `resource_type` | string | `Resources[0].Type` | `resourceDetails.ResourceType` | parsed from `resourceName` |
| `region` | string | `Region` (auto-populated) | parsed from resource (often empty) | parsed from `resourceName` (zones/locations/regions) |
| `title` | string | `Title` | `displayName` | `category` |
| `description` | string | `Description` (max 1024) | `metadata.description` | `description` |
| `severity` | enum | `Severity.Label` | `metadata.severity` (Critical/High/Medium/Low/N/A) | `severity` (CRITICAL/HIGH/MEDIUM/LOW/UNSPECIFIED) |
| `status` | enum | `Workflow.Status` mapped | `status.code` mapped (Unhealthy=ACTIVE) | `state` mapped (ACTIVE/INACTIVE) + `mute` override |
| `finding_class` | enum | derived from `Types[]` + `ProductArn` | `MISCONFIGURATION` (default for assessments) | `findingClass` (direct mapping) |
| `control_id` | string | `ProductFields.ControlId` or `GeneratorId` | `name` (assessment GUID) | `category` |
| `standard` | string | parsed from `ProductFields.StandardsArn` | `"MCSB"` (default) | `compliances[0].standard` or `"GCP-SHA"` |
| `compliance_standards` | []string | `Compliance.AssociatedStandards` parsed | `metadata.categories` with MCSB prefix | `compliances[]` (standard + version) |
| `remediation_url` | string | `Remediation.Recommendation.Url` | `metadata.remediationDescription` | `nextSteps` (text) |
| `risk_score` | float64 | `Criticality` (0-100) | `risk.level` mapped (High=80, Med=50, Low=20) | `attackExposure.score` |
| `ai_workload` | bool | keyword detection in title/type | keyword detection + resource type | `vertexAi` or `notebook` presence + keywords |
| `first_seen` | time | `FirstObservedAt` (fallback: `CreatedAt`) | `status.firstEvaluationDate` | `createTime` |
| `last_seen` | time | `LastObservedAt` (fallback: `UpdatedAt`) | `status.statusChangeDate` | `eventTime` |

---

## AWS Security Hub (ASFF)

**Schema Version:** `2018-10-08` (unchanged since launch)
**API:** `securityhub.GetFindings`

### Key Fields

| ASFF Field | Type | Notes |
|---|---|---|
| `Id` | string | Product-specific finding identifier (ARN) |
| `AwsAccountId` | string | 12-digit AWS account ID |
| `AwsAccountName` | string | Auto-populated (Nov 2023+), NOT updatable |
| `Title` | string | Max 256 chars |
| `Description` | string | Max 1024 chars |
| `Severity.Label` | enum | INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL |
| `Severity.Normalized` | int | 0-100 (deprecated, use Label) |
| `Severity.Original` | string | Native severity from source product |
| `Compliance.Status` | enum | PASSED, WARNING, FAILED, NOT_AVAILABLE |
| `Compliance.SecurityControlId` | string | Cross-standard control ID (e.g., IAM.1) |
| `Compliance.AssociatedStandards` | array | Standards that triggered this finding |
| `Workflow.Status` | enum | NEW, NOTIFIED, SUPPRESSED, RESOLVED |
| `RecordState` | enum | ACTIVE, ARCHIVED |
| `Resources[]` | array | Max 32 items; Type, Id, Region, Tags, Details |
| `GeneratorId` | string | Component that generated the finding |
| `ProductArn` | string | ARN of source product |
| `ProductFields` | map | Solution-specific metadata (ControlId, StandardsArn, etc.) |
| `Remediation.Recommendation.Url` | string | Link to remediation docs |
| `FirstObservedAt` | timestamp | When issue was first observed |
| `LastObservedAt` | timestamp | When issue was most recently observed |
| `Detection` | object | **NEW Dec 2024** — GuardDuty Extended Threat Detection attack sequences |

### Severity Mapping

| Label | Normalized Range | Auto-set |
|---|---|---|
| INFORMATIONAL | 0 | 0 |
| LOW | 1-39 | 1 |
| MEDIUM | 40-69 | 40 |
| HIGH | 70-89 | 70 |
| CRITICAL | 90-100 | 90 |

### Standard ARN Patterns

| Standard | ARN Contains |
|---|---|
| FSBP | `aws-foundational-security-best-practices` |
| CIS v1.2 | `cis-aws-foundations-benchmark/v/1.2.0` |
| CIS v3.0 | `cis-aws-foundations-benchmark/v/3.0.0` |
| CIS v5.0 | `cis-aws-foundations-benchmark/v/5.0.0` (Oct 2025) |
| PCI DSS v3.2.1 | `pci-dss/v/3.2.1` |
| PCI DSS v4.0.1 | `pci-dss/v/4.0.1` (Dec 2024) |
| NIST 800-53 | `nist-800-53/v/5.0.0` |
| NIST 800-171 | `nist-800-171/v/2.0.0` (May 2025) |

### Changes Since Mid-2025

- `Detection` object — GuardDuty attack sequence graph (actors, endpoints, signals)
- `CodeRepository` resource type — Inspector code repo scanning (Aug 2025)
- CIS v5.0.0 (40 controls), PCI DSS v4.0.1, NIST 800-171 Rev 2 standards
- No Bedrock/Q dedicated resource types (AI findings via GuardDuty ProductArn)
- `WorkflowState` deprecated (use `Workflow.Status`)
- `Network` object retired (use `Action`)

---

## Azure Defender for Cloud

**Stable API:** `2020-01-01`
**Preview API:** `2025-05-04-preview` (adds `risk` object)
**Resource Graph Table:** `securityresources` where `type == "microsoft.security/assessments"`

### Key Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Full ARM resource ID |
| `name` | string | Assessment GUID |
| `properties.displayName` | string | Recommendation title |
| `properties.status.code` | enum | Healthy, Unhealthy, NotApplicable |
| `properties.status.firstEvaluationDate` | datetime | Requires `$expand=statusEvaluationDates` or ARG |
| `properties.status.statusChangeDate` | datetime | Last status transition |
| `properties.metadata.severity` | enum | Low, Medium, High, **Critical** (2024+) |
| `properties.metadata.description` | string | Recommendation description |
| `properties.metadata.remediationDescription` | string | Fix steps |
| `properties.metadata.categories` | array | Compute, Networking, Data, IdentityAndAccess, IoT, AppServices, Container |
| `properties.metadata.threats` | array | accountBreach, dataExfiltration, elevationOfPrivilege, etc. |
| `properties.metadata.userImpact` | enum | Low, Moderate, High |
| `properties.metadata.implementationEffort` | enum | Low, Moderate, High |
| `properties.resourceDetails.Id` | string | Target resource ARM ID |
| `properties.resourceDetails.ResourceType` | string | ARM resource type |
| `properties.resourceDetails.source` | enum | Azure, OnPremise, OnPremiseSql, **Aws**, **Gcp** |
| `properties.risk` | object | **NEW 2025-05-04-preview** — attack path context |

### Severity Values

| Value | Since | Notes |
|---|---|---|
| Low | Launch | Minor issues |
| Medium | Launch | Moderate risk |
| High | Launch | Significant risk |
| Critical | 2024 | Immediately exploitable, high-impact (CVSS 9.0+) |
| N/A | Launch | Not applicable — normalize to LOW |

### Changes Since Mid-2025

- `Critical` severity level added (2024, now established)
- `risk` object — attack path graph, risk factors, risk level (2025-05-04-preview)
- AI assessments — 20+ new recs for Azure AI Foundry, Bedrock, Vertex AI
- MCSB v2 AI domain — 7 new controls (AI-1 through AI-7)
- Multi-cloud `resourceDetails` — `source: Aws` and `source: Gcp` with native IDs
- `assessmentType` enum expanded — BuiltInPolicy, DynamicBuiltIn, ManualBuiltIn, etc.
- K8S alert resourceIdentifiers changed to native cloud IDs (Oct 2025)
- SQL hardening — 80+ new recommendations (Feb 2026, Preview)

---

## GCP Security Command Center

**v1 API:** `securitycenter.googleapis.com/v1`
**v2 API:** `securitycenter.googleapis.com/v2` (adds `/locations/{loc}` in paths)
**CLI:** `gcloud scc findings list`

### Key Fields

| Field | Type | Notes |
|---|---|---|
| `name` | string | Resource path (v1: `org/src/finding`, v2: `org/src/loc/finding`) |
| `canonicalName` | string | Stable cross-version name |
| `category` | string | Finding category (e.g., PUBLIC_BUCKET_ACL) |
| `severity` | enum | CRITICAL, HIGH, MEDIUM, LOW, SEVERITY_UNSPECIFIED |
| `state` | enum | ACTIVE, INACTIVE |
| `findingClass` | enum | 10 values (see below) |
| `mute` | enum | MUTED, UNMUTED, UNDEFINED |
| `muteInfo` | object | **v2 only** — static + dynamic mute records |
| `resourceName` | string | Full GCP resource name |
| `description` | string | Human-readable description |
| `nextSteps` | string | Remediation guidance (text) |
| `createTime` | timestamp | When finding was created in SCC |
| `eventTime` | timestamp | When triggering event occurred |
| `compliances[]` | array | Standard, version, control IDs |
| `mitreAttack` | object | MITRE ATT&CK tactics and techniques |
| `vulnerability.cve` | object | CVE details with CVSS v3 |
| `attackExposure` | object | **v2** — score, exposed resource counts, state |
| `toxicCombination` | object | **v2** — attack exposure score + related findings |
| `chokepoint` | object | **v2** — convergence of attack paths |
| `securityPosture` | object | **v2** — posture drift details |
| `vertexAi` | object | **v2** — Vertex AI dataset/pipeline context |
| `notebook` | object | **v2** — Colab/Workbench notebook context |
| `kubernetes` | object | GKE context (pods, nodes, roles, bindings) |

### Finding Class Values (10 total)

| Value | Source | Notes |
|---|---|---|
| FINDING_CLASS_UNSPECIFIED | — | Default/unset |
| THREAT | ETD, CTD, VMTD, AETD | Active threats |
| VULNERABILITY | SHA, Container scan, Agentless | Software CVEs |
| MISCONFIGURATION | SHA, GKE Posture, DSPM | Config weaknesses |
| OBSERVATION | CIEM, audit | Informational |
| SCC_ERROR | SCC internal | Service errors |
| POSTURE_VIOLATION | Security Posture | Drift from posture (GA 2024) |
| TOXIC_COMBINATION | Attack path | Combined attack path (GA 2025) |
| SENSITIVE_DATA_RISK | DSPM | Data risk (GA 2025) |
| CHOKEPOINT | Attack path | Attack convergence point (GA 2025) |

### Changes Since Mid-2025

- v2 API path format — adds `/locations/{loc}` segment
- 4 new `findingClass` values — POSTURE_VIOLATION, TOXIC_COMBINATION, SENSITIVE_DATA_RISK, CHOKEPOINT
- `toxicCombination` + `chokepoint` objects — composite attack path findings
- `attackExposure` — risk scoring with exposed resource counts (GA 2025)
- `vertexAi` + `notebook` objects — AI workload context
- `securityPosture` — posture drift details
- `dataAccessEvents[]` / `dataFlowEvents[]` — DSPM events
- Agent Engine Threat Detection — 11+ new categories for AI agent runtime
- Cloud Run Threat Detection — 16 runtime detectors (Preview)
- AlloyDB misconfiguration detectors (GA 2025)
- Compliance Manager — new standards: HIPAA, SOC2, CSA CCM, GDPR
- Security marks no longer affect SHA detection (Apr 2025)

---

## Normalized CSV Export Format

The normalized output includes all Finding struct fields as CSV columns. URLs are stored as plain strings — CSV handles them natively per RFC 4180.

```csv
finding_id,finding_id_short,csp,account_id,resource_id,resource_type,region,title,description,severity,status,finding_class,control_id,standard,compliance_standards,remediation_url,risk_score,ai_workload,cbu,tier,env_type,owner,first_seen,last_seen,asana_task_id,remediation_sla,delta_status,days_open
```

### Severity Normalization Rules

| CSP | Raw Value | Normalized |
|---|---|---|
| AWS | INFORMATIONAL | LOW |
| AWS | LOW/MEDIUM/HIGH/CRITICAL | As-is (uppercase) |
| Azure | Low/Medium/High/Critical | Uppercase |
| Azure | N/A or empty | LOW |
| GCP | SEVERITY_UNSPECIFIED | LOW |
| GCP | LOW/MEDIUM/HIGH/CRITICAL | As-is |

### Status Normalization Rules

| CSP | Raw Value | Normalized |
|---|---|---|
| AWS | Workflow.Status=NEW or NOTIFIED, RecordState=ACTIVE | ACTIVE |
| AWS | Workflow.Status=RESOLVED | RESOLVED |
| AWS | Workflow.Status=SUPPRESSED | SUPPRESSED |
| Azure | status.code=Unhealthy | ACTIVE |
| Azure | status.code=Healthy | RESOLVED |
| Azure | status.code=NotApplicable | SUPPRESSED |
| GCP | state=ACTIVE | ACTIVE |
| GCP | state=INACTIVE | RESOLVED |
| GCP | mute=MUTED (overrides state) | SUPPRESSED |
