# FP/FN Training Data Quality Review

**Reviewer:** Opus 4.6 (automated quality pipeline)
**Date:** 2026-02-27
**Dataset:** 931 samples across 8 sectors
**Verdict:** CONDITIONAL PASS (3.61/5.0)

---

## Summary Statistics

| Sector | n | FP | FN | FP% | AWS% | Azure% | GCP% | Classes | Envs | Conf | Quality |
|--------|---|----|----|-----|------|--------|------|---------|------|------|---------|
| automotive | 151 | 109 | 42 | 72.2% | 52.3% | 22.5% | 25.2% | 19 | 2 | 0.906 | 3.54/5 |
| education | 110 | 74 | 36 | 67.3% | 71.8% | 12.7% | 15.5% | 15 | 4 | 0.897 | 3.52/5 |
| energy | 110 | 84 | 26 | 76.4% | 34.5% | 33.6% | 31.8% | 8 | 1 | 0.891 | 3.82/5 |
| financial | 110 | 71 | 39 | 64.5% | 55.5% | 21.8% | 22.7% | 14 | 3 | 0.871 | 3.62/5 |
| government | 116 | 80 | 36 | 69.0% | 57.8% | 24.1% | 18.1% | 27 | 2 | 0.909 | 3.42/5 |
| healthcare | 110 | 74 | 36 | 67.3% | 46.4% | 27.3% | 26.4% | 11 | 3 | 0.901 | 3.84/5 |
| retail | 114 | 78 | 36 | 68.4% | 66.7% | 14.9% | 18.4% | 11 | 3 | 0.891 | 3.61/5 |
| saas | 110 | 75 | 35 | 68.2% | 58.2% | 12.7% | 29.1% | 11 | 4 | 0.9 | 3.54/5 |
| **TOTAL** | **931** | **645** | **286** | **69.3%** | — | — | — | — | — | — | **3.61/5** |

---

## 1. Schema Validation

**Status:** All 931 samples now pass schema validation (0 remaining issues).
**Total auto-fixes applied:** 237

### Fix Summary

| Fix Category | Count | Sectors Affected |
|-------------|-------|------------------|
| `severity INFO -> INFORMATIONAL` | 96 | automotive (48), energy (48) |
| `severity NOT_FOUND -> NONE` | 19 | automotive (19) |
| `null edge_case -> EC-UNCLASSIFIED` | 122 | financial (37), government (85) |

### Required Fields (all present in every sample)

`id`, `sector`, `type`, `edge_case`, `csp`, `finding_type`, `finding_class`, `severity_reported`, `severity_actual`, `resource_type`, `environment`, `compliance_frameworks`, `scenario`, `why_misclassified`, `detection_signal`, `ground_truth`, `remediation_impact`, `confidence`

### Type Constraints Verified

- `type`: all values in {"false_positive", "false_negative"}
- `csp`: all values in {"aws", "azure", "gcp"}
- `severity_reported` / `severity_actual`: all values in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "INFORMATIONAL"}
- `confidence`: all float values in [0.0, 1.0]
- `compliance_frameworks`: all list type


---

## 2. Deduplication

| Check | Result |
|-------|--------|
| Exact ID duplicates (within file) | 0 |
| Exact ID duplicates (across files) | 0 |
| Samples removed | 0 |

All 931 sample IDs are unique within and across all 8 sector files. No exact duplicates found.

### Near-Duplicate Clusters (25 informational)

25 clusters share the same `finding_type` + `resource_type` + `type` within the same sector. These are **not removed** because their scenarios describe legitimately different situations (different resource names, environments, or business contexts). Examples:

| Cluster | Shared Pattern | IDs |
|---------|---------------|-----|
| 1 | `OPEN_SECURITY_GROUP` + `aws_security_group` | `FP-AUTO-001`, `FP-AUTO-004`, `FP-AUTO-017`, `FP-AUTO-046`, `FP-AUTO-058` |
| 2 | `OPEN_SECURITY_GROUP` + `aws_security_group` | `FP-HEALTH-004`, `FP-HEALTH-019`, `FP-HEALTH-054` |
| 3 | `VULNERABLE_DEPENDENCY` + `aws_lambda_function` | `FP-AUTO-010`, `FP-AUTO-022`, `FP-AUTO-050` |
| 4 | `OPEN_FIREWALL_RULE` + `gcp_compute_firewall` | `FP-AUTO-011`, `FP-AUTO-052` |
| 5 | `VULNERABLE_DEPENDENCY` + `aws_ecr_image` | `FP-AUTO-034`, `FP-AUTO-037` |
| 6 | `VULNERABLE_DEPENDENCY` + `gcp_cloud_run_service` | `FP-AUTO-043`, `FP-AUTO-056` |
| 7 | `RDS_PUBLICLY_ACCESSIBLE` + `aws_db_instance` | `FP-FIN-002`, `FP-FIN-046` |
| 8 | `S3_BUCKET_PUBLIC_READ_ACCESS` + `aws_s3_bucket` | `FN-EDU-026`, `FN-EDU-029` |
| 9 | `ECR_IMAGE_HIGH_CVE` + `aws_ecr_repository` | `FP-EDU-040`, `FP-EDU-056` |
| 10 | `CVE_IN_DEPENDENCY` + `aws_lambda_function` | `FP-FIN-014`, `FP-FIN-031` |

*... and 15 more clusters. All verified as distinct scenarios.*


---

## 3. Distribution Analysis

**Targets:** FP/FN ~70/30 (+/-15%), AWS ~40%, Azure ~35%, GCP ~25% (+/-10%)

### Automotive (n=151)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 109/42 (72.2%/27.8%) | PASS |
| CSP | AWS 52.3% / Azure 22.5% / GCP 25.2% | DEVIATION |
| Severity (reported) | {'HIGH': 80, 'CRITICAL': 12, 'MEDIUM': 18, 'NONE': 19, 'LOW': 12, 'INFORMATIONAL': 10} | — |
| Severity (actual) | {'LOW': 52, 'INFORMATIONAL': 50, 'MEDIUM': 8, 'HIGH': 29, 'CRITICAL': 12} | — |
| Finding classes | 19: API_SECURITY, ATTACK_SURFACE, AVAILABILITY, COMPLIANCE_VIOLATION, CONTAINER_SECURITY, CREDENTIAL_MANAGEMENT, CSPM_OPERATIONAL, DATA_EXPOSURE, DATA_PROTECTION, ENCRYPTION, ENCRYPTION_IN_TRANSIT, IAM, IAM_MISCONFIGURATION, KEY_MANAGEMENT, LOGGING_MONITORING, NETWORK_EXPOSURE, SUPPLY_CHAIN, VULNERABILITY, VULNERABILITY_MANAGEMENT | PASS |
| Environments | 2: dev, prod | PASS |
| Confidence | avg=0.906, range=[0.83, 0.98] | — |
| EC-UNCLASSIFIED | 0 samples | OK |

### Education (n=110)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 74/36 (67.3%/32.7%) | PASS |
| CSP | AWS 71.8% / Azure 12.7% / GCP 15.5% | DEVIATION |
| Severity (reported) | {'CRITICAL': 11, 'HIGH': 46, 'MEDIUM': 17, 'NONE': 33, 'LOW': 3} | — |
| Severity (actual) | {'NONE': 51, 'LOW': 21, 'MEDIUM': 3, 'CRITICAL': 11, 'HIGH': 24} | — |
| Finding classes | 15: AUTHENTICATION, CONFIGURATION, DATA_EXPOSURE, DATA_INTEGRITY, ENCRYPTION, HYGIENE, IDENTITY_ACCESS, LOGGING, MONITORING, NETWORK_EXPOSURE, RESILIENCE, SECRETS_MANAGEMENT, SUPPLY_CHAIN, THREAT_DETECTION, VULNERABILITY | PASS |
| Environments | 4: dev, prod, sandbox, staging | PASS |
| Confidence | avg=0.897, range=[0.76, 0.99] | — |
| EC-UNCLASSIFIED | 0 samples | OK |

### Energy (n=110)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 84/26 (76.4%/23.6%) | PASS |
| CSP | AWS 34.5% / Azure 33.6% / GCP 31.8% | PASS |
| Severity (reported) | {'HIGH': 56, 'CRITICAL': 3, 'MEDIUM': 23, 'INFORMATIONAL': 14, 'LOW': 14} | — |
| Severity (actual) | {'LOW': 47, 'INFORMATIONAL': 34, 'CRITICAL': 7, 'HIGH': 19, 'MEDIUM': 3} | — |
| Finding classes | 8: COMPLIANCE_VIOLATION, CONTAINER_SECURITY, DATA_EXPOSURE, ENCRYPTION, IAM_MISCONFIGURATION, LOGGING_MONITORING, NETWORK_EXPOSURE, VULNERABILITY | PASS |
| Environments | 1: prod | LOW |
| Confidence | avg=0.891, range=[0.83, 0.97] | — |
| EC-UNCLASSIFIED | 0 samples | OK |

### Financial (n=110)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 71/39 (64.5%/35.5%) | PASS |
| CSP | AWS 55.5% / Azure 21.8% / GCP 22.7% | DEVIATION |
| Severity (reported) | {'CRITICAL': 16, 'HIGH': 42, 'MEDIUM': 14, 'NONE': 22, 'LOW': 16} | — |
| Severity (actual) | {'NONE': 46, 'LOW': 22, 'MEDIUM': 5, 'HIGH': 25, 'CRITICAL': 12} | — |
| Finding classes | 14: APPLICATION_VULNERABILITY, COMPLIANCE_DRIFT, CONTAINER_VULNERABILITY, DATA_EXPOSURE, ENCRYPTION_WEAKNESS, IAM_MISCONFIGURATION, IDENTITY_RISK, MISCONFIGURATION, NETWORK_EXPOSURE, OS_VULNERABILITY, RESOURCE_ANOMALY, RUNTIME_VULNERABILITY, SUPPLY_CHAIN_RISK, THREAT | PASS |
| Environments | 3: dev, prod, staging | PASS |
| Confidence | avg=0.871, range=[0.77, 0.98] | — |
| EC-UNCLASSIFIED | 37 samples | NEEDS TAGGING |

### Government (n=116)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 80/36 (69.0%/31.0%) | PASS |
| CSP | AWS 57.8% / Azure 24.1% / GCP 18.1% | DEVIATION |
| Severity (reported) | {'CRITICAL': 10, 'HIGH': 48, 'MEDIUM': 20, 'LOW': 2, 'NONE': 36} | — |
| Severity (actual) | {'NONE': 64, 'LOW': 15, 'HIGH': 26, 'CRITICAL': 11} | — |
| Finding classes | 27: ASSET_MANAGEMENT, COMPLIANCE, COMPLIANCE_VIOLATION, COMPUTE_SECURITY, CONFIGURATION_DRIFT, CRYPTOGRAPHY, DATABASE_EXPOSURE, DATA_CLASSIFICATION, DATA_EXPOSURE, DATA_GOVERNANCE, DATA_PROTECTION, ENCRYPTION, IDENTITY_ACCESS, IDENTITY_FEDERATION, LOGGING_INTEGRITY, LOGGING_MONITORING, NETWORK_EXPOSURE, NETWORK_RESILIENCE, NETWORK_SECURITY, PATCH_MANAGEMENT, POLICY_VIOLATION, SECRETS_MANAGEMENT, SECURITY_COVERAGE, STORAGE_EXPOSURE, THREAT_DETECTION, VULNERABILITY, VULNERABILITY_MANAGEMENT | PASS |
| Environments | 2: dev, prod | PASS |
| Confidence | avg=0.909, range=[0.84, 0.99] | — |
| EC-UNCLASSIFIED | 85 samples | NEEDS TAGGING |

### Healthcare (n=110)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 74/36 (67.3%/32.7%) | PASS |
| CSP | AWS 46.4% / Azure 27.3% / GCP 26.4% | PASS |
| Severity (reported) | {'CRITICAL': 18, 'HIGH': 46, 'MEDIUM': 10, 'NONE': 28, 'LOW': 8} | — |
| Severity (actual) | {'NONE': 53, 'LOW': 19, 'MEDIUM': 2, 'CRITICAL': 10, 'HIGH': 26} | — |
| Finding classes | 11: COMPLIANCE_VIOLATION, CONTAINER_SECURITY, CRYPTOMINING, DATA_EXPOSURE, ENCRYPTION, IAM_MISCONFIGURATION, KUBERNETES_ANOMALY, LOGGING_MONITORING, MALWARE, NETWORK_EXPOSURE, VULNERABILITY | PASS |
| Environments | 3: dev, prod, staging | PASS |
| Confidence | avg=0.901, range=[0.82, 0.98] | — |
| EC-UNCLASSIFIED | 0 samples | OK |

### Retail (n=114)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 78/36 (68.4%/31.6%) | PASS |
| CSP | AWS 66.7% / Azure 14.9% / GCP 18.4% | DEVIATION |
| Severity (reported) | {'CRITICAL': 10, 'HIGH': 49, 'MEDIUM': 19, 'NONE': 29, 'LOW': 7} | — |
| Severity (actual) | {'NONE': 48, 'LOW': 25, 'MEDIUM': 5, 'HIGH': 28, 'CRITICAL': 8} | — |
| Finding classes | 11: AUDIT_LOGGING, CONFIGURATION, DATA_CLASSIFICATION, DATA_EXPOSURE, IAM_OVERPERMISSION, NETWORK_EXPOSURE, RESOURCE_ANOMALY, SEVERITY_MISCALIBRATION, SUPPLY_CHAIN, THREAT_DETECTION, VULNERABILITY | PASS |
| Environments | 3: dev, prod, staging | PASS |
| Confidence | avg=0.891, range=[0.8, 0.97] | — |
| EC-UNCLASSIFIED | 0 samples | OK |

### Saas (n=110)

| Metric | Value | Status |
|--------|-------|--------|
| FP/FN | 75/35 (68.2%/31.8%) | PASS |
| CSP | AWS 58.2% / Azure 12.7% / GCP 29.1% | DEVIATION |
| Severity (reported) | {'HIGH': 54, 'CRITICAL': 7, 'MEDIUM': 13, 'NONE': 29, 'LOW': 7} | — |
| Severity (actual) | {'NONE': 50, 'LOW': 20, 'HIGH': 32, 'CRITICAL': 4, 'MEDIUM': 4} | — |
| Finding classes | 11: AUDIT_LOGGING, CONFIGURATION, DATA_CLASSIFICATION, DATA_EXPOSURE, IAM_OVERPERMISSION, NETWORK_EXPOSURE, RESOURCE_ANOMALY, SEVERITY_MISCALIBRATION, SUPPLY_CHAIN, THREAT_DETECTION, VULNERABILITY | PASS |
| Environments | 4: dev, prod, sandbox, staging | PASS |
| Confidence | avg=0.9, range=[0.82, 0.97] | — |
| EC-UNCLASSIFIED | 0 samples | OK |

### CSP Balance Summary

| Sector | AWS | Azure | GCP | Verdict |
|--------|-----|-------|-----|---------|
| automotive | 52.3% | 22.5% | 25.2% | NEEDS REBALANCE |
| education | 71.8% | 12.7% | 15.5% | NEEDS REBALANCE |
| energy | 34.5% | 33.6% | 31.8% | PASS |
| financial | 55.5% | 21.8% | 22.7% | NEEDS REBALANCE |
| government | 57.8% | 24.1% | 18.1% | NEEDS REBALANCE |
| healthcare | 46.4% | 27.3% | 26.4% | PASS |
| retail | 66.7% | 14.9% | 18.4% | NEEDS REBALANCE |
| saas | 58.2% | 12.7% | 29.1% | NEEDS REBALANCE |

**6/8 sectors** deviate from target CSP distribution. Primary issue: AWS over-representation in retail (66.7%), education (71.8%), government (57.8%), saas (58.2%).


---

## 4. Quality Audit (80 samples, 10 per sector)

Deterministic sampling (seed=42). Four dimensions scored 1-5:

| Sector | Realism | Specificity | Misclass Logic | Remediation | Overall |
|--------|---------|-------------|----------------|-------------|---------|
| automotive | 3.5 | 3.4 | 4.3 | 3.77 | 3.74 |
| education | 3.5 | 3.24 | 4.3 | 3.85 | 3.72 |
| energy | 3.55 | 3.6 | 4.3 | 3.82 | 3.82 |
| financial | 3.55 | 3.53 | 4.24 | 3.95 | 3.82 |
| government | 3.55 | 3.1 | 4.06 | 3.77 | 3.62 |
| healthcare | 3.6 | 3.5 | 4.35 | 3.9 | 3.84 |
| retail | 3.5 | 3.61 | 4.3 | 3.85 | 3.81 |
| saas | 3.4 | 3.35 | 4.35 | 3.87 | 3.74 |
| **Average** | **3.52** | **3.42** | **4.27** | **3.85** | **3.76** |

**Scoring Methodology:**
- **Realism (avg 3.52):** Concrete identifiers (ARNs, VPCs), financial impact, scenario depth
- **Specificity (avg 3.42):** Detection signals with real resource IDs, IPs, ports, SG refs
- **Misclassification Logic (avg 4.27):** Reasoning depth, scanner limitation references, edge case tagging
- **Remediation Impact (avg 3.85):** Business impact quantification (revenue, users, compliance risk)

**Strongest dimension:** Misclassification Logic (4.27/5) — most samples provide solid reasoning for why the scanner gets it wrong.
**Weakest dimension:** Specificity (3.42/5) — some detection signals use generic identifiers instead of realistic ARNs/subscription IDs.


---

## 5. Top 5 Strongest Samples

### 1. `FN-ENERGY-029` (energy) — 4.08/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 4.0 |
| Specificity | 4.2 |
| Misclass Logic | 4.3 |
| Remediation | 3.8 |

- **Type:** false_negative | **CSP:** aws | **Finding:** OVERLY_BROAD_NSG_RULE
- **Scenario:** Security group sg-ems-admin allows RDP (TCP 3389) from 10.0.0.0/8. CSPM reports LOW (private source range). The 10.0.0.0/8 range encompasses the full corporate network including contractor VPN pools and vendor access networks. The protected EC2 instance runs the Energy Management System configuratio
- **Why strong:** Concrete resource identifiers, realistic blast radius, well-reasoned FP/FN logic

### 2. `FP-FIN-020` (financial) — 4.03/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 3.5 |
| Specificity | 3.5 |
| Misclass Logic | 4.3 |
| Remediation | 4.8 |

- **Type:** false_positive | **CSP:** azure | **Finding:** AZURE_SQL_AUDITING_DISABLED
- **Scenario:** Azure Defender reports SQL auditing disabled on a staging database server used for QA testing of the trade reconciliation system. The database is populated exclusively with synthetic trading data generated by the bank's test data management platform. No real customer or financial records are present
- **Why strong:** Concrete resource identifiers, realistic blast radius, well-reasoned FP/FN logic

### 3. `FN-HEALTH-107` (healthcare) — 4.03/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 4.0 |
| Specificity | 3.5 |
| Misclass Logic | 4.3 |
| Remediation | 4.3 |

- **Type:** false_negative | **CSP:** gcp | **Finding:** GCP_CLOUD_SQL_BACKUP_DISABLED
- **Scenario:** GCP SCC shows a Cloud SQL instance hosting patient records as compliant for automated backups. A Cloud SQL maintenance update 50 days ago introduced a bug that silently disabled automated backups on instances with custom backup windows outside business hours. The compliance check reflects the pre-up
- **Why strong:** Concrete resource identifiers, realistic blast radius, well-reasoned FP/FN logic

### 4. `FP-FIN-044` (financial) — 3.97/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 4.0 |
| Specificity | 3.8 |
| Misclass Logic | 4.3 |
| Remediation | 3.8 |

- **Type:** false_positive | **CSP:** aws | **Finding:** FINDING_STATUS_REOPENED
- **Scenario:** Security Hub shows a previously resolved finding as REOPENED for S3 bucket versioning on the audit log bucket. The finding was remediated and resolved at 11:58 PM EST. The CSPM re-scans at midnight UTC (7 PM EST). The scan sees the bucket configuration at a time 5 hours before the remediation timest
- **Why strong:** Concrete resource identifiers, realistic blast radius, well-reasoned FP/FN logic

### 5. `FP-RETAIL-006` (retail) — 3.97/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 3.5 |
| Specificity | 4.3 |
| Misclass Logic | 4.3 |
| Remediation | 3.8 |

- **Type:** false_positive | **CSP:** aws | **Finding:** CROSS_ACCOUNT_ACCESS
- **Scenario:** IAM role 'payment-processor-integration-role' has cross-account trust policy allowing account 123456789012 (Stripe's AWS account) to assume it. Scanner flags as HIGH severity cross-account access risk.
- **Why strong:** Concrete resource identifiers, realistic blast radius, well-reasoned FP/FN logic


---

## 6. Top 5 Weakest Samples

### 1. `FP-GOV-078` (government) — 3.58/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 3.5 |
| Specificity | 3.0 |
| Misclass Logic | 4.0 |
| Remediation | 3.8 |

- **Type:** false_positive | **CSP:** gcp | **Finding:** GCP_BUCKET_RETENTION_POLICY_MISSING
- **Scenario:** SCC flags a GCS bucket in Assured Workloads project as missing a retention policy. The bucket stores temporary processing artifacts that are deleted immediately after downstream processing completes — typically within 60 seconds. A retention policy would prevent deletion of these short-lived objects
- **Improvement:** Add concrete resource identifiers (ARN/subscription ID), quantify blast radius, deepen misclassification reasoning

### 2. `FP-GOV-034` (government) — 3.58/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 3.5 |
| Specificity | 3.0 |
| Misclass Logic | 4.0 |
| Remediation | 3.8 |

- **Type:** false_positive | **CSP:** azure | **Finding:** AZURE_KEYVAULT_PUBLIC_NETWORK_ACCESS
- **Scenario:** Defender flags an Azure Government Key Vault as allowing public network access. The Key Vault has public access enabled but IP firewall rules restrict access to the agency MPLS egress IPs and an ExpressRoute private endpoint. The public access flag refers to the endpoint type, not unrestricted publi
- **Improvement:** Add concrete resource identifiers (ARN/subscription ID), quantify blast radius, deepen misclassification reasoning

### 3. `FP-GOV-103` (government) — 3.58/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 3.5 |
| Specificity | 3.0 |
| Misclass Logic | 4.0 |
| Remediation | 3.8 |

- **Type:** false_positive | **CSP:** aws | **Finding:** DIRECT_CONNECT_NO_BACKUP
- **Scenario:** Config flags a GovCloud Direct Connect connection as lacking a backup connection. The agency uses a dual-carrier MPLS network with automatic failover — the second carrier also terminates via Direct Connect at a different colocation facility. The backup Direct Connect exists under a different connect
- **Improvement:** Add concrete resource identifiers (ARN/subscription ID), quantify blast radius, deepen misclassification reasoning

### 4. `FP-SAAS-011` (saas) — 3.53/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 3.0 |
| Specificity | 3.0 |
| Misclass Logic | 4.3 |
| Remediation | 3.8 |

- **Type:** false_positive | **CSP:** aws | **Finding:** TEST_FRAMEWORK_CVE
- **Scenario:** ECR scan flags production container image saas-api:v8.4.2 for CVE-2024-21538 (ReDoS in jest) as HIGH. Container is the production API service.
- **Improvement:** Add concrete resource identifiers (ARN/subscription ID), quantify blast radius, deepen misclassification reasoning

### 5. `FP-GOV-012` (government) — 3.5/5.0

| Dimension | Score |
|-----------|-------|
| Realism | 3.5 |
| Specificity | 3.0 |
| Misclass Logic | 4.0 |
| Remediation | 3.5 |

- **Type:** false_positive | **CSP:** aws | **Finding:** GUARDDUTY_POLICY_BUCKET_BLOCK_PUBLIC_DISABLED
- **Scenario:** GuardDuty raises Policy:S3/BucketBlockPublicAccessDisabled for an S3 bucket in GovCloud. The bucket is the agency CDN origin for public-facing web content hosted behind CloudFront with WAF. Block-public-access is intentionally disabled because CloudFront OAI requires direct bucket access for content
- **Improvement:** Add concrete resource identifiers (ARN/subscription ID), quantify blast radius, deepen misclassification reasoning


---

## 7. Overall Assessment

| Metric | Value |
|--------|-------|
| Total samples | 931 |
| Sectors | 8 |
| Schema issues fixed | 237 (0 remaining) |
| Duplicates found | 0 |
| Near-duplicate clusters | 25 (informational) |
| Global FP/FN ratio | 645/286 (69.3%/30.7%) |
| CSP sectors meeting target | 2/8 |
| Average quality score | 3.61/5.0 |
| Average confidence | 0.896 |

### Verdict: CONDITIONAL PASS (3.61/5.0)

Training data is usable for ML training. All schema issues resolved. FP/FN ratios on target. Primary improvement area: CSP balance (6/8 sectors skew toward AWS) and detection signal specificity.

### Recommendations

1. **CSP rebalancing (P1):** 6 sectors over-index on AWS. Add Azure/GCP samples for retail, education, government, SaaS, financial to hit 40/35/25 target.
2. **Edge case tagging (P2):** 122 samples tagged `EC-UNCLASSIFIED` (financial: 37, government: 85). Map these to specific EC-* codes from the CSPM rule engine.
3. **Specificity lift (P2):** Lowest audit dimension at 3.42/5. Enrich detection signals with realistic ARNs, subscription IDs, and project paths.
4. **Environment diversity (P3):** Energy (1 env), automotive (2 envs), government (2 envs) lack environment variety. Add staging, DR, shared-services scenarios.
5. **Confidence review (P3):** All samples have high confidence (0.76-0.99). Consider adding ambiguous cases (0.5-0.7) where FP/FN classification is genuinely debatable.

### Files Modified

| File | Samples | Changes |
|------|---------|---------|
| `automotive.json` | 151 | 48 INFO->INFORMATIONAL, 19 NOT_FOUND->NONE |
| `education.json` | 110 | No changes |
| `energy.json` | 110 | 48 INFO->INFORMATIONAL |
| `financial.json` | 110 | 37 null edge_case->EC-UNCLASSIFIED |
| `government.json` | 116 | 85 null edge_case->EC-UNCLASSIFIED |
| `healthcare.json` | 110 | No changes |
| `retail.json` | 114 | No changes |
| `saas.json` | 110 | No changes |
| `all_sectors.json` | 931 | **NEW** — consolidated, sorted by sector+type+ID |
| `REVIEW.md` | — | **NEW** — this report |

---

*Generated by Opus 4.6 quality review pipeline.*
