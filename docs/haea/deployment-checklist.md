# HAEA Cloud Guard — Deployment Checklist

**Version:** 1.0
**Updated:** 2026-03-24
**Author:** Liem Vo-Nguyen
**Purpose:** One-shot provisioning guide for sit-downs with each admin team

---

## Pre-requisites

- [ ] HAEA security account access confirmed (831926608679 or dedicated account)
- [ ] GitLab repo: `haea-sec/cloudguard` — CI/CD pipelines configured
- [ ] All 4 AWS SSO sessions authenticated (`scripts/cloud-env-login.sh status`)
- [ ] Cost forecast reviewed and approved (~$368/mo pilot, ~$532/mo phase 1)

---

## Track 1: M365 / AD Team

**Sit-down duration:** ~30 min
**Contact:** TBD (Azure AD / M365 admin)

### App Registration

- [ ] Create Azure AD App Registration: `haea-cloud-guard`
  - Tenant: `bd29b3ab-aaa2-425a-b882-9e7f73283ca6` (HMGNA)
  - Single-tenant, Web application
  - Application ID URI: `api://{client-id}`
- [ ] Create client secret (12-month expiry, store in 1Password)
- [ ] Grant API permissions:
  - Microsoft Graph: `User.Read` (delegated)
  - No admin consent required for basic SSO

### Internal DNS

- [ ] Add A record on AD DNS server:
  - `cloudguard.haeaus.com` → `{internal deployment IP}`
  - Internal-only — NOT added to public DNS (Enom registrar untouched)
- [ ] Verify resolution from corporate network / VPN

### Conditional Access

- [ ] Create Conditional Access policy:
  - Name: `Cloud Guard — Security Team Only`
  - Target: Cloud Guard app registration
  - Users: Security TFT group (or specific users)
  - Conditions: Corporate network / VPN only
  - Grant: Require MFA

### Validation

- [ ] Navigate to `https://cloudguard.haeaus.com` from VPN — SSO prompt appears
- [ ] Non-security-team user is blocked by Conditional Access

---

## Track 2: AWS Team (per org — repeat 4x)

**Sit-down duration:** ~20 min per org (can batch if same admin)
**Contact:** TBD (AWS account admin per org)

### Org-level: SecurityHub Delegated Admin

- [ ] Identify or designate delegated admin account per org:

| Org | Audit Account (candidate) | Delegated Admin Status |
|-----|--------------------------|----------------------|
| HMA Legacy | 699798148919 (HAEAAudit) — SSO: `haea-aws-sso.awsapps.com` | [ ] Configured |
| KNA | TBD (12 hidden accs — need access expansion) — SSO: `d-9267fb4f9b.awsapps.com` | [ ] Configured |
| HMNA | 047618028274 (lza-haea-audit) — SSO: `d-92678cbdc7.awsapps.com` | [ ] Configured |
| HMGNA | 276934860623 (dev-lza-haea-audit) — SSO: `d-92678d8f7b.awsapps.com`, also has security acc 165641229246 | [ ] Configured |

- [ ] Enable SecurityHub in delegated admin account (if not already)
- [ ] Enable SecurityHub member account auto-enrollment

### Central Account (831926608679): OIDC Provider

- [ ] Create OIDC identity provider:
  ```
  Issuer URL: https://gitlab.com (or GitLab self-hosted URL)
  Audience:   sts.amazonaws.com
  Thumbprint: (get from GitLab issuer — see AWS_OIDC_Setup.md)
  ```
- [ ] Create app role: `haea-cg-prod-app`
  - Trust: OIDC provider (GitLab) + ECS tasks
  - Policy: `sts:AssumeRole` into all tenant reader roles

### Per-Tenant: Reader Role (repeat per member account)

- [ ] Create IAM role: `haea-cs-read-automation`
  - Trust: central app role (831926608679)
  - External ID: `haea-cg-cspm`
- [ ] Attach policy: 12 statements, 95 read-only actions
  - SecurityHub, Config, GuardDuty, IAM, EC2/RDS/S3, SSM, CloudTrail,
    Network Topology, ELB, Lambda/ECS/EKS, Access Analyzer, KMS/Secrets
  - Policy JSON: `terraform output cspm_reader_policy_json`
- [ ] **Validated:** 21/21 actions pass in test environment (2026-03-24)

### Validation

- [ ] From central account, AssumeRole into `haea-cs-read-automation` in tenant
- [ ] Call `securityhub:GetFindings` — returns findings (not AccessDenied)
- [ ] Call `iam:GetAccountSummary` — returns summary
- [ ] Call `cloudtrail:DescribeTrails` — returns trails

---

## Track 3: GCP Team

**Sit-down duration:** ~30 min
**Contact:** TBD (GCP org admin)

### Org Context

- Organization: `autoeveramerica.com` (single GCP org)
- 95 active projects across 5 brands (HMA 38, KUS 19, HMNA 12, Shared-Infra 18, HAEA 5)

### Enable APIs (org-level or per security project)

- [ ] `securitycenter.googleapis.com`
- [ ] `iam.googleapis.com`
- [ ] `cloudresourcemanager.googleapis.com`
- [ ] `compute.googleapis.com`
- [ ] `cloudasset.googleapis.com`

### Workload Identity Federation

- [ ] Create WIF pool: `haea-cg-cspm-pool`
  - Location: global
- [ ] Create WIF provider: `gitlab-oidc`
  - Issuer: `https://gitlab.com` (or self-hosted)
  - Attribute mapping: `google.subject=assertion.sub`
  - Attribute condition: repo filter for `haea-sec/cloudguard`

### Service Account

- [ ] Create SA: `haea-cg-cspm-reader@{project}.iam.gserviceaccount.com`
- [ ] Grant roles (org-level for full coverage, project-level for pilot):
  - `roles/securitycenter.findingsViewer`
  - `roles/iam.securityReviewer`
  - `roles/compute.viewer`
  - `roles/cloudasset.viewer`
- [ ] Bind WIF pool to service account (`roles/iam.workloadIdentityUser`)
- [ ] **Validated:** 4 roles bound in test environment (2026-03-24)

### Validation

- [ ] Impersonate SA: `gcloud ... --impersonate-service-account=SA_EMAIL`
- [ ] List SCC findings — succeeds
- [ ] List compute instances — succeeds
- [ ] Search all resources — succeeds

---

## Track 4: Azure Security Team

**Sit-down duration:** ~20 min
**Contact:** TBD (Azure subscription admin)

### Org Context

- Tenant: HMGNA (`bd29b3ab-aaa2-425a-b882-9e7f73283ca6`)
- 52 subscriptions (HMA, KUS, GUS, HAEA, HATCI, shared services)

### Service Principal

- [ ] Create App Registration: `haea-cloud-guard-reader`
  - Or reuse the SSO app registration from Track 1 with a separate client secret
- [ ] Create Service Principal from app registration
- [ ] Assign roles at management group or subscription scope:
  - `Security Reader` — Defender for Cloud findings, security alerts
  - `Reader` — resource inventory, network topology, policy compliance

### Per-Subscription (if not using management group)

- [ ] Repeat role assignment for each subscription in scope
- [ ] Start with pilot subscriptions:
  - `subs-hma-us-prod-01` (b4a93397)
  - `subs-kus-us-prod-01` (e0e16a0c)
  - `subs-haea-us-hub-01` (7f0ef750)

### Validation

- [ ] `az security alert list --subscription {id}` — succeeds
- [ ] `az security pricing list --subscription {id}` — succeeds
- [ ] `az vm list --subscription {id}` — succeeds
- [ ] `az policy assignment list --subscription {id}` — succeeds
- [ ] **Validated:** 10/10 actions pass in test environment (2026-03-24)

---

## Track 5: ECS Deployment (Security TFT — self)

**After Tracks 1-4 complete**

### Infrastructure

- [ ] Apply Terraform: `deploy/terraform/environments/haea/`
  - Backend: S3 state bucket (`haea-cg-tfstate`)
  - VPC: `10.40.0.0/16`, 3 subnets, NAT Gateway
  - ECS: API (2 vCPU/2 GB, min 2) + OPA sidecar
  - RDS: PostgreSQL 15, db.t3.medium, Multi-AZ
  - ElastiCache: Redis 7, cache.t3.small, 2 nodes
  - Secrets Manager: 11 secrets

### Configuration

- [ ] Populate Secrets Manager entries:
  - `DATABASE_URL`, `JWT_SECRET`, `REDIS_URL`
  - `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`
  - `BEDROCK_ACCESS_KEY`, `BEDROCK_SECRET_KEY`
  - `GREYOISE_API_KEY`, `HIBP_API_KEY`
  - `OTX_API_KEY`
- [ ] Set environment variables in ECS task definition:
  - `GRC_PROVIDER=postgres`
  - `IDENTITY_PROVIDER=okta`
  - `CONTAINER_SCANNER=trivy`
  - `FINOPS_PROVIDER=aws`
  - `AEGIS_AI_ENABLED=true`
  - `AEGIS_TRACING_ENABLED=true`

### Validation

- [ ] `curl https://cloudguard.haeaus.com/health` — returns `{"status":"healthy"}`
- [ ] Login via Azure AD SSO — dashboard loads
- [ ] SecurityHub findings visible from first onboarded accounts
- [ ] AI enrichment returns results (test single finding)

---

## Account Onboarding (Post-Deploy)

New accounts can be onboarded in <30 min per account:

1. Create `haea-cs-read-automation` role in target account (use policy JSON from TF output)
2. Add account to `aws_tenant_accounts` variable in Terraform
3. Apply Terraform (adds AssumeRole permission to central app role)
4. Findings appear in dashboard within next ingestion cycle (~15 min)

---

## Current Access Gaps

| Org | Gap | Action Required |
|-----|-----|----------------|
| KNA | 12/21 accounts hidden — zero operational accounts visible | Request access expansion from KNA org admin |
| HMNA | 21/35 accounts hidden | Request access expansion |
| HMGNA | 3/20 accounts hidden | Minor — most accounts visible |
| GCP | Org-level permissions limited (can't list folders) | Request `resourcemanager.folders.list` on org |

---

## Cost Summary

| Scenario | Monthly | Annual | When |
|----------|---------|--------|------|
| Pilot (26 HMA accounts) | $368 | $4,416 | Q2 2026 |
| Phase 1 (132 AWS accounts) | $532 | $6,384 | Q3 2026 |
| Full Scope (270 envs) | $1,665 | $19,980 | Q4 2026+ |

See [cost-forecast-20260325.md](cost-forecast-20260325.md) for detailed breakdown.
