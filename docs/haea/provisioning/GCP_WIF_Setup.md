# GCP Workload Identity Federation — HAEA Cloud Guard (v2)

| Property | Value |
|----------|-------|
| Version | 2.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | March 2026 |
| Status | Active |
| Owner | GCP Team |
| IaC Source | `deploy/terraform/environments/haea/main.tf` (GCP section planned) |

---

## 1. Account Context

| Property | Value |
|----------|-------|
| GCP Organization | haea.com (95 projects) |
| Security Project | prj-haea-security (or designated GCP project) |
| WIF Pool ID | haea-cg-cspm-pool |
| WIF Provider | aws-oidc |
| Service Account | sa-cg-reader@{project}.iam.gserviceaccount.com |

---

## 2. Architecture — AWS-to-GCP Federation (v2)

Cloud Guard runs on AWS ECS Fargate. GCP access uses Workload Identity Federation to trust the AWS ECS task role, eliminating service account keys.

```
ECS Task (AWS, 831926608679)
  |
  | AWS STS credentials (from haea-cg-prod-app role)
  v
GCP Security Token Service
  | Token exchange (AWS → GCP)
  v
GCP WIF Pool: haea-cg-cspm-pool
  | Provider: aws-oidc (trusts AWS account 831926608679)
  v
Service Account: sa-cg-reader
  | Impersonation (workloadIdentityUser)
  v
GCP APIs: SCC, IAM, Compute, Cloud Asset
```

**Why AWS→GCP federation?**
- No service account keys to store or rotate
- Short-lived credentials (1 hour)
- Compute runs on AWS — the ECS task role IS the identity
- Adding GCP projects doesn't require AWS reconfiguration

**Changed from v1:**
- v1 used Azure ACI → Azure AD → GCP WIF (Azure AD as OIDC provider)
- v2 uses AWS ECS → AWS STS → GCP WIF (AWS as identity provider)

---

## 3. Service Account Roles — 4 Reader Roles

Validated in `lvn-dev-483106` (test project). All roles are read-only.

| Role | Purpose |
|------|---------|
| `roles/securitycenter.findingsViewer` | Read SCC findings + sources |
| `roles/iam.securityReviewer` | Read IAM policies, roles, service accounts |
| `roles/compute.viewer` | Read compute instances, networks, firewalls |
| `roles/cloudasset.viewer` | Read Cloud Asset Inventory (resource + policy search) |

**Scope:** Organization-level (covers all 95 projects). If org-level is not approved, apply per-project.

---

## 4. One-Shot Provisioning Checklist

### Prerequisites

- [ ] `gcloud` CLI authenticated with org admin or project owner
- [ ] GCP project ID designated for WIF pool (e.g., `prj-haea-security`)
- [ ] AWS central app role ARN: `arn:aws:iam::831926608679:role/haea-cg-prod-app`
- [ ] AWS account ID: `831926608679`

### Step 4.1: Create Service Account

```bash
PROJECT_ID="prj-haea-security"  # Replace with actual
gcloud config set project "$PROJECT_ID"

gcloud iam service-accounts create sa-cg-reader \
  --display-name="Cloud Guard CSPM Reader" \
  --description="Read-only service account for multi-cloud CSPM finding ingestion"

SA_EMAIL="sa-cg-reader@${PROJECT_ID}.iam.gserviceaccount.com"
echo "Service Account: $SA_EMAIL"
```

### Step 4.2: Create WIF Pool

```bash
gcloud iam workload-identity-pools create haea-cg-cspm-pool \
  --location="global" \
  --display-name="HAEA Cloud Guard CSPM" \
  --description="WIF pool for AWS ECS task federation"
```

### Step 4.3: Create AWS Provider

```bash
AWS_ACCOUNT_ID="831926608679"

gcloud iam workload-identity-pools providers create-aws aws-oidc \
  --location="global" \
  --workload-identity-pool="haea-cg-cspm-pool" \
  --display-name="AWS Central Security Account" \
  --account-id="$AWS_ACCOUNT_ID" \
  --attribute-mapping="google.subject=assertion.arn,attribute.aws_role=assertion.arn"
```

### Step 4.4: Grant Service Account Impersonation

```bash
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')

gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/haea-cg-cspm-pool/attribute.aws_role/arn:aws:sts::${AWS_ACCOUNT_ID}:assumed-role/haea-cg-prod-app"
```

### Step 4.5: Grant Reader Roles (org-level)

```bash
ORG_ID="REPLACE_WITH_ORG_ID"

for ROLE in \
  roles/securitycenter.findingsViewer \
  roles/iam.securityReviewer \
  roles/compute.viewer \
  roles/cloudasset.viewer; do
  gcloud organizations add-iam-policy-binding "$ORG_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="$ROLE"
done
```

### Step 4.6: Generate Credential Configuration

```bash
gcloud iam workload-identity-pools create-cred-config \
  "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/haea-cg-cspm-pool/providers/aws-oidc" \
  --service-account="$SA_EMAIL" \
  --aws \
  --output-file="gcp-wif-config.json"
```

Set on ECS task:
```bash
# Environment variable in ECS task definition
GOOGLE_APPLICATION_CREDENTIALS=/app/config/gcp-wif-config.json
```

### Step 4.7: Validation

```bash
# From an environment with AWS credentials for haea-cg-prod-app:
export GOOGLE_APPLICATION_CREDENTIALS=gcp-wif-config.json

# Test SCC access
gcloud scc findings list "organizations/$ORG_ID" \
  --filter="state=\"ACTIVE\" AND severity=\"CRITICAL\"" \
  --limit=1

# Test IAM access
gcloud asset search-all-iam-policies --scope="organizations/$ORG_ID" --limit=1

# Test compute access
gcloud compute instances list --project="$PROJECT_ID" --limit=1
```

---

## 5. Validated Test Results (2026-03-24)

| Test | Environment | Result |
|------|-------------|--------|
| WIF pool creation | lvn-dev-483106 | PASS |
| AWS provider binding | lvn-dev-483106 | PASS |
| SA impersonation | lvn-dev-483106 | PASS |
| SCC Viewer access | lvn-dev-483106 | PASS |
| IAM Reviewer access | lvn-dev-483106 | PASS |
| Compute Viewer access | lvn-dev-483106 | PASS |
| Cloud Asset Viewer access | lvn-dev-483106 | PASS |

**Test resources:** WIF pool `haea-cg-cspm-pool` + SA in `lvn-dev-483106`. Calendar reminder April 20 to teardown.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `PERMISSION_DENIED` on token exchange | AWS account ID mismatch in WIF provider | Verify `--account-id` matches 831926608679 |
| `INVALID_ARGUMENT` on credential config | Wrong pool/provider path | Re-run `create-cred-config` with correct project number |
| SCC returns empty | SCC not enabled in org | `gcloud scc organizations enable $ORG_ID` |
| `iam.workloadIdentityUser` denied | Attribute mapping mismatch | Check `assertion.arn` matches the assumed-role ARN pattern |
| Stale credentials | Token expired (1h default) | SDK auto-refreshes; verify `GOOGLE_APPLICATION_CREDENTIALS` is set |

---

## 7. Security Considerations

- No service account keys — WIF provides keyless authentication
- Short-lived tokens (1 hour) limit blast radius
- AWS provider restricted to specific account ID (831926608679)
- Attribute mapping restricts to specific AWS role ARN
- All authentications logged in Cloud Audit Logs
- Service account has read-only access only (no write permissions)

---

## Contact

| Property | Value |
|----------|-------|
| Primary Contact | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Backup Contact | Seungwoo Son (seungwooson@haeaus.com) |
| Team | HAEA Security TFT |
