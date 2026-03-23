# AWS OIDC Setup — HAEA Cloud Guard (v2)

| Property | Value |
|----------|-------|
| Version | 2.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | March 2026 |
| Status | Active |
| Owner | AWS Team |
| IaC Source | `deploy/terraform/environments/haea/cspm-readers.tf` |

---

## 1. Account Context

| Property | Value |
|----------|-------|
| Central Security Account | 831926608679 (account-haea-security) |
| Management Account | 254170812053 (haea-org-root) |
| Reader Role Name | haea-cs-read-automation |
| App Role Name | haea-cg-prod-app |
| Aggregator Region | us-west-2 |
| OIDC Trust | GitLab CI/CD (gitlab.com) |
| External ID | haea-cg-cspm |

---

## 2. Architecture — Two-Hop Model

Cloud Guard uses a hub-and-spoke trust model. The central security account holds the OIDC-federated app role, which then assumes read-only roles in each tenant account.

```
GitLab CI/CD (or ECS Task)
  |
  | OIDC token (JWT)
  v
Central Security Account (831926608679)
  haea-cg-prod-app (OIDC-federated role)
  |
  | sts:AssumeRole (with ExternalId: haea-cg-cspm)
  |
  +---> Tenant 1: haea-cs-read-automation  --> SecurityHub, Config, GuardDuty, CloudTrail...
  +---> Tenant 2: haea-cs-read-automation  --> SecurityHub, Config, GuardDuty, CloudTrail...
  +---> Tenant 3: haea-cs-read-automation  --> SecurityHub, Config, GuardDuty, CloudTrail...
  +---> Tenant N: haea-cs-read-automation  --> SecurityHub, Config, GuardDuty, CloudTrail...
```

**Why two hops?**
- OIDC provider only needs to exist in ONE account (central)
- Tenant accounts only trust the central app role (not the OIDC provider directly)
- Adding/removing tenants doesn't require OIDC reconfiguration
- The reader role name (`haea-cs-read-automation`) is shared — other tools can use it too

**Existing SSO flow (unchanged):**
```
SSO Auth (PowerUser/Admin)
  --> hma-security-remediation-sp (831926608679)
  --> AssumeRole to SSOReadOnlyForAudit (254170812053)
  --> Org-wide visibility
```

---

## 3. CSPM Reader Policy — 12 Statement Blocks

The canonical policy is IaC-managed in `deploy/terraform/environments/haea/cspm-readers.tf`. Below is the human-readable breakdown.

| # | Sid | Service | Actions | Purpose |
|---|-----|---------|---------|---------|
| 1 | SecurityHubRead | securityhub | 10 actions | Finding ingestion (aggregated) |
| 2 | ConfigRead | config | 10 actions | Configuration compliance |
| 3 | GuardDutyRead | guardduty | 6 actions | Threat detection findings |
| 4 | IAMAudit | iam | 10 actions | Identity audit (users, roles, policies) |
| 5 | ResourceInventory | ec2, rds, s3, ssm | 14 actions | Compute/storage/network inventory |
| 6 | SSMCompliance | ssm | 3 actions | Patch compliance |
| 7 | CloudTrailRead | cloudtrail | 6 actions | Activity analysis, lateral movement |
| 8 | NetworkTopology | ec2 | 9 actions | Route tables, NAT, peering, transit gateways |
| 9 | LoadBalancerRead | elasticloadbalancing | 5 actions | Public-facing entry points |
| 10 | ServerlessContainerRead | lambda, ecs, eks | 13 actions | Serverless + container attack surface |
| 11 | AccessAnalyzerRead | access-analyzer | 3 actions | External access path detection |
| 12 | EncryptionPosture | kms, secretsmanager | 6 actions | Encryption posture (metadata only) |

**Total: 95 read-only actions across 12 service families. No write actions.**

---

## 4. One-Shot Provisioning Checklist

### Prerequisites (before sit-down)

- [ ] AWS CLI configured for delegated admin account (831926608679)
- [ ] GitLab OIDC thumbprint retrieved (see 4.1)
- [ ] Policy JSON exported from Terraform: `terraform output -raw cspm_reader_policy_json > /tmp/policy.json`
- [ ] Trust policy JSON exported: `terraform output -raw cspm_reader_trust_policy_json > /tmp/trust.json`

### Step 4.1: Get OIDC Thumbprint

```bash
# For GitLab.com:
THUMBPRINT=$(openssl s_client -servername gitlab.com \
  -showcerts -connect gitlab.com:443 </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha1 -noout \
  | sed 's/.*=//;s/://g' | tr '[:upper:]' '[:lower:]')
echo "Thumbprint: $THUMBPRINT"

# For GitHub Actions (if using GH instead of GL):
# Thumbprint: 6938fd4d98bab03faadb97b34396831e3780aea1
```

### Step 4.2: Create OIDC Provider (central account)

```bash
# Verify no existing OIDC providers
aws iam list-open-id-connect-providers

# Create GitLab OIDC provider
aws iam create-open-id-connect-provider \
  --url "https://gitlab.com" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "$THUMBPRINT" \
  --tags Key=Purpose,Value="GitLab OIDC for Cloud Guard CSPM"

# Capture the ARN
OIDC_ARN=$(aws iam list-open-id-connect-providers \
  --query 'OpenIDConnectProviderList[?ends_with(Arn, `gitlab.com`)].Arn' \
  --output text)
echo "OIDC Provider ARN: $OIDC_ARN"
```

**Verify:**
```bash
aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_ARN"
# Should show: Url=gitlab.com, ClientIDList=[sts.amazonaws.com]
```

### Step 4.3: Create Central App Role (central account)

```bash
# Create trust policy file
cat > /tmp/app-trust-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "OIDC_ARN_PLACEHOLDER"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "gitlab.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "gitlab.com:sub": "project_path:haea-sec/cloudguard:ref_type:branch:ref:main"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

# Replace placeholder with actual ARN
sed -i '' "s|OIDC_ARN_PLACEHOLDER|$OIDC_ARN|" /tmp/app-trust-policy.json

# Create the role
aws iam create-role \
  --role-name haea-cg-prod-app \
  --assume-role-policy-document file:///tmp/app-trust-policy.json \
  --description "Cloud Guard central app role (OIDC-federated)" \
  --tags Key=Purpose,Value="Cloud Guard CSPM"
```

**Verify:**
```bash
aws iam get-role --role-name haea-cg-prod-app
# Should show: AssumeRolePolicyDocument with Federated=gitlab.com
```

### Step 4.4: Grant Cross-Account AssumeRole (central account)

```bash
# Create policy allowing app role to assume reader roles in all tenants
cat > /tmp/assume-tenants.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": [
      "arn:aws:iam::TENANT_1_ID:role/haea-cs-read-automation",
      "arn:aws:iam::TENANT_2_ID:role/haea-cs-read-automation",
      "arn:aws:iam::TENANT_3_ID:role/haea-cs-read-automation",
      "arn:aws:iam::TENANT_4_ID:role/haea-cs-read-automation"
    ]
  }]
}
POLICY

# TODO: Replace TENANT_*_ID with actual account IDs

aws iam put-role-policy \
  --role-name haea-cg-prod-app \
  --policy-name assume-tenant-readers \
  --policy-document file:///tmp/assume-tenants.json
```

### Step 4.5: Create Reader Role (EACH tenant account)

**Repeat this block for each tenant account.** Switch AWS CLI profile or use `--profile` flag.

```bash
# --- Run in each tenant account ---
CENTRAL_APP_ROLE_ARN="arn:aws:iam::831926608679:role/haea-cg-prod-app"

# Create trust policy (trusts central app role only)
cat > /tmp/reader-trust.json << POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "$CENTRAL_APP_ROLE_ARN"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "haea-cg-cspm"
      }
    }
  }]
}
POLICY

# Create the reader role
aws iam create-role \
  --role-name haea-cs-read-automation \
  --assume-role-policy-document file:///tmp/reader-trust.json \
  --description "Cloud security read-only role for CSPM + audit tools" \
  --tags Key=Purpose,Value="Cloud Security Read Automation"

# Attach the CSPM reader policy (exported from Terraform)
aws iam put-role-policy \
  --role-name haea-cs-read-automation \
  --policy-name CSPMReaderAccess \
  --policy-document file:///tmp/policy.json
```

**Verify (in each tenant):**
```bash
aws iam get-role --role-name haea-cs-read-automation
aws iam get-role-policy --role-name haea-cs-read-automation --policy-name CSPMReaderAccess
```

### Step 4.6: End-to-End Validation

```bash
# From central account: assume into a tenant
aws sts assume-role \
  --role-arn "arn:aws:iam::TENANT_ID:role/haea-cs-read-automation" \
  --role-session-name validation-test \
  --external-id "haea-cg-cspm"

# Using the temp credentials, test key APIs:
aws securityhub get-findings --region us-west-2 --max-items 1
aws configservice describe-compliance-by-config-rule --region us-east-1
aws guardduty list-detectors --region us-east-1
aws cloudtrail describe-trails --region us-east-1
aws ec2 describe-vpcs --region us-east-1
aws access-analyzer list-analyzers --region us-east-1
```

---

## 5. Role Summary

| Role | Account | Purpose | Trust |
|------|---------|---------|-------|
| haea-cg-prod-app | 831926608679 | Central OIDC-federated app role | GitLab OIDC + ECS tasks |
| haea-cs-read-automation | Each tenant | Read-only CSPM reader (shared) | Central app role + ExternalId |
| hma-security-remediation-sp | 831926608679 | Write remediation (unchanged) | SSO |
| SSOReadOnlyForAudit | 254170812053 | Manual SSO audit (unchanged) | SSO |

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `AccessDenied` on AssumeRoleWithWebIdentity | OIDC audience/subject mismatch | Check `gitlab.com:aud` and `gitlab.com:sub` conditions in trust policy |
| `AccessDenied` on AssumeRole to tenant | Missing ExternalId | Add `--external-id haea-cg-cspm` to the assume-role call |
| `InvalidIdentityToken` | Wrong OIDC thumbprint | Re-retrieve thumbprint (step 4.1) and update provider |
| SecurityHub returns empty | Hub not enabled in region | `aws securityhub enable-security-hub --region us-west-2` |
| GuardDuty returns no detectors | GuardDuty not enabled | `aws guardduty create-detector --enable` |

---

## Contact

| Property | Value |
|----------|-------|
| Primary Contact | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Backup Contact | Seungwoo Son (seungwooson@haeaus.com) |
| Team | HAEA Security TFT |
