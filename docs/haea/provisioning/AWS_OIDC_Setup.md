# AWS OIDC Setup - HAEA Cloud Security Read Automation

| Property | Value |
|----------|-------|
| Version | 1.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | December 2025 |
| Status | Draft |
| Owner | AWS Team |

---

## 1. Account Context

| Property | Value |
|----------|-------|
| Delegated Admin Account | 831926608679 (account-haea-security) |
| Management Account | 254170812053 (haea-org-root) |
| Role Name | haea-cs-read-automation |
| Aggregator Region | us-west-2 |
| Trust | Azure AD OIDC |

---

## 2. SAML 2.0 vs OIDC - Why We Need Both

AWS currently has a SAML 2.0 IdP configured for SSO console access. **OIDC is a separate requirement** for programmatic automation.

| Protocol | Use Case | AWS API | Token |
|----------|----------|---------|-------|
| SAML 2.0 | Human login (console) | AssumeRoleWithSAML | XML |
| OIDC | Machine-to-machine | AssumeRoleWithWebIdentity | JWT |

**Why Azure Container Instance needs OIDC:**

- ACI cannot use SAML (no browser redirect)
- OIDC provides JWT tokens for programmatic authentication
- AWS STS validates JWT signature directly via OIDC provider

**Bottom line:** Keep existing SAML for console SSO, add OIDC provider for automation workloads.

---

## 3. Architecture

### 3.1 Scheduled Exports (Azure Container Instance)

```
Azure Container Instance (Go binary)
  → OIDC token from Azure AD App Registration (haea-cloud-security-automation)
  → AssumeRoleWithWebIdentity to haea-cs-read-automation (831926608679)
  → Security Hub API (aggregated findings, us-west-2)
```

### 3.2 Manual SSO Audit (Management Account)

```
SSO Auth (PowerUser/Admin)
  → hma-security-remediation-sp (831926608679)
  → AssumeRole to SSOReadOnlyForAudit (254170812053)
  → Org-wide resource/config visibility
```

---

## 4. OIDC Provider Setup

### 4.1 Prerequisites

| Requirement | Value | Status |
|-------------|-------|--------|
| Azure AD App Registration | haea-cloud-security-automation | Pending AD team |
| Application ID URI | api://{client-id} | Pending AD team |
| Azure AD Tenant | bd29b3ab-aaa2-425a-b882-9e7f73283ca6 | Existing |

### 4.2 Get Azure AD Thumbprint

AWS requires the thumbprint of the certificate used to sign OIDC tokens.

**Option A: Let AWS auto-fetch (Console)**

AWS Console will auto-retrieve thumbprint when you enter the provider URL.

**Option B: Manual retrieval (CLI)**

```bash
# Get thumbprint from Azure AD OIDC endpoint
THUMBPRINT=$(openssl s_client -servername sts.windows.net \
  -showcerts -connect sts.windows.net:443 </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha1 -noout \
  | sed 's/.*=//;s/://g' | tr '[:upper:]' '[:lower:]')

echo "Thumbprint: $THUMBPRINT"
```

### 4.3 Create OIDC Provider in AWS

```bash
# From delegated admin account (831926608679)

# Check if OIDC provider already exists
aws iam list-open-id-connect-providers

# Create OIDC provider
aws iam create-open-id-connect-provider \
  --url "https://sts.windows.net/bd29b3ab-aaa2-425a-b882-9e7f73283ca6/" \
  --client-id-list "api://{client-id}" \
  --tags Key=Purpose,Value="Azure AD OIDC for CSPM"
```

---

## 5. Role Migration

The existing hma-security-remediation-sp role combines read + write capabilities. This restructure separates concerns:

| Old Role | New Role | Purpose |
|----------|----------|---------|
| hma-security-remediation-sp | haea-cs-read-automation | Read-only exports |
| hma-security-remediation-sp | haea-remediation-sp | Write remediation |

### 5.1 Create Read-Only Role

```bash
# From delegated admin account (831926608679)

aws iam create-role \
  --role-name haea-cs-read-automation \
  --assume-role-policy-document file://trust-policy.json \
  --description "Read-only role for CSPM scheduled exports" \
  --tags Key=Purpose,Value="CSPM Read Automation"

aws iam put-role-policy \
  --role-name haea-cs-read-automation \
  --policy-name SecurityReadAccess \
  --policy-document file://inline-policies/SecurityReadAccess.json
```

---

## 6. What This Role Can Access

### 6.1 From Delegated Admin (831926608679)

| Capability | Coverage | Notes |
|------------|----------|-------|
| Security Hub Findings | All accounts, all regions | Aggregated in us-west-2 |
| GuardDuty Findings | All accounts | Via Security Hub integration |
| Inspector Findings | All accounts | Via Security Hub integration |
| Config Compliance | All accounts | Via Config aggregator |
| IAM (local account) | 831926608679 only | Full IAM read for security account |
| Organizations | All accounts | Account enumeration, OUs |
| SSO/Identity Center | All | Permission sets, assignments |

### 6.2 SecurityReadAccess.json Coverage (59 statements)

**Security Services:**
- Security Hub, GuardDuty, Inspector, Macie, Detective
- IAM, SSO, Identity Store, SSO-Admin
- WAFv2, WAF Classic, Network Firewall
- Config, CloudTrail, Access Analyzer
- KMS, Secrets Manager (metadata only)

**Asset Inventory:**
- EC2, Auto Scaling, Lambda, Batch
- S3, EBS, RDS, DynamoDB, ElastiCache, Redshift
- ECS, EKS, ECR
- CloudFront, Route53, ELB, API Gateway

---

## 7. Provisioning Checklist

### 7.1 OIDC Provider (831926608679)

- [ ] Confirm Azure AD App Registration created (AD team)
- [ ] Get Application ID URI from AD team
- [ ] Retrieve Azure AD thumbprint
- [ ] Create OIDC Identity Provider in AWS
- [ ] Verify OIDC provider configuration

### 7.2 haea-cs-read-automation Role (831926608679)

- [ ] Create IAM role with trust policy
- [ ] Attach SecurityReadAccess inline policy
- [ ] (Optional) Attach SecurityAudit managed policy
- [ ] Verify Security Hub aggregation in us-west-2
- [ ] Test from Azure Container Instance

### 7.3 Validation

- [ ] Test OIDC token exchange (AssumeRoleWithWebIdentity)
- [ ] Test Security Hub findings query
- [ ] Test SSO/Identity Center queries
- [ ] Test Organizations queries

---

## 8. Related Roles

| Role | Account | Purpose |
|------|---------|---------|
| haea-cs-read-automation | 831926608679 | Read-only scheduled exports (this role) |
| hma-security-remediation-sp | 831926608679 | Write remediation actions |
| SSOReadOnlyForAudit | 254170812053 | Manual SSO audit at management account |
| OrganizationAccountAccessRole | Member accounts | Cross-account access from management |

---

## 9. Usage Examples

### 9.1 Export Aggregated Findings

```bash
# Get all active findings
aws securityhub get-findings --region us-west-2 \
  --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'

# Get critical findings across all accounts
aws securityhub get-findings --region us-west-2 \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'
```

### 9.2 Query Organizations

```bash
# List all accounts
aws organizations list-accounts

# Get account details
aws organizations describe-account --account-id 123456789012
```

### 9.3 Validation Commands

```bash
# Verify OIDC provider exists
aws iam list-open-id-connect-providers

# Verify role exists
aws iam get-role --role-name haea-cs-read-automation

# Test OIDC assumption (from Azure Container Instance)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::831926608679:role/haea-cs-read-automation \
  --role-session-name scheduled-export \
  --web-identity-token $AZURE_TOKEN
```

---

## Appendix A: File Structure

```
infrastructure/aws-oidc/
├── README.md
├── trust-policy.json
└── inline-policies/
    └── SecurityReadAccess.json
```

---

## Appendix B: References

- [AWS Security Hub Delegated Admin](https://docs.aws.amazon.com/securityhub/latest/userguide/designate-orgs-admin-account.html)
- [Finding Aggregation](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html)
- [OIDC Federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

---

## Contact

| Property | Value |
|----------|-------|
| Primary Contact | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Backup Contact | Seungwoo Son (seungwooson@haeaus.com) |
| Team | HAEA Security TFT |
