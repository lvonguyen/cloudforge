# Icon Mapping: Identity Access Architecture Diagram

## draw.io Enhancement Workflow

1. **Import**: File → Import → `identity-access-architecture.svg`
2. **Fix subgraph fills**: Override brownish Mermaid defaults:
   - ENTRA container: `#1e40af` (dark blue)
   - AWS container: `#fef3c7` (light amber)
   - AZ container: `#dbeafe` (light blue)
   - GC container: `#dcfce7` (light green)
   - ONPREM (AD node): already `#6b7280` via classDef
3. **Add icons** (24x24 or 32x32 px): see mapping below
4. **Export**: File → Export as → PNG (300 DPI)
5. **Save as**: `identity-access-architecture-final.png`

## Icon Libraries

All icon libraries are git submodules under `env-config/icons/`:

| Library | Path | Icons | Source |
|---------|------|-------|--------|
| AWS Architecture | `icons/aws-icons-svg/` | 2,208 SVGs | [weibeld/aws-icons-svg](https://github.com/weibeld/aws-icons-svg) |
| Azure & Microsoft | `icons/azure-icon-collection/` | 3,225 SVGs | [benc-uk/icon-collection](https://github.com/benc-uk/icon-collection) |
| GCP Architecture | `icons/gcp-icons/` | 217 SVGs | [AwesomeLogos/google-cloud-icons](https://github.com/AwesomeLogos/google-cloud-icons) |
| Homelab Community | `icons/homelab-svg-assets/` | 614 SVGs | Community logos |
| Curated Templates | `shared/standards/templates/icons/` | 22 SVGs | Hand-picked |

## Node → Icon Mapping (Official Architecture Icons)

### Identity Layer (On-Prem + Entra ID)

| Diagram Node | Icon File | Size |
|-------------|-----------|------|
| Active Directory | `azure-icon-collection/azure-icons/Active-Directory-Connect-Health.svg` | 32px |
| Entra ID | `azure-icon-collection/azure-icons/Azure-Active-Directory.svg` | 32px |
| AD-Synced Groups | `azure-icon-collection/azure-cds/identity-224-Active-Directory-Connect-Health.svg` | 24px |
| Cloud-Only Groups | `azure-icon-collection/azure-cds/identity-221-Azure-Active-Directory.svg` | 24px |
| Identity Governance | `azure-icon-collection/azure-icons/Identity-Governance.svg` | 24px |

### AWS Layer

| Diagram Node | Icon File | Size |
|-------------|-----------|------|
| SAML 2.0 | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Identity-Access-Management_Temporary-Security-Credential_48_Light.svg` | 32px |
| SCIM 2.0 | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Identity-Access-Management_Add-on_48_Light.svg` | 32px |
| AWS Identity Store | `aws-icons-svg/q1-2022/Architecture-Service-Icons_.../Arch_Security-Identity-Compliance/48/Arch_AWS-Identity-and-Access-Management_48.svg` | 32px |
| AWS SSO | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Identity-Access-Management_Role_48_Light.svg` | 32px |
| AWS STS | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Identity-Access-Management_AWS-STS_48_Light.svg` | 24px |
| SAML Provider | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Identity-Access-Management_Long-Term-Security-Credential_48_Light.svg` | 24px |
| AWS Organizations | `aws-icons-svg/q1-2022/Architecture-Service-Icons_.../Arch_Management-Governance/48/Arch_AWS-Organizations_48.svg` | 32px |
| Management Account | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Organizations_Management-Account_48_Light.svg` | 24px |
| Member Accounts | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Organizations_Account_48_Light.svg` | 24px |
| Org Units | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Organizations_Organizational-Unit_48_Light.svg` | 24px |
| MFA Token | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Identity-Access-Management_MFA-Token_48_Light.svg` | 24px |
| Permissions | `aws-icons-svg/q1-2022/Resource-Icons_.../Res_AWS-Identity-Access-Management_Permissions_48_Light.svg` | 24px |

### Azure Layer

| Diagram Node | Icon File | Size |
|-------------|-----------|------|
| ESM Portal | `azure-icon-collection/azure-icons/App-Registrations.svg` | 32px |
| Azure RBAC | `azure-icon-collection/azure-icons/Azure-AD-Roles-and-Administrators.svg` | 32px |
| Subscriptions | `azure-icon-collection/azure-icons/Subscriptions.svg` | 32px |
| Identity Protection | `azure-icon-collection/azure-cds/identity-231-Azure-AD-Identity-Protection.svg` | 24px |
| Privilege Identity Mgmt | `azure-icon-collection/azure-cds/identity-234-Azure-AD-Privilege-Identity-Mapping.svg` | 24px |

### GCP Layer

| Diagram Node | Icon File | Size |
|-------------|-----------|------|
| Cloud Identity | `gcp-icons/docs/images/identity_platform.svg` | 32px |
| GCP IAM | `gcp-icons/docs/images/identity_and_access_management.svg` | 32px |
| Identity-Aware Proxy | `gcp-icons/docs/images/identity-aware_proxy.svg` | 24px |
| Security Command Center | `gcp-icons/docs/images/cloud_security_scanner.svg` | 24px |
| Resource Manager | `gcp-icons/docs/images/administration.svg` | 24px |

## Color Palette

| Purpose | Hex | Node Fill |
|---------|-----|-----------|
| On-Premises | `#6b7280` | AD node |
| Identity/Entra | `#1e40af` | Entra ID, groups |
| AWS | `#fbbf24` | AWS nodes |
| AWS Legacy | `#fde68a` | HMGNA Legacy (dashed) |
| Azure | `#60a5fa` | Azure nodes |
| GCP | `#4ade80` | GCP nodes |

## Data Notes

- P37 evidence was HMA-scoped (single LoB). Full enterprise scope below.
- **AWS**: 4 orgs / 132 accounts — HMGNA Legacy (56), HKNA (35), KNA (21), HMGNA (20, successor — HAEA + Glovis)
- **Azure**: HMGNA tenant / 51 subscriptions — KUS (22), HAEA (14), HMA (6), GUS/Glovis US (3), SS (3), KIA (2), HATCI (1)
- **GCP**: autoeveramerica.com org / 96 projects — HMA (49), KUS (21), HAEA (19), CMN (4), SBX (3)
- **CBU legend**: HMA = Hyundai Motor America, KUS = Kia US, HAEA = Hyundai AutoEver America, GUS = Glovis US, GMA = Genesis Motor America, HCA = Hyundai Capital America, HACC = Hyundai Canada, HATCI = Hyundai America Technical Center
- HMGNA Legacy mgmt account: 254170812053 (SAML provider: AWSSSO_7f7b92fe74ed2d0b_DO_NOT_DELETE)
- SSO portal region: us-west-2
- H Cloud: Pending discovery (coordinate with Will)
