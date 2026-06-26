# Application Intake and Review Template

This template is the human-facing companion to
`docs/schemas/application-intake.schema.json`. It is designed to become a
system record in a governance workspace and to map cleanly to future issue and
knowledge-base workflows.

Do not store secrets in this record. Use secret references, vault paths, or
approved credential custody links instead.

## 1. Application or Workload Identity

| Field | Value |
| --- | --- |
| Record ID |  |
| System name |  |
| Short name |  |
| System type | software application / embedded system / hardware control system / test lab system / simulation environment / data pipeline / infrastructure platform / vendor tool / other |
| Lifecycle status | draft / intake submitted / in review / needs changes / approved / registered / retired |
| Business purpose |  |
| Program or portfolio area |  |
| Owning department |  |
| Owning team |  |

## 2. Ownership

| Role | Name | Email | Department or team |
| --- | --- | --- | --- |
| Business owner |  |  |  |
| Technical lead |  |  |  |
| System custodian |  |  |  |
| Security reviewer |  |  |  |
| Data steward |  |  |  |
| Support group |  |  |  |
| Approval group |  |  |  |

## 3. Deployment Scope

| Field | Value |
| --- | --- |
| Deployment type | cloud service / on-prem server / lab workstation / embedded device / flight or robotics stack / hardware-in-loop / simulation only / factory or test equipment / hybrid |
| Hosting location | cloud / on-prem / lab / edge device / local workstation / hybrid |
| Environments | dev / test / staging / lab / production / fielded / archived |
| Cloud provider |  |
| Cloud account, subscription, project, or namespace |  |
| Physical site |  |
| Lab or facility |  |
| Network zone | public / internal / restricted / isolated / air gapped / unknown |
| Internet exposed | yes / no |
| Remote access required | yes / no |
| Privileged access required | yes / no |

### External Connections

| Name | Type | Direction | Approved | Notes |
| --- | --- | --- | --- | --- |
|  | API / VPN / private link / remote desktop / SSH / serial / fieldbus / radio / file transfer / vendor portal / other | inbound / outbound / bidirectional | yes / no |  |

## 4. Attached Assets

Assets are child records under the application or workload. Use this section for
hosts, virtual machines, switches, routers, firewalls, storage, lab machines,
controllers, sensors, actuators, radios, test fixtures, manufacturing equipment,
cloud resources, repositories, and data stores.

| Field | Asset 1 | Asset 2 | Asset 3 |
| --- | --- | --- | --- |
| Asset ID |  |  |  |
| Asset name |  |  |  |
| Asset type | host / VM / switch / router / firewall / lab workstation / controller / sensor / actuator / radio / test fixture / embedded device / cloud resource / repo / data store / other |  |  |
| Hosting role | primary runtime / secondary runtime / build or test / control plane / data plane / network dependency / storage dependency / operator workstation / lab fixture / telemetry source / external dependency / documentation or repo |  |  |
| Hostname or device name |  |  |  |
| FQDN |  |  |  |
| Serial number |  |  |  |
| Inventory ID |  |  |  |
| Cloud resource ID |  |  |  |
| IP addresses |  |  |  |
| MAC addresses |  |  |  |
| Environment | dev / test / staging / lab / production / fielded / archived |  |  |
| Site or region |  |  |  |
| Network zone | public / internal / restricted / isolated / air gapped / unknown |  |  |
| Owner team |  |  |  |
| Managed by |  |  |  |
| Privileged access | yes / no |  |  |
| Remote access | yes / no |  |  |
| Data processed | none / logs / telemetry / test results / design artifacts / configuration / source code / firmware / business data / other |  |  |
| Control authority | none / monitor only / command capable / safety relevant / autonomous control |  |  |
| Safety impact | none / low / medium / high / critical |  |  |
| Lifecycle status | planned / active / maintenance / quarantined / retired |  |  |

## 5. Data Profile

| Field | Value |
| --- | --- |
| Highest data classification | public / internal / confidential / restricted / controlled |
| Sensitive design or engineering data | yes / no |
| Personal data | yes / no |
| Customer data | yes / no |
| Vendor data | yes / no |
| Operational telemetry | yes / no |
| Data residency boundary |  |
| Retention requirement |  |
| Sharing restrictions |  |
| Approved storage locations |  |
| Approved transfer methods |  |

## 6. Engineering Assets

| Field | Value |
| --- | --- |
| Primary repository |  |
| Additional repositories |  |
| Artifact locations |  |
| Build system |  |
| Pipeline URL |  |
| IaC or configuration path |  |
| Release process |  |
| Dependency sources |  |

## 7. Risk and Controls

| Field | Value |
| --- | --- |
| Criticality | p1 / p2 / p3 / p4 |
| Service tier |  |
| Required control baseline |  |
| Threat model required | yes / no |
| Threat model status | not started / in progress / complete / waived |
| Architecture review required | yes / no |
| Data review required | yes / no |
| Security review required | yes / no |
| Hardware safety review required | yes / no |
| Compensating controls |  |

### Open Risks

| Risk ID | Description | Severity | Owner | Status |
| --- | --- | --- | --- | --- |
|  |  | low / medium / high / critical |  | open / accepted / mitigating / closed |

## 8. Operational Readiness

| Field | Value |
| --- | --- |
| Monitoring required | yes / no |
| Logging required | yes / no |
| Audit logging required | yes / no |
| Backup required | yes / no |
| RTO hours |  |
| RPO hours |  |
| Support hours |  |
| Incident contact |  |
| Runbook URL |  |
| Recovery procedure URL |  |

## 9. Review Workflow

| Stage | Status | Reviewer | Decision time | Comments |
| --- | --- | --- | --- | --- |
| Business owner | not started / pending / approved / rejected / needs changes / skipped |  |  |  |
| Technical owner | not started / pending / approved / rejected / needs changes / skipped |  |  |  |
| Data classification | not started / pending / approved / rejected / needs changes / skipped |  |  |  |
| Platform engineering | not started / pending / approved / rejected / needs changes / skipped |  |  |  |
| Security controls | not started / pending / approved / rejected / needs changes / skipped |  |  |  |
| Hardware safety | not started / pending / approved / rejected / needs changes / skipped |  |  |  |
| Cost review | not started / pending / approved / rejected / needs changes / skipped |  |  |  |
| Final governance | not started / pending / approved / rejected / needs changes / skipped |  |  |  |

## 10. Governance Workspace Mapping

| Field | Value |
| --- | --- |
| Jira project key |  |
| Jira issue key |  |
| Jira component |  |
| Jira issue type | Application Intake |
| Confluence space key |  |
| Confluence page ID |  |
| Confluence page template | System Record / Evidence Package |
| Linked epics |  |
| Linked change requests |  |

## 11. Retention

| Record class | Default policy | Delete trigger | Archive | Legal hold |
| --- | --- | --- | --- | --- |
| Draft intake | draft_180_days | created_at + 180 days if never submitted | no | yes |
| System record | system_lifecycle_plus_7_years | retired_at + 7 years | yes | yes |
| Approval record | approval_record_7_years | final decision + 7 years | yes | yes |
| Security review | security_review_7_years | review completion + 7 years | yes | yes |
| Asset inventory | asset_inventory_lifecycle_plus_7_years | asset retired + 7 years | yes | yes |
| Operational log | operational_log_2_years | event timestamp + 2 years | no | yes |
| Artifact reference | artifact_reference_lifecycle | parent record retired | yes | yes |

## 12. Audit

| Field | Value |
| --- | --- |
| Created by |  |
| Created at |  |
| Updated by |  |
| Updated at |  |
| Submitted at |  |
| Approved at |  |
| Retired at |  |
| Registration version |  |
