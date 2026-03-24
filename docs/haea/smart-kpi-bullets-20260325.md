# SMART KPI Bullets — Cloud Security Governance

**For:** Luis Acevedo → Jordan
**Meeting:** Wed 2026-03-25 8:00am
**Author:** Liem Vo-Nguyen
**Last Updated:** 2026-03-24

**Scope:** 7 cloud tenants, ~270* subscriptions/accounts/projects across AWS (132 accounts / 4 orgs), GCP (95 projects / 1 org), Azure (52 subscriptions / HMGNA tenant).

*Dec 2025 POC estimate — actual count may vary as accounts are provisioned/decommissioned. Current discovery: 94 AWS visible, 95 GCP confirmed, 52 Azure confirmed.

---

## 1. Quarterly Tenant Configuration Audits

**Scope:** Hybrid — application/resource-level configuration (SecurityHub findings, Config rules, GuardDuty detectors) AND tenant-wide policy posture (IAM policies, SCPs, account-level settings, org-level guardrails). First audit covers both layers to establish which gaps are resource-specific vs org-wide.

**AWS landscape (132 accounts / 4 orgs):**

| Org | SSO Portal | Accounts | Visible | Brands |
|-----|-----------|----------|---------|--------|
| HMA Legacy | haea-aws-sso.awsapps.com | 56 | 54 | HMA, KUS, HMGMA, HACC |
| KNA | d-9267fb4f9b | 21 | 9 | KUS, HCAA (Canada), KAGA (Kia Georgia) |
| HMNA | d-92678cbdc7 | 35 | 14 | GEA (Glovis Electrifying America), GUS, HAEA |
| HMGNA | d-92678d8f7b | 20 | 17 | HMA, HKNA ops, successor for Legacy |

- **Achievable:** Deploy read-only CSPM reader roles and SecurityHub delegated admin across all 4 AWS Orgs (132 accounts). CSPM reader policy validated — 21/21 actions pass, two-hop AssumeRole chain confirmed. Produce first scored baseline report (CIS AWS Foundations Benchmark v3.0) covering resource config + tenant policy posture by end of Q2.
- **Stretch:** Formalize quarterly cadence with stakeholder distribution. Second audit (July) includes delta comparison showing remediation progress. Extend coverage to GCP (95 projects) and Azure (52 subscriptions).

---

## 2. HAEA-Wide Cloud Security Standard

**Current state:** Email sent to HQ inquiring about existing security policy/approach as starting point. No formal cloud security standard exists today. Pre-requisites being addressed in parallel: updated deployment checklists, cost forecasting, DNS/hosting inventory.

**DNS landscape (mapped 2026-03-23):**

| Domain | Hosting | Notes |
|--------|---------|-------|
| `haeaus.com` | **Azure** (20.119.144.14) | Primary corporate. M365, Mimecast MX, KnowBe4, Atlassian, Adobe SSO, Apple Business Mgr, AWS SES |
| `autoeveramerica.com` | **Tucows/registrar** (64.98.135.111) | Legacy. Mimecast MX. Likely colo or on-prem |
| `haea.bpmsonline.net` | **Kia America IP space** (209.198.179.46) | ESM/Creatio portal — hosted on Kia's network |
| `ts.autoeveramerica.com` | Not publicly resolvable | Internal-only or decommissioned |

No Cloudflare in the chain. Internal DNS record on existing AD infrastructure preferred (no DNS migration).

**Deployment checklist items (coordinate with M365/AD team):**
- [ ] Azure AD App Registration for Cloud Guard (SSO via existing M365 identity)
- [ ] Internal DNS record on AD DNS server (`cloudguard.haeaus.com` → internal deployment IP)
- [ ] VPN-only access — no public endpoint, reachable only via corporate network/VPN
- [ ] Conditional Access policy scoping Cloud Guard to authorized security team members
- [ ] Cost forecast for compute (ECS/App Service) + data transfer + storage

- **Achievable:** Establish v1.0 Cloud Security Standard covering AWS guardrails (IAM, encryption, network segmentation, logging) for 132 accounts across 4 orgs. Standard maps to CIS benchmarks + NIST 800-53 Rev 5. Dependent on HQ policy response for baseline alignment. Prerequisite deliverables: updated deployment checklists, Azure AD app registration, internal DNS record, cost forecast. Target: end of Q2 2026.
- **Stretch:** Extend coverage to GCP (95 projects) + Azure (52 subscriptions). Encode 10+ priority controls as machine-enforceable policies with automated drift detection.

---

## 3. Centralized Cloud Logging Strategy

**Current state:** Splunk Cloud instance exists — configuration status and ingestion scope unknown. GCP has per-brand logging projects (4+ brand-specific + 1 aggregate: `prj-cmn-mgmt-aggregate-logging`). AWS has dedicated log archive accounts per org (Legacy: 936680313364, HMNA: 341742814363, HMGNA: 360136158627, KNA: TBD — hidden).

- **Achievable:** Assess existing Splunk Cloud (config, ingestion, gaps), GCP logging projects, and AWS log archive accounts across all 4 orgs. Document target-state logging architecture: AWS CloudTrail org trails (all regions, all 4 orgs, 132 accounts), VPC Flow Logs, S3 access logs → Splunk; GCP Cloud Audit Logs per brand → aggregate project. Published strategy with stakeholder sign-off by end of Q2 2026.
- **Stretch:** Begin implementation in one pilot AWS org — org-level CloudTrail enabled, logs flowing to Splunk. Unify GCP audit log routing through the existing aggregate logging project. Establish log completeness monitoring for coverage gaps.

---

## 4. GCP Technical Debt — Documentation & Remediation

**Current state (discovered 2026-03-23):**
- **95 active GCP projects** under `autoeveramerica.com` org (was 93 in Dec 2025 — +2 growth)
- **By brand:** HMA 38 | KUS 19 | HMNA 12 | Shared-Infra 18 | HAEA-direct 5
- **Architecture present:** Shared VPC host/service separation, Apigee per brand, per-brand logging, Terraform bootstrap
- **Security gaps found:** Security Command Center NOT enabled, default service accounts enabled on infra projects, org-level permissions limited
- **Applications:** CS chatbots, SmartChat, Halo IT bot, OpenScheduler, MapNSoft, Vision AI POC, NHTSA VOQ classification, GA4 analytics

- **Achievable:** Establish GCP project inventory: 95 projects mapped by brand, environment, and purpose. Assess IAM bindings, enabled APIs, and default SA usage across all projects. Produce prioritized remediation backlog (enable SCC, disable default SAs, orphaned projects, over-permissioned accounts, disabled audit logging). Target: end of May 2026.
- **Stretch:** Remediate top-5 HIGH-severity findings (SCC enablement, default SA lockdown) by end of Q2. Establish GCP project provisioning guardrails to prevent new debt.

---

## 5. Enhance CSPM Processes — Consistent Deployment & Operation

**Current state:** Remediation access exists in HMA accounts today. CSPM reader policy (12 statements, 95 read-only actions) validated in test environment — 21/21 actions pass, two-hop AssumeRole chain confirmed. Need to expand access across remaining orgs and update operational runbooks.

**Access gaps:**
- KNA: 12/21 accounts hidden (zero operational accounts visible)
- HMNA: 21/35 accounts hidden
- HMGNA: 3/20 accounts hidden (best coverage)

- **Achievable:** Deploy Cloud Aegis CSPM aggregator to HAEA central security account (831926608679) with OIDC-federated two-hop trust model. Ingest SecurityHub + Config + GuardDuty findings from the initial 26 HMA accounts by end of Q2 2026. Updated deployment checklists and operational runbooks — new account onboarding <30 min. Total addressable: ~270* environments across 7 cloud tenants.
- **Stretch:** Enhance coverage to full 132-account AWS footprint across all 4 orgs. Integrate GCP SCC (95 projects). AI-enriched findings with threat-intel severity recalibration. Attack path visualization operational for security operations.
