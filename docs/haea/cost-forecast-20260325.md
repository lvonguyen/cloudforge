# Cloud Aegis CSPM Aggregator — HAEA Infrastructure Cost Forecast

**For:** Luis Acevedo / Jordan
**Meeting:** Wed 2026-03-25 8:00am
**Author:** Liem Vo-Nguyen
**Date:** 2026-03-25
**Region:** us-east-1 (primary)

---

## Scope

Cost forecast for deploying Cloud Aegis to HAEA's central security account (`831926608679`) on AWS. Architecture derived from Terraform modules in `deploy/terraform/environments/haea/`.

**Total addressable environments:** ~270 (132 AWS accounts / 4 orgs, 95 GCP projects / 1 org, 52 Azure subscriptions / HMGNA tenant).

**[!] This document covers cloud infrastructure costs only.** Excluded: labor, licensing (Splunk, Okta, Asana), third-party threat intel subscription fees (GreyNoise, HIBP, OTX), and VPN/corporate network costs.

---

## Architecture Summary

| Component | Service | Spec (from main.tf) | Notes |
|-----------|---------|---------------------|-------|
| API Server | ECS Fargate | 2 vCPU / 2 GB, min 2 / max 6 tasks | Go binary + env vars, 9 secrets |
| OPA Sidecar | ECS Fargate | 256 CPU units / 512 MB (default), min 2 / max 4 tasks | Policy evaluation engine |
| Database | RDS PostgreSQL 15 | db.t3.medium, 50 GB SSD, Multi-AZ (prod) | Findings, attack paths, GRC, compliance |
| Cache | ElastiCache Redis 7.0 | cache.t3.small (2 GB), 2 nodes (HA) | Enrichment cache (30m TTL), sessions, rate limiting |
| Storage | S3 | 3 buckets: tfstate, findings archive, SBOM | Lifecycle policies for archive tier |
| AI/ML | AWS Bedrock | Claude Sonnet 4.6 (TierFast, ~80% calls) | Finding enrichment: root cause, impact, remediation |
| Networking | VPC + NAT Gateway | 10.40.0.0/16, 3 subnets, NAT enabled, flow logs | Cross-account STS calls to 132+ tenants |
| Monitoring | CloudWatch | Logs, metrics, alarms (CPU threshold) | OTel traces (Jaeger) run in-container |
| Secrets | Secrets Manager | 11 secrets | DB URL, JWT, Redis, Okta, threat intel keys, Bedrock keys |
| DNS | Route 53 or AD DNS | 1 hosted zone / 1 internal record | `cloudguard.haeaus.com` — internal only |
| IAM | IAM roles + OIDC | 1 OIDC provider, 1 app role, N reader roles | No incremental cost (IAM is free) |

---

## Pricing Assumptions

All prices are AWS us-east-1 list prices as of March 2026. Reserved Instance / Savings Plan discounts noted where applicable but **not applied** to base estimates (conservative).

### Compute (ECS Fargate)

- **vCPU:** $0.04048/vCPU/hour
- **Memory:** $0.004445/GB/hour
- **730 hours/month** (standard billing month)

### Database (RDS PostgreSQL)

- **db.t3.medium:** $0.068/hour (2 vCPU, 4 GB RAM)
- **Multi-AZ:** 2x instance cost
- **Storage:** $0.115/GB-month (gp3)
- **Backup:** First backup = free (up to DB size); additional $0.095/GB-month

### Cache (ElastiCache Redis)

- **cache.t3.small:** $0.034/hour (1.5 GB, burstable)
- **HA (2 nodes):** 2x node cost

### Storage (S3)

- **S3 Standard:** $0.023/GB-month
- **S3 Infrequent Access:** $0.0125/GB-month
- **PUT requests:** $0.005/1,000 requests
- **GET requests:** $0.0004/1,000 requests

### AI/ML (AWS Bedrock — Claude Sonnet 4.6)

- **Input tokens:** $3.00/MTok
- **Output tokens:** $15.00/MTok
- **Estimated tokens per finding enrichment:** ~800 input + ~400 output (system prompt + finding context -> JSON response)
- **80% of calls use TierFast (Sonnet); 20% use TierPremium (Opus) at $15/$75 per MTok**
- **Enrichment is on-demand** (user clicks "Enrich" or batch job), not automatic for every finding
- **Cache TTL:** 30 minutes; singleflight dedup prevents duplicate calls

### Networking

- **NAT Gateway:** $0.045/hour + $0.045/GB processed
- **Data transfer (out to internet):** $0.09/GB (first 10 TB)
- **Data transfer (cross-AZ):** $0.01/GB each way
- **VPC flow logs:** $0.50/GB ingested to CloudWatch

### Monitoring

- **CloudWatch Logs:** $0.50/GB ingested
- **CloudWatch Metrics:** first 10 custom metrics free, then $0.30/metric/month
- **CloudWatch Alarms:** $0.10/alarm/month

### Secrets Manager

- **Per secret:** $0.40/secret/month
- **API calls:** $0.05/10,000 API calls

### DNS (Route 53)

- **Hosted zone:** $0.50/zone/month
- **Queries:** $0.40/million queries

---

## Scenario 1: Low (Pilot) — 26 HMA Accounts

**Scope:** 26 HMA accounts, single region, minimal AI enrichment, ~500 findings/day.
**AI enrichment:** ~50 findings/day enriched (10% of ingest, on-demand only).

| Service | Configuration | Monthly Cost |
|---------|--------------|-------------|
| **ECS Fargate — API** | 2 tasks x (2 vCPU + 2 GB) | $137 |
| **ECS Fargate — OPA** | 2 tasks x (0.25 vCPU + 0.5 GB) | $22 |
| **RDS PostgreSQL** | db.t3.medium, Multi-AZ, 50 GB | $106 |
| **ElastiCache Redis** | cache.t3.small, 2 nodes (HA) | $50 |
| **S3 Storage** | ~10 GB (archive) + ~1 GB (state/SBOM) | $1 |
| **Bedrock — Sonnet (80%)** | 40 calls/day x 30d x 800 in + 400 out | $4 |
| **Bedrock — Opus (20%)** | 10 calls/day x 30d x 800 in + 400 out | $5 |
| **NAT Gateway** | 1 NAT, ~5 GB/month data | $33 |
| **CloudWatch** | ~2 GB logs/month, 5 alarms, 10 metrics | $2 |
| **Secrets Manager** | 11 secrets, ~100K API calls/month | $5 |
| **Route 53** | 1 zone, negligible queries | $1 |
| **Data Transfer** | ~2 GB outbound (API responses) | $1 |
| **VPC Flow Logs** | ~1 GB/month | $1 |
| | | |
| **Monthly Subtotal** | | **$368** |
| **3-Month Total** | | **$1,104** |
| **6-Month Total** | | **$2,208** |
| **12-Month Total** | | **$4,416** |

---

## Scenario 2: Medium (Phase 1) — 132 AWS Accounts

**Scope:** 132 AWS accounts across 4 orgs, single region, moderate AI enrichment, ~5,000 findings/day.
**AI enrichment:** ~500 findings/day enriched (10% of ingest).
**Compute scale-up:** API scales to 3-4 tasks during ingestion peaks.

| Service | Configuration | Monthly Cost |
|---------|--------------|-------------|
| **ECS Fargate — API** | 3 tasks avg x (2 vCPU + 2 GB) | $205 |
| **ECS Fargate — OPA** | 2 tasks x (0.25 vCPU + 0.5 GB) | $22 |
| **RDS PostgreSQL** | db.t3.medium, Multi-AZ, 100 GB | $112 |
| **ElastiCache Redis** | cache.t3.small, 2 nodes (HA) | $50 |
| **S3 Storage** | ~50 GB (archive) + ~2 GB (state/SBOM) | $2 |
| **Bedrock — Sonnet (80%)** | 400 calls/day x 30d x 800 in + 400 out | $40 |
| **Bedrock — Opus (20%)** | 100 calls/day x 30d x 800 in + 400 out | $50 |
| **NAT Gateway** | 1 NAT, ~20 GB/month data | $34 |
| **CloudWatch** | ~8 GB logs/month, 10 alarms, 20 metrics | $6 |
| **Secrets Manager** | 11 secrets, ~500K API calls/month | $7 |
| **Route 53** | 1 zone, ~100K queries/month | $1 |
| **Data Transfer** | ~10 GB outbound | $1 |
| **VPC Flow Logs** | ~3 GB/month | $2 |
| | | |
| **Monthly Subtotal** | | **$532** |
| **3-Month Total** | | **$1,596** |
| **6-Month Total** | | **$3,192** |
| **12-Month Total** | | **$6,384** |

---

## Scenario 3: High (Full Scope) — All 270 Environments

**Scope:** 132 AWS + 95 GCP + 52 Azure, multi-region HA (us-east-1 primary, us-west-2 DR), full AI enrichment + threat intel, ~20,000 findings/day.
**AI enrichment:** ~4,000 findings/day enriched (20% of ingest — automated batch + on-demand).
**Compute scale-up:** API scales to 4-6 tasks; OPA scales to 3-4 tasks.
**Multi-region:** Primary + standby (50% compute in DR, full RDS read replica, Redis replica).

| Service | Configuration | Monthly Cost |
|---------|--------------|-------------|
| **ECS Fargate — API (primary)** | 5 tasks avg x (2 vCPU + 2 GB) | $342 |
| **ECS Fargate — API (DR)** | 2 tasks x (2 vCPU + 2 GB) | $137 |
| **ECS Fargate — OPA (primary)** | 3 tasks x (0.25 vCPU + 0.5 GB) | $33 |
| **ECS Fargate — OPA (DR)** | 2 tasks x (0.25 vCPU + 0.5 GB) | $22 |
| **RDS PostgreSQL (primary)** | db.t3.medium, Multi-AZ, 200 GB | $118 |
| **RDS PostgreSQL (read replica)** | db.t3.medium, us-west-2, 200 GB | $73 |
| **ElastiCache Redis (primary)** | cache.t3.small, 2 nodes (HA) | $50 |
| **ElastiCache Redis (DR)** | cache.t3.small, 2 nodes (HA) | $50 |
| **S3 Storage** | ~200 GB (archive, cross-region repl) + ~5 GB (state/SBOM) | $7 |
| **Bedrock — Sonnet (80%)** | 3,200 calls/day x 30d x 800 in + 400 out | $317 |
| **Bedrock — Opus (20%)** | 800 calls/day x 30d x 800 in + 400 out | $396 |
| **NAT Gateway (2 regions)** | 2 NATs, ~80 GB/month data total | $70 |
| **CloudWatch** | ~25 GB logs/month, 20 alarms, 40 metrics | $16 |
| **Secrets Manager** | 11 secrets x 2 regions, ~2M API calls/month | $19 |
| **Route 53** | 1 zone, health checks (2 endpoints) | $3 |
| **Data Transfer** | ~40 GB outbound + ~20 GB cross-region | $6 |
| **VPC Flow Logs** | ~10 GB/month (2 regions) | $5 |
| **Cross-region RDS replication** | ~5 GB/month data transfer | $1 |
| | | |
| **Monthly Subtotal** | | **$1,665** |
| **3-Month Total** | | **$4,995** |
| **6-Month Total** | | **$9,990** |
| **12-Month Total** | | **$19,980** |

---

## Summary Comparison

| Scenario | Environments | Findings/Day | Monthly | 3-Month | 6-Month | Annual |
|----------|-------------|-------------|---------|---------|---------|--------|
| **Low (Pilot)** | 26 HMA accounts | ~500 | **$368** | $1,104 | $2,208 | $4,416 |
| **Medium (Phase 1)** | 132 AWS accounts | ~5,000 | **$532** | $1,596 | $3,192 | $6,384 |
| **High (Full Scope)** | 270 envs (AWS+GCP+Azure) | ~20,000 | **$1,665** | $4,995 | $9,990 | $19,980 |

---

## Cost Drivers Analysis

### Top 3 Cost Drivers by Scenario

**Pilot:**
1. ECS Fargate compute (API + OPA): $159/mo (43%)
2. RDS PostgreSQL Multi-AZ: $106/mo (29%)
3. ElastiCache Redis HA: $50/mo (14%)

**Phase 1:**
1. ECS Fargate compute: $227/mo (43%)
2. RDS PostgreSQL: $112/mo (21%)
3. Bedrock AI enrichment: $90/mo (17%)

**Full Scope:**
1. Bedrock AI enrichment: $713/mo (43%)
2. ECS Fargate compute (2 regions): $534/mo (32%)
3. RDS PostgreSQL (primary + replica): $191/mo (11%)

### Key Observation

AI enrichment becomes the dominant cost driver at scale. The enrichment rate (% of findings enriched) is the single most impactful tuning knob:

| Enrichment Rate | Full Scope Bedrock Cost/mo | Total Monthly |
|----------------|---------------------------|---------------|
| 5% (conservative) | $178 | $1,130 |
| 10% (baseline) | $356 | $1,308 |
| 20% (modeled above) | $713 | $1,665 |
| 50% (aggressive) | $1,782 | $2,734 |
| 100% (every finding) | $3,564 | $4,516 |

---

## Cost Optimization Opportunities

| Optimization | Savings Estimate | Applicability |
|-------------|-----------------|---------------|
| **Fargate Savings Plan (1yr, no upfront)** | ~20% on compute ($32-$107/mo) | All scenarios |
| **Fargate Savings Plan (1yr, all upfront)** | ~30% on compute ($48-$160/mo) | All scenarios |
| **RDS Reserved Instance (1yr, no upfront)** | ~25% on RDS ($27-$48/mo) | All scenarios |
| **ElastiCache Reserved Nodes (1yr)** | ~30% on Redis ($15/mo) | All scenarios |
| **Bedrock batch API (async)** | ~50% on AI costs ($5-$356/mo) | If real-time enrichment not required |
| **TierFast-only (no Opus calls)** | Eliminate TierPremium premium ($5-$396/mo) | If Sonnet quality is acceptable for all enrichments |
| **Enrichment cache TTL increase** | 10-30% fewer AI calls (varies) | All scenarios — currently 30m, consider 4-24hr for stable findings |
| **NAT Gateway to VPC endpoints** | $33-$70/mo NAT cost reduction | For S3, Secrets Manager, CloudWatch (interface endpoints: $7.30/mo each) |
| **Single-AZ RDS (non-prod)** | 50% RDS savings in pilot | Pilot only — not recommended for production |

### Optimized Scenario Estimates (1yr Savings Plans + Reserved Instances)

| Scenario | Unoptimized Monthly | Optimized Monthly | Annual Savings |
|----------|--------------------|--------------------|----------------|
| **Pilot** | $368 | ~$295 | ~$876 |
| **Phase 1** | $532 | ~$415 | ~$1,404 |
| **Full Scope** | $1,665 | ~$1,250 | ~$4,980 |

---

## Bedrock Token Cost Calculation Detail

Per-finding enrichment call (from `service_enrichment.go`):

```
System prompt:  ~150 tokens (fixed — security analyst persona + JSON schema)
User prompt:    ~650 tokens (finding title, severity, category, provider,
                resource name/type/region, status, description)
                Total input: ~800 tokens

Output:         ~400 tokens (JSON: root_cause, impact, remediation,
                related_controls array)
```

**TierFast (Sonnet 4.6) — 80% of calls:**
- Input: 800 tokens x $3.00/MTok = $0.0024/call
- Output: 400 tokens x $15.00/MTok = $0.006/call
- **Total: $0.0084/call**

**TierPremium (Opus 4.6) — 20% of calls:**
- Input: 800 tokens x $15.00/MTok = $0.012/call
- Output: 400 tokens x $75.00/MTok = $0.030/call
- **Total: $0.042/call**

**Blended cost per enrichment (80/20 split): ~$0.015/call**

---

## IAM and OIDC — No Incremental Cost

The following resources defined in `cspm-readers.tf` are **free**:

- IAM OIDC identity provider (GitLab federation)
- IAM roles: `haea-cg-prod-app` (central), `haea-cs-read-automation` (per tenant)
- IAM policies: CSPM reader (12 statements, 95 actions), cost reader
- STS AssumeRole / AssumeRoleWithWebIdentity API calls
- Cross-account trust policies

The only cost associated with the cross-account model is the **data transfer** from SecurityHub/Config/GuardDuty API calls, which is captured in the NAT Gateway line item.

---

## Threat Intel Provider API Costs (Out of Scope — Reference Only)

The enrichment service calls 5 threat intel providers (from `threatintel/enricher.go`). API costs for these are **not included** in the infrastructure estimate as they are separate subscriptions:

| Provider | Data | Pricing Model |
|----------|------|---------------|
| FIRST EPSS | CVE exploit probability scores | Free (public API) |
| CISA KEV | Known Exploited Vulnerabilities catalog | Free (public dataset) |
| GreyNoise | IP noise/classification | Paid subscription (Community tier free, limited) |
| HIBP | Breached email check | Paid API key ($3.50/month) |
| OTX | Threat pulse data | Free (AlienVault community) |

---

## Notes and Caveats

1. **Estimates are based on AWS list prices** as of March 2026. Actual costs depend on usage patterns, data volumes, and AWS pricing changes.

2. **Finding volume assumptions** are derived from HAEA's current security tool landscape (SecurityHub + Config + GuardDuty across 4 orgs). Actual finding counts may vary significantly based on which benchmarks/standards are enabled and how many resources exist per account.

3. **AI enrichment is the most variable cost.** The system supports on-demand enrichment (user-initiated) and could support batch enrichment. The enrichment rate is configurable and directly controls the Bedrock spend. The 30-minute cache TTL and singleflight deduplication prevent redundant API calls.

4. **Multi-region (Scenario 3) is optional.** If HA/DR is not required initially, the full-scope deployment can run single-region at approximately the Phase 1 + Bedrock delta cost (~$1,100/mo instead of $1,665/mo).

5. **GCP and Azure cross-cloud API calls** (for SCC and Defender findings) traverse the public internet via NAT Gateway. These are included in the NAT data processing estimate but actual volumes depend on finding counts from those cloud providers.

6. **No egress to corporate network is costed** — the deployment is VPN-accessible only, and VPN infrastructure is assumed to exist (corporate network).

7. **Fargate CPU/memory mapping from Terraform:** The API service specifies `cpu = "2"` and `memory = "2Gi"`, which maps to 2048 CPU units (2 vCPU) and 2048 MB in Fargate. The OPA sidecar uses defaults (256 CPU units, 512 MB).

---

## Recommended Path

**Start with Scenario 1 (Pilot)** at ~$368/month. This covers the 26 HMA accounts already accessible and validates the full pipeline (ingestion -> normalization -> enrichment -> dashboard) before expanding to the remaining 106 AWS accounts.

**Graduate to Scenario 2** once access expansion completes across all 4 AWS orgs (~Q3 2026). The incremental cost from Pilot to Phase 1 is ~$164/month, primarily from increased Bedrock usage and storage growth.

**Evaluate Scenario 3** after AWS coverage is stable and GCP SCC / Azure Defender integrations are validated. The jump to multi-region adds ~$1,133/month, with AI enrichment being the primary driver.
