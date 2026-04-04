# CloudForge -- Codebase Cost Estimate

**Date:** 2026-03-18
**Prepared for:** Portfolio ROI Analysis
**Repository:** github.com/lvonguyen/cloudforge (renamed CloudForge)
**Methodology:** LOC scan + complexity scoring + industry rate cards

---

## [1] Lines of Code Summary

### Source Code (Hand-Written)

| Language         | Total LOC | Source LOC | Test LOC | Files |
|------------------|-----------|------------|----------|-------|
| Go               | 67,005    | 38,274     | 28,731   | 165 + 108 test |
| TypeScript/TSX   | 25,738    | 20,507     | 5,191    | 148 + 38 test |
| Rego (OPA)       | 923       | 923        | --       | incl. in total |
| SQL (migrations) | 521       | 521        | --       | incl. in total |
| Shell scripts    | 245       | 245        | --       | incl. in total |
| CSS              | 87        | 87         | --       | 1 |
| HTML             | 26        | 26         | --       | 1 |
| **Subtotal**     | **94,545**| **60,583** | **33,922**| **~460** |

### Configuration and Infrastructure

| Category               | LOC    | Notes                                      |
|------------------------|--------|--------------------------------------------|
| YAML (CI/CD, config)   | 2,478  | ci.yml (344), release.yml (77), misc       |
| Terraform              | 1,627  | IaC for deployment                         |
| Infra configs          | 469    | Dockerfile, fly.toml, Makefile, goreleaser |
| JSON (config/data)     | 57,499 | Excludes LFS mock data and package-lock    |
| Markdown (docs)        | 28,004 | ADRs, HLD, STRIDE, HANDOFF, CHANGELOG     |
| **Subtotal**           | **90,077** |                                        |

### Generated / LFS Data (excluded from cost basis)

| Asset                      | Size     | Notes                          |
|----------------------------|----------|--------------------------------|
| findings.json (LFS)        | 42 MB    | 20K mock CSPM findings         |
| testdata exports           | ~1.6 GB  | AWS/GCP raw scrubbed exports   |
| attack-paths.json          | 1.4 MB   | Generated mock topology        |
| CSPM test fixtures         | ~22 MB   | Normalized + raw test data     |

### Totals

| Metric              | Value       |
|----------------------|-------------|
| Total files          | 807         |
| Total source LOC     | 60,583      |
| Total test LOC       | 33,922      |
| Test-to-source ratio | 56%         |
| Total hand-written   | 94,545      |
| Config + docs        | 90,077      |
| Grand total (excl generated) | ~185K |
| Git commits          | 419         |
| Distinct commit days | 27          |
| First commit         | 2026-01-01  |
| Last commit          | 2026-03-18  |
| Calendar span        | 77 days (11 weeks) |

---

## [2] Complexity Scorecard

| Dimension                | Rating | Justification |
|--------------------------|--------|---------------|
| Backend complexity       | 4.5/5  | 23 internal packages (RBAC, attack paths, enrichment, GRC, identity, FinOps, OPA, containers, secrets, WAF, workflows, webhooks, tenant, API gateway, rate limiting). BFS graph algorithms, singleflight dedup, AES-256-GCM encryption, SHA-256 integrity hashing. |
| Frontend complexity      | 4.0/5  | 21+ routes across ops/admin/portal. Role-based views (admin/operator/viewer), data viz (heatmaps, graph, kanban), Cmd+K palette, NLQ bar, real-time SSE hooks, 22 custom hooks, 59 components. Largest page: 1,038 LOC (Findings). |
| Security depth           | 4.5/5  | RS256 JWT auth, 4-tier RBAC with resource scoping, OPA policy engine, audit logging (Memory + Zap impls), AES-256-GCM state encryption, input validation (actor/filter length caps, regex allowlists, OData injection guards), CSP headers, secrets scanning. |
| Infrastructure           | 3.5/5  | Docker multi-stage, fly.toml (Fly.io), Cloudflare Pages, R2 storage, GitHub Actions CI (gosec, Trivy, Codecov, vitest, npm audit, CycloneDX SBOM), goreleaser, Terraform (1,627 LOC), k6 load test scripts. No K8s yet. |
| Data layer               | 4.0/5  | Mock data architecture with LFS (42MB), trim script for demo (20K to 500), R2 CDN fallback chain, dedup cache with background eviction, singleflight for enrichment, DataStore with 4 lookup maps, attack path BFS topology. |
| Integration surface      | 4.0/5  | Okta + Entra ID (config-driven, mock fallback), Asana/Jira/ServiceNow stubs (GRC), AI provider abstraction (Anthropic/OpenAI/Bedrock), comment CRUD, webhook system, container scanner, VCS integrations (GitHub/GitLab/Azure DevOps). |
| Documentation maturity   | 4.5/5  | 19 ADRs, STRIDE threat model (T-01/T-02 implemented), HANDOFF doc (92%), CHANGELOG, HLD, DDD analysis, 28K lines of markdown. Comprehensive inline docs. |
| **Weighted average**     | **4.14/5** | |

---

## [3] Human Team Estimate

### Rate Cards (2025-2026 US Market)

| Role                     | Hourly Rate | Effective LOC/hr | Notes |
|--------------------------|-------------|------------------|-------|
| Senior Go Backend        | $175        | 40               | Security-sensitive code |
| Senior React Frontend    | $165        | 50               | Complex UI + data viz |
| Security Engineer        | $190        | 30               | Policy, audit, crypto |
| DevOps/Infra Engineer    | $160        | 25               | CI/CD, IaC, deploy |
| Technical Writer         | $120        | 200 words/hr     | Architecture docs |

### Work Decomposition

#### Backend (Go)

| Work Package               | Source LOC | LOC/hr | Raw Hours |
|----------------------------|-----------|--------|-----------|
| Core API + handlers         | 6,500     | 40     | 163       |
| CSPM normalizer + scoring   | 4,200     | 35     | 120       |
| RBAC + auth middleware       | 2,800     | 30     | 93        |
| Identity (Okta/Entra)       | 2,500     | 35     | 71        |
| GRC providers               | 2,400     | 40     | 60        |
| Attack path engine          | 1,800     | 30     | 60        |
| Secrets + encryption        | 1,600     | 25     | 64        |
| Remaining 16 packages       | 16,474    | 40     | 412       |
| **Backend subtotal**        | **38,274**|        | **1,043** |

#### Backend Tests (Go)

| Work Package               | Test LOC  | LOC/hr | Raw Hours |
|----------------------------|-----------|--------|-----------|
| Unit + integration tests    | 28,731    | 60     | 479       |
| **Test subtotal**           | **28,731**|        | **479**   |

#### Frontend (TypeScript/React)

| Work Package               | Source LOC | LOC/hr | Raw Hours |
|----------------------------|-----------|--------|-----------|
| Ops pages (findings, CC, graph, attack paths, compliance, containers, remediation) | 7,500 | 45 | 167 |
| Admin pages (dashboard, agents, policies, webhooks, health) | 3,200 | 50 | 64 |
| Portal pages (request, exceptions, catalog, reports) | 2,800 | 50 | 56 |
| Components (59 shared)      | 4,500     | 50     | 90        |
| Hooks (22 custom)           | 1,200     | 50     | 24        |
| Layout + routing + auth     | 1,307     | 50     | 26        |
| **Frontend subtotal**       | **20,507**|        | **427**   |

#### Frontend Tests

| Work Package               | Test LOC  | LOC/hr | Raw Hours |
|----------------------------|-----------|--------|-----------|
| Component + page tests      | 5,191     | 70     | 74        |
| **Test subtotal**           | **5,191** |        | **74**    |

#### Security Engineering

| Work Package               | LOC       | LOC/hr | Raw Hours |
|----------------------------|-----------|--------|-----------|
| OPA policies (Rego)         | 923       | 25     | 37        |
| Auth middleware design       | --        | --     | 40        |
| STRIDE threat modeling       | --        | --     | 24        |
| Security review cycles       | --        | --     | 40        |
| **Security subtotal**       |           |        | **141**   |

#### DevOps / Infrastructure

| Work Package               | LOC       | LOC/hr | Raw Hours |
|----------------------------|-----------|--------|-----------|
| Terraform                   | 1,627     | 25     | 65        |
| CI/CD (GitHub Actions)      | 421       | 20     | 21        |
| Docker + fly.toml + goreleaser | 469    | 25     | 19        |
| YAML configs                | 2,057     | 30     | 69        |
| Shell scripts               | 245       | 30     | 8         |
| **DevOps subtotal**         |           |        | **182**   |

#### Documentation

| Work Package               | Lines     | Words (est) | Hrs @ 200w/hr |
|----------------------------|-----------|-------------|---------------|
| ADRs (14)                   | 3,500     | ~14,000     | 70            |
| Architecture docs (HLD, DDD) | 8,000   | ~32,000     | 160           |
| CHANGELOG + HANDOFF         | 371       | ~1,500      | 8             |
| README + inline docs        | 16,133    | ~64,500     | 323           |
| **Docs subtotal**           | **28,004**|             | **561**       |

### Aggregate Hours by Role

| Role                  | Raw Hours | Sprint Overhead (20%) | Total Hours |
|-----------------------|-----------|----------------------|-------------|
| Senior Go Backend     | 1,522     | 304                  | 1,826       |
| Senior React Frontend | 501       | 100                  | 601         |
| Security Engineer     | 141       | 28                   | 169         |
| DevOps Engineer       | 182       | 36                   | 218         |
| Technical Writer      | 561       | 112                  | 673         |
| **Total**             | **2,907** | **581**              | **3,488**   |

### Calendar Time Estimates

| Team Size           | FTEs | Parallel Factor | Calendar Weeks | Calendar Months |
|---------------------|------|-----------------|----------------|-----------------|
| Solo developer      | 1    | 1.0x            | 87 weeks       | ~20 months      |
| Growth team (3-4)   | 3.5  | 2.8x (collab overhead) | 31 weeks  | ~7 months       |
| Enterprise team (6-8) | 7  | 4.5x            | 19 weeks       | ~4.5 months     |

### Total Human Cost

| Cost Component          | Calculation                     | Amount        |
|-------------------------|---------------------------------|---------------|
| Backend engineering     | 1,826 hrs x $175               | $319,550      |
| Frontend engineering    | 601 hrs x $165                  | $99,165       |
| Security engineering    | 169 hrs x $190                  | $32,110       |
| DevOps engineering      | 218 hrs x $160                  | $34,880       |
| Technical writing       | 673 hrs x $120                  | $80,760       |
| **Raw labor total**     |                                 | **$566,465**  |
| Loaded cost (1.35x)     | Benefits, tools, overhead       | **$764,728**  |
| Recruiting + onboarding | ~8% of loaded cost              | $61,178       |
| **Fully loaded total**  |                                 | **$825,906**  |

---

## [4] AI-Assisted Development Analysis

### Session Patterns (from git log)

| Date       | Commits | Estimated Sessions | Notes |
|------------|---------|-------------------|-------|
| 2026-01-01 | 1       | 1                 | Project init |
| 2026-01-02 | 2       | 1                 | Early scaffolding |
| 2026-01-03 | 2       | 1                 | |
| 2026-01-04 | 2       | 1                 | |
| 2026-01-05 | 4       | 1                 | |
| 2026-01-09 | 1       | 1                 | |
| 2026-01-10 | 6       | 2                 | |
| 2026-01-13 | 3       | 1                 | |
| 2026-01-14 | 24      | 4                 | Heavy sprint day |
| 2026-02-11 | 5       | 2                 | |
| 2026-02-16 | 1       | 1                 | |
| 2026-02-26 | 30      | 5                 | Sprint 8-11 |
| 2026-02-27 | 12      | 3                 | |
| 2026-03-02 | 4       | 1                 | |
| 2026-03-03 | 3       | 1                 | |
| 2026-03-04 | 10      | 2                 | |
| 2026-03-05 | 6       | 2                 | |
| 2026-03-06 | 11      | 2                 | |
| 2026-03-09 | 6       | 2                 | |
| 2026-03-10 | 15      | 3                 | |
| 2026-03-11 | 16      | 3                 | |
| 2026-03-12 | 57      | 8                 | Peak day (Sprint C) |
| 2026-03-13 | 7       | 2                 | QA + CI fixes |
| 2026-03-15 | 35      | 5                 | Sprint C Phase 3 |
| 2026-03-16 | 82      | 10                | Sprint A/A+/B (peak) |
| 2026-03-17 | 52      | 8                 | Sprint G/H |
| 2026-03-18 | 22      | 5                 | Sprint I + whitelabel |
| **Total**  | **419** | **~78**           | Across 27 active days |

### AI Development Metrics

| Metric                          | Value                    |
|---------------------------------|--------------------------|
| Active development days         | 27                       |
| Calendar span                   | 77 days (11 weeks)       |
| Estimated Claude sessions       | ~78                      |
| Avg commits per session         | 5.4                      |
| Avg LOC produced per session    | ~1,213 (source only)     |
| Avg LOC produced per active day | ~3,503 (source only)     |
| Peak throughput                 | 82 commits / 1 day (Mar 16) |
| Human role                      | Architect + reviewer (1 person) |
| Human hours (est)               | ~4 hrs/session avg = 312 hrs |

### AI-Assisted Cost Breakdown

| Cost Component               | Calculation              | Amount         |
|------------------------------|--------------------------|----------------|
| Claude Max subscription      | $200/mo x 3 months      | $600           |
| Human architect (oversight)  | 312 hrs x $190/hr       | $59,280        |
| CI/CD tooling                | GitHub Actions, Fly.io   | ~$50/mo x 3    |
| Infrastructure (R2, domains) | Minimal                  | ~$20/mo x 3    |
| **Total AI-assisted cost**   |                          | **$60,090**    |

---

## [5] Comparative Analysis

### Cost Comparison

| Scenario               | Total Cost    | Calendar Time  | Team Size |
|------------------------|---------------|----------------|-----------|
| Solo human developer   | $825,906      | ~20 months     | 1 FTE     |
| Growth team (3-4)      | $825,906      | ~7 months      | 3.5 FTE   |
| Enterprise team (6-8)  | $825,906      | ~4.5 months    | 7 FTE     |
| AI-assisted (actual)   | $60,090       | 2.5 months     | 1 person + Claude |

### Efficiency Multipliers

| Metric                      | Human Solo | AI-Assisted | Multiplier |
|-----------------------------|------------|-------------|------------|
| Calendar time               | 20 months  | 2.5 months  | 8x faster |
| Total cost                  | $825,906   | $60,090     | 13.7x cheaper |
| Cost vs growth team time    | $825,906 / 7mo | $60,090 / 2.5mo | 2.8x faster, 13.7x cheaper |
| Effective LOC/hr (source)   | ~21        | ~194        | 9.2x throughput |
| Test coverage ratio         | Typically ~30% | 56%      | Higher quality baseline |
| Documentation density       | Often deferred | 28K lines shipped | Integrated from day 1 |

### ROI Summary

| Metric                              | Value           |
|--------------------------------------|-----------------|
| Gross savings vs solo dev            | $765,816        |
| Gross savings vs growth team         | $765,816 (same cost, 4.5mo faster) |
| ROI (savings / AI cost)             | 1,275%          |
| Break-even point                     | < 1 week of solo dev equivalent |
| Cost per source LOC (human solo)     | $13.63          |
| Cost per source LOC (AI-assisted)    | $0.99           |

---

## [6] Caveats and Limitations

[!] These estimates assume:
- Industry-standard rates for US-based senior engineers (2025-2026).
- The loaded cost multiplier (1.35x) accounts for benefits, tooling, and workspace but NOT equity compensation.
- AI-assisted human hours are estimated from git commit patterns, not tracked precisely.
- The 20% sprint overhead (standups, planning, retros, PR reviews) is conservative for a team >3 but generous for a solo dev.
- Mock data generation (42MB findings, attack paths) is excluded from the human LOC estimate since it was script-generated.
- JSON config/data files (57K LOC) are included in the grand total but NOT in the per-role cost calculation -- they are treated as generated output of engineering effort already counted.
- Documentation hours assume original writing; in practice, some docs were AI-drafted and human-edited, which further favors the AI-assisted model.

[*] Quality indicators that would increase human team cost:
- 56% test-to-source ratio exceeds the industry average (~30%).
- 19 ADRs is unusual for a project of this age -- most teams defer or skip architectural decision records.
- STRIDE threat model with implemented mitigations (T-01, T-02) is rare outside compliance-mandated environments.
- The iterative QA process (3 blind agents, 4.5+ threshold) has no direct human equivalent without dedicated QA headcount.

---

## [7] Conclusion

CloudForge represents ~94.5K lines of hand-written source code across Go, TypeScript, Rego, SQL, and shell scripts, plus ~90K lines of configuration, infrastructure, and documentation. The codebase scores 4.14/5 on complexity, with particular depth in backend security (4.5/5) and documentation maturity (4.5/5).

A traditional human team would require an estimated 3,488 loaded hours across 5 roles, costing $825,906 fully loaded. The AI-assisted approach delivered the same output in 2.5 months at $60,090 -- a 13.7x cost reduction and 8x calendar acceleration versus a solo developer.

The primary cost driver in the AI model is human oversight ($59,280 / 99% of total), not the AI tooling itself ($600 / 1%). This suggests the bottleneck is architectural decision-making and review, not code generation -- consistent with the emerging pattern where AI handles implementation throughput while humans own design authority.

---

*Generated by cost-estimate analysis, 2026-03-18.*
