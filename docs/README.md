# Cloud Aegis Documentation

## Architecture

| Document | Description |
|----------|-------------|
| [HLD.md](core/architecture/HLD.md) | High-Level Design v3.0 |
| [DDD.md](core/architecture/DDD.md) | Detailed Design -- API specs, data models |
| [DR-BC.md](core/architecture/DR-BC.md) | Disaster Recovery / Business Continuity v2.1 |
| [component-rationale.md](core/architecture/adr/component-rationale.md) | Technology selection and cost analysis |
| [performance-baseline.md](core/performance-baseline.md) | Go vs Rust benchmark comparison |

## Architecture Decision Records (19 ADRs)

| ADR | Decision | Status |
|-----|----------|--------|
| [ADR-001](core/architecture/adr/ADR-001-programming-language.md) | Programming Language (Go) | Accepted |
| [ADR-002](core/architecture/adr/ADR-002-database-selection.md) | Database Selection (PostgreSQL) | Accepted |
| [ADR-003](core/architecture/adr/ADR-003-caching-strategy.md) | Caching Strategy (Redis) | Accepted |
| [ADR-004](core/architecture/adr/ADR-004-ai-provider-selection.md) | AI Provider (Anthropic Claude) | Accepted |
| [ADR-005](core/architecture/adr/ADR-005-rate-limiting.md) | Rate Limiting Strategy | Accepted |
| [ADR-006](core/architecture/adr/ADR-006-authentication.md) | Authentication (OIDC + JWT) | Accepted |
| [ADR-007](core/architecture/adr/ADR-007-grc-integration.md) | GRC Integration Pattern | Accepted |
| [ADR-008](core/architecture/adr/ADR-008-attack-path-computation.md) | Attack Path Computation (BFS) | Accepted |
| [ADR-009](core/architecture/adr/ADR-009-remediation-dispatcher.md) | Remediation Dispatcher Architecture | Accepted |
| [ADR-010](core/architecture/adr/ADR-010-finops-cost-aggregation.md) | FinOps Multi-Cloud Cost Aggregation | Accepted |
| [ADR-011](core/architecture/adr/ADR-011-toxic-combo-detection.md) | Toxic Combination Detection | Accepted |
| [ADR-012](core/architecture/adr/ADR-012-whitelabel-architecture.md) | Whitelabel / Multi-Tenant Architecture | Accepted |
| [ADR-013](core/architecture/adr/ADR-013-resource-scoped-rbac.md) | Resource-Scoped RBAC | Accepted |
| [ADR-014](core/architecture/adr/ADR-014-event-driven-ingestion.md) | Event-Driven Finding Ingestion | Accepted |
| [ADR-015](core/architecture/adr/ADR-015-graph-query-engine.md) | Graph Query Engine (PuppyGraph) | Proposed |
| [ADR-016](core/architecture/adr/ADR-016-container-scanning.md) | Container Security Scanning | Accepted |
| [ADR-017](core/architecture/adr/ADR-017-secrets-management.md) | Secrets Management Architecture | Accepted |
| [ADR-018](core/architecture/adr/ADR-018-threat-intelligence-feeds.md) | Threat Intelligence Feed Integration | Accepted |
| [ADR-019](core/architecture/adr/ADR-019-multi-tenant-data-isolation.md) | Multi-Tenant Data Isolation | Accepted |

## Operational Runbooks

See [runbooks/README.md](core/runbooks/README.md) -- 9 runbooks covering deployment, incident response, DR failover, performance, remediation, policy management, secrets rotation, FinOps alerts, and identity provider setup.

## Diagrams

See [diagrams/README.md](core/diagrams/README.md) -- 8 architecture diagrams (SVG + Mermaid source).

## Research

| Document | Description |
|----------|-------------|
| [attack-path-enhancements.md](research/attack-path-enhancements.md) | Graph-based attack path analysis roadmap |
| [INDUSTRY_LANDSCAPE.md](research/INDUSTRY_LANDSCAPE.md) | CSPM/CNAPP competitive landscape |
| [puppygraph-poc.md](research/puppygraph-poc.md) | PuppyGraph zero-ETL graph POC notes |
| [whitelabel-exploration.md](research/whitelabel-exploration.md) | Whitelabel strategy (4-phase) |

## Archive

One-time planning documents moved to [archive/](archive/):

| Document | Description |
|----------|-------------|
| [cloudforge-HLD-v1.md](archive/cloudforge-HLD-v1.md) | Original HLD (superseded by v3.0) |
| [implementation-plan-v1.md](archive/implementation-plan-v1.md) | Initial implementation plan |
| [frontend-planning.md](archive/frontend-planning.md) | Frontend design (superseded by implementation) |
| [iac-planning.md](archive/iac-planning.md) | IaC planning session notes |
| [pitch-deck.md](archive/pitch-deck.md) | Executive presentation (12 slides) |
| [figma-session-prep.md](archive/figma-session-prep.md) | Figma MCP session preparation notes |

## Related: CSPM Aggregator

See [cspm/](cspm/) -- Cross-Cloud CSPM Aggregator documentation (separate project, shared lineage with Cloud Aegis).

---

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | Liem Vo-Nguyen | Initial docs README |
| 2.0 | March 20, 2026 | Liem Vo-Nguyen | Full reorg: core/archive/research structure, 19 ADRs, updated cross-references |
