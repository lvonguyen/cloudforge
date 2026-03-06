# CloudForge Documentation

## Architecture

| Document | Description |
|----------|-------------|
| [HLD.md](architecture/HLD.md) | High-Level Design v2.0 |
| [DDD.md](architecture/DDD.md) | Detailed Design — API specs, data models |
| [component-rationale.md](architecture/component-rationale.md) | Technology selection and cost analysis |

## Architecture Decision Records

| ADR | Decision |
|-----|----------|
| [ADR-001](adr/ADR-001-programming-language.md) | Programming Language (Go) |
| [ADR-002](adr/ADR-002-database-selection.md) | Database Selection (PostgreSQL) |
| [ADR-003](adr/ADR-003-caching-strategy.md) | Caching Strategy (Redis) |
| [ADR-004](adr/ADR-004-ai-provider-selection.md) | AI Provider (Anthropic Claude) |
| [ADR-005](adr/ADR-005-rate-limiting.md) | Rate Limiting Strategy |
| [ADR-006](adr/ADR-006-authentication.md) | Authentication (OIDC) |
| [ADR-007](adr/ADR-007-grc-integration.md) | GRC Integration Pattern |
| [ADR-008](adr/ADR-008-attack-path-computation.md) | Attack Path Computation |

## Operational Runbooks

See [runbooks/README.md](runbooks/README.md) — deployment, incident, DR, performance, remediation, policy management.

## Diagrams

See [diagrams/README.md](diagrams/README.md) — 8 architecture diagrams (SVG + Mermaid source).

## Supporting Documents

| Document | Description |
|----------|-------------|
| [DR-BC.md](DR-BC.md) | Disaster Recovery / Business Continuity v2.0 |
| [pitch-deck.md](pitch-deck.md) | Executive presentation (12 slides) |
| [frontend-planning.md](frontend-planning.md) | Frontend design (superseded by implementation) |
| [iac-planning.md](iac-planning.md) | IaC planning session notes |
| [figma-session-prep.md](figma-session-prep.md) | Figma MCP session preparation notes |

## Research

| Document | Description |
|----------|-------------|
| [wiz-attack-path-enhancements.md](research/wiz-attack-path-enhancements.md) | Graph-based attack path analysis roadmap |

## Related: CSPM Aggregator

See [cspm/](cspm/) — Cross-Cloud CSPM Aggregator documentation (separate project, shared lineage with CloudForge).
