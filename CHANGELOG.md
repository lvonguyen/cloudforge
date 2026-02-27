# Changelog

All notable changes to CloudForge are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- Frontend planning doc — 18-screen React/Vite UI across Admin, Operator, and Requester role views with phased build plan and TypeScript type alignment (`docs/frontend-planning.md`)
- IaC planning doc — Terraform module catalog, Rego policy expansion, two-track OPA architecture, Cloud Run + CF Pages deployment design (`docs/iac-planning.md`)

---

## [0.5.0] — 2026-02-26

### Added

- AI governance module — selective merge from AgentGuard; embedded OPA Go library engine for in-process AI agent tool and data-flow control (Rego namespace: `cloudforge.ai.*`)
- Agent registry — lifecycle tracking, observability, status management across agent fleet
- STRIDE + ATLAS threat models — structured threat modeling structs per registered agent type
- Maturity assessment — governance readiness scoring across 5 maturity dimensions
- AI governance OPA policies — example YAML policies for tool access and data-flow control (`internal/ai-governance/policies/examples/`)
- MIT License

### Fixed

- Missing `s3control` dependency causing build failures in remediators
- Injectable client pattern for remediators (testability improvement)

### Changed

- AI model reference updated from `claude-opus-4-5-20250514` to `claude-opus-4-6` across all docs and config
- Architecture hardened: BOLA fix on exception endpoints, N+1 query resolved in PostgreSQL GRC provider, CI action pins, OPA evaluator timeout cap

---

## [0.4.0] — 2026-02-26

### Fixed

- Security audit fixes SEC-001 through SEC-012:
  - SEC-001: Input sanitization on exception request fields
  - SEC-002: BOLA — authorization check before resource fetch
  - SEC-003: Rate limiting wired to all API routes
  - SEC-004 through SEC-012: Hardening across GRC, policy, and observability layers

---

## [0.3.0] — 2026-02-11

### Added

- Remediation dispatcher — concurrent batch executor with semaphore-controlled parallelism (`pkg/remediation/`)
- 10 remediation handlers across 8 security domains:
  - Network: SSH/RDP ingress blocking
  - Security services: GuardDuty enablement, Azure Defender (stub)
  - Storage: S3 public access block
  - Compute: EC2 IMDSv2 enforcement
  - Identity: IAM key rotation (Tier 2)
  - Secrets: Manual rotation guidance
  - Patching: SSM patch compliance (query-only, Tier 3)
  - Rollback: 48-hour state snapshot engine
- Tiered execution model — Tier 1 (auto-safe), Tier 2 (requires verification), Tier 3 (change window)
- Findings bridge package (`internal/findings/`) — temporary bridge to cspm-aggregator types pending monorepo merge
- Executor engine unit tests — 14 test cases covering core execution paths
- Domain READMEs for all 8 remediation domains

---

## [0.2.0] — 2026-01-xx

### Added

- FinOps cost management module:
  - Multi-cloud cost aggregation (AWS Cost Explorer, Azure Cost Management, GCP Billing)
  - ML-based anomaly detection with configurable thresholds
  - Tag-based chargeback/showback engine
  - Budget alerting via Slack/PagerDuty
- CI/CD security scanning:
  - SAST integrations: SonarQube, Checkov, Veracode
  - VCS integrations: GitHub, GitLab, Azure DevOps
- Rate limiting middleware — Redis-backed, tier-based limits wired to all API routes
- CI/CD pipeline — GitHub Actions with build, test, lint, and security scanning
- Dockerfile — multi-stage Go build, non-root user, Alpine runtime

### Changed

- AI provider abstraction extended to support Claude and OpenAI behind a common interface

---

## [0.1.0] — 2025-12-xx

### Added

- Core API server (`cmd/server/`) — HTTP handlers, health probes (`/health`, `/ready`, `/live`), Prometheus metrics (`/metrics`)
- GRC provider abstraction — pluggable interface with RSA Archer, ServiceNow GRC, PostgreSQL, and in-memory implementations
- Compliance framework engine — 20+ frameworks: CIS, NIST CSF, ISO 27001, PCI-DSS, HIPAA, HITRUST, SOX, FedRAMP, CMMC, ISO 21434, TISAX, NIST AI RMF, ISO 42001
- OPA/Rego policy engine — region, cost, and network policies for cloud provisioning governance
- AI integration — Claude/OpenAI provider abstraction for contextual risk scoring and remediation generation
- Temporal workflow definitions — registration, approval, provisioning, and compliance scan workflows
- Identity module — Entra ID and Okta provider stubs with Zero Trust policy enforcement patterns
- WAF golden templates and compliance scanner
- Container security module
- Structured logging (zap), OpenTelemetry tracing (basic spans)
- PostgreSQL migrations
- Architecture documentation: HLD, DDD, ADRs (001-006), DR/BC plan, runbooks
