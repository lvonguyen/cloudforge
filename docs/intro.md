---
sidebar_position: 1
slug: /intro
title: Welcome
---

# Aegis Documentation

**Aegis** is an enterprise cloud governance platform that unifies posture findings, AI-powered risk scoring, policy enforcement, and automated remediation across AWS, Azure, and GCP.

## Quick Links

| Section | Description |
|---------|-------------|
| [Architecture](/docs/architecture/hld) | High-Level Design, Detailed Design, DR/BC |
| [ADRs](/docs/adr) | 20 Architecture Decision Records |
| [Diagrams](/docs/diagrams) | System architecture and flow diagrams |
| [API Reference](/docs/api) | Interactive OpenAPI explorer (89 operations) |
| [Posture Management](/docs/cspm/hld) | Multi-cloud finding aggregation module |
| [Runbooks](/docs/runbooks/01-deployment) | 9 operational runbooks |
| [Security](/docs/security/threat-model) | STRIDE threat model |

## Architecture at a Glance

```mermaid
flowchart TD
    Portal["<b>Portal</b><br/>React 19 · Vite 7"]:::blue
    API["<b>API Server</b><br/>Go 1.25 · JWT · RBAC"]:::navy
    Core["<b>Core Engines</b><br/>CSPM · Remediation · Graph · ASM"]:::purple
    Intel["<b>Risk Intelligence</b><br/>EPSS · CISA KEV · GreyNoise · HIBP"]:::red
    Policy["<b>Policy — OPA</b><br/>Region · Network · AI Agent · IaC"]:::amber
    FinOps["<b>FinOps</b><br/>Cost Aggregation · Anomaly · Chargeback"]:::green
    Infra["<b>Infrastructure</b><br/>Terraform · Postgres · Redis · Webhooks"]:::slate

    Portal --> API --> Core
    Core --> Intel
    Core --> Policy
    Core --> FinOps
    Policy --> Infra
    FinOps --> Infra

    classDef blue fill:#3b82f6,stroke:#1e3a8a,color:#fff
    classDef navy fill:#1e40af,stroke:#1e3a8a,color:#fff
    classDef purple fill:#7c3aed,stroke:#4c1d95,color:#fff
    classDef red fill:#dc2626,stroke:#991b1b,color:#fff
    classDef amber fill:#f59e0b,stroke:#b45309,color:#fff
    classDef green fill:#22c55e,stroke:#166534,color:#fff
    classDef slate fill:#64748b,stroke:#334155,color:#fff
```

> For the detailed component-level diagram, see [Diagrams](/docs/diagrams).

## Key Capabilities

- **Multi-cloud CSPM** -- Normalize findings from AWS Security Hub, Azure Defender, GCP SCC, Trivy, and Prowler into a unified schema
- **AI Risk Scoring** -- LLM-powered severity re-scoring considering asset tier, environment, exposure, and blast radius
- **Dual-OPA Policy** -- External OPA server for cloud provisioning + embedded Go SDK for AI agent governance
- **Automated Remediation** -- Dispatcher routes findings to provider-specific handlers with approval workflows
- **FinOps Integration** -- Multi-cloud cost aggregation with anomaly detection
- **Graph Analysis** -- PuppyGraph-backed attack path computation and resource relationship mapping
