---
sidebar_position: 1
slug: /intro
title: Welcome
---

# Cloud Aegis Documentation

**Cloud Aegis** is an enterprise cloud governance platform that unifies CSPM findings, AI-powered risk scoring, policy enforcement, and automated remediation across AWS, Azure, and GCP.

## Quick Links

| Section | Description |
|---------|-------------|
| [Architecture](/docs/architecture/hld) | High-Level Design, Detailed Design, DR/BC |
| [ADRs](/docs/adr) | 19 Architecture Decision Records |
| [Diagrams](/docs/diagrams) | System architecture and flow diagrams |
| [API Reference](/docs/api) | Interactive OpenAPI explorer (82 operations) |
| [CSPM Aggregator](/docs/cspm/hld) | Multi-cloud finding aggregation module |
| [Runbooks](/docs/runbooks/01-deployment) | 9 operational runbooks |
| [Security](/docs/security/threat-model) | STRIDE threat model |

## Architecture at a Glance

![Cloud Aegis Architecture](/architecture-figma.png)

## Key Capabilities

- **Multi-cloud CSPM** -- Normalize findings from AWS Security Hub, Azure Defender, GCP SCC, Trivy, and Prowler into a unified schema
- **AI Risk Scoring** -- LLM-powered severity re-scoring considering asset tier, environment, exposure, and blast radius
- **Dual-OPA Policy** -- External OPA server for cloud provisioning + embedded Go SDK for AI agent governance
- **Automated Remediation** -- Dispatcher routes findings to provider-specific handlers with approval workflows
- **FinOps Integration** -- Multi-cloud cost aggregation with anomaly detection
- **Graph Analysis** -- PuppyGraph-backed attack path computation and resource relationship mapping
