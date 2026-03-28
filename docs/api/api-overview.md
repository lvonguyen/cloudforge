---
title: API Reference
sidebar_position: 1
slug: /api
---

# API Reference

Cloud Aegis exposes 85 REST API operations across 21 domains. The full specification is available as an OpenAPI 3.1.0 document.

## Quick Access

- **[Download OpenAPI Spec](https://github.com/lvonguyen/cloudforge/blob/main/docs/api/openapi.yaml)** (3,326 lines, YAML)
- **[Endpoint Reference](/docs/reference/api-reference)** (markdown summary with pagination contract)

## API Domains

| Domain | Endpoints | Description |
|--------|-----------|-------------|
| System | 3 | Health, readiness, configuration |
| Findings | 7 | CRUD, search, stats, enrichment, ingest |
| Compliance | 3 | Frameworks, posture, mapping |
| Agents | 5 | Registry, lifecycle, traces, maturity |
| Costs | 7 | Spend, trends, anomalies, budgets, estimates, resources |
| Remediations | 5 | Queue, dispatch, approve, status |
| Exceptions | 3 | Request, review, audit |
| Policies | 4 | CRUD, evaluation, audit |
| Attack Paths | 3 | Compute, query, visualize |
| Graph | 3 | Gremlin, Cypher, traversal |
| Containers | 4 | Images, CVEs, SBOM, runtime |
| Secrets | 3 | Scan, upload, findings |
| WAF | 2 | Rules, events |
| Identity | 3 | Users, roles, sessions |
| AI/NLQ | 3 | Natural language query, suggestions |
| Deploy | 3 | Plan, apply, status |
| Workflows | 3 | Triggers, executions, templates |
| Webhooks | 4 | CRUD, test, logs |
| ASM | 3 | Assets, exposure, risk |
| Terminal | 2 | Sessions, commands |
| Integration | 3 | Providers, sync, status |

## Authentication

All endpoints (except `/health`, `/healthz`, `/ready`) require a Bearer JWT token with RBAC role claims.

```
Authorization: Bearer <jwt-token>
```

Roles: `viewer` | `requester` | `operator` | `admin`
