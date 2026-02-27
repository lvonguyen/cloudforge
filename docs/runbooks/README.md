# CloudForge Technical Runbooks

## Overview

This directory contains operational runbooks for CloudForge. Each runbook provides step-by-step procedures for common operational tasks and incident response.

## Runbook Index

| Runbook | Description | Priority |
|---------|-------------|----------|
| [01-deployment.md](./01-deployment.md) | Deployment procedures, rollout, rollback | High |
| [02-incident-response.md](./02-incident-response.md) | Incident triage, classification, post-mortem | Critical |
| [03-dr-failover.md](./03-dr-failover.md) | DR failover per CSP, failback, communication templates | Critical |
| [04-performance-troubleshooting.md](./04-performance-troubleshooting.md) | CPU/memory profiling, DB analysis, optimization | Medium |
| [05-remediation-operations.md](./05-remediation-operations.md) | Remediation dispatcher, per-handler ops, rollback, emergency stop | High |
| [06-policy-management.md](./06-policy-management.md) | OPA lifecycle, dual-OPA ops, IaC policy gates, Rego testing | High |

## Runbook Template

Each runbook follows this structure:

1. **Overview** - What this runbook covers
2. **Prerequisites** - Required access and tools
3. **Procedures** - Step-by-step instructions
4. **Verification** - How to verify success
5. **Rollback** - How to undo changes
6. **Escalation** - When and who to escalate to

## Contact Points

| Role | Contact | Hours |
|------|---------|-------|
| On-Call Engineer | PagerDuty | 24/7 |
| Security Team | security@company.com | 24/7 |
| Platform Team | platform@company.com | Business hours |

