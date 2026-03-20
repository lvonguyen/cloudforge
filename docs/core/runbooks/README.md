# Cloud Aegis Technical Runbooks

## Overview

This directory contains operational runbooks for Cloud Aegis. Each runbook provides step-by-step procedures for common operational tasks and incident response.

## Runbook Index

| Runbook | Description | Priority |
|---------|-------------|----------|
| [01-deployment.md](./01-deployment.md) | Deployment procedures, rollout, rollback | High |
| [02-incident-response.md](./02-incident-response.md) | Incident triage, classification, post-mortem | Critical |
| [03-dr-failover.md](./03-dr-failover.md) | DR failover per CSP, failback, communication templates | Critical |
| [04-performance-troubleshooting.md](./04-performance-troubleshooting.md) | CPU/memory profiling, DB analysis, optimization | Medium |
| [05-remediation-operations.md](./05-remediation-operations.md) | Remediation dispatcher, per-handler ops, rollback, emergency stop | High |
| [06-policy-management.md](./06-policy-management.md) | OPA lifecycle, dual-OPA ops, IaC policy gates, Rego testing | High |
| [07-secrets-rotation.md](./07-secrets-rotation.md) | JWT keys, DB passwords, API keys, IdP secrets rotation | High |
| [08-finops-budget-alerts.md](./08-finops-budget-alerts.md) | Budget configuration, alert channels, anomaly investigation, chargeback | Medium |
| [09-identity-provider-setup.md](./09-identity-provider-setup.md) | Okta/Entra ID OIDC setup, JWT validation, mock provider | High |

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
| Security Team | security@contoso.dev | 24/7 |
| Platform Team | platform@contoso.dev | Business hours |

