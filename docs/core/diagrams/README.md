# Diagrams Index

| File | Description | Intent | Source |
|------|-------------|--------|--------|
| [architecture.svg](architecture.svg) | System overview | Current portfolio implementation | [.mmd](architecture.mmd) / Figma |
| [attack-path-secgraph-runtime.svg](attack-path-secgraph-runtime.svg) | Current secgraph materialization and attack-path runtime flow | Current portfolio implementation | [.mmd](attack-path-secgraph-runtime.mmd) |
| [cross-cloud-failover.svg](cross-cloud-failover.svg) | Cross-cloud failover sequence across detection, promotion, compute, and DNS cutover | Enterprise target / self-managed DR reference | [.mmd](cross-cloud-failover.mmd) |
| [dedup-algorithm.svg](dedup-algorithm.svg) | Finding deduplication, TTL cache, and canonical rule mapping flow | Current portfolio implementation | [.mmd](dedup-algorithm.mmd) |
| [dual-opa-architecture.svg](dual-opa-architecture.svg) | Dual OPA engine layout | Current portfolio implementation | [.mmd](dual-opa-architecture.mmd) / Figma |
| [compliance-deployment-models.svg](compliance-deployment-models.svg) | Multi-cloud compliance topology | Enterprise target / reference model | [.mmd](compliance-deployment-models.mmd) / [.drawio](compliance-deployment-models.drawio) |
| [failover-sequence.svg](failover-sequence.svg) | DR failover sequence | Enterprise target / self-managed DR reference | [.mmd](failover-sequence.mmd) / [.drawio](failover-sequence.drawio) |
| [global-deployment-architecture.svg](global-deployment-architecture.svg) | Multi-region deployment layout | Enterprise target / self-managed deployment reference | [.mmd](global-deployment-architecture.mmd) / Figma |
| [iac-deploy-pipeline.svg](iac-deploy-pipeline.svg) | Terraform/conftest CI/CD flow | Current implementation | [.mmd](iac-deploy-pipeline.mmd) |
| [remediation-dispatcher-flow.svg](remediation-dispatcher-flow.svg) | Automated remediation routing | Current implementation | [.mmd](remediation-dispatcher-flow.mmd) |
| [restore-dependency-dag.svg](restore-dependency-dag.svg) | Recovery dependency map across PostgreSQL, cluster restore, workflow state, secrets, and DNS | Enterprise target / self-managed DR reference | [.mmd](restore-dependency-dag.mmd) |
| [risk-intelligence-pipeline.svg](risk-intelligence-pipeline.svg) | Risk scoring data pipeline | Current portfolio implementation | [.mmd](risk-intelligence-pipeline.mmd) / Figma |
| [incident-response.svg](incident-response.svg) | Severity triage, escalation, containment | Operational runbook | [.mmd](incident-response.mmd) |
| [performance-troubleshooting.svg](performance-troubleshooting.svg) | Symptom diagnosis decision tree | Operational runbook | [.mmd](performance-troubleshooting.mmd) |
| [secrets-rotation.svg](secrets-rotation.svg) | Generate, deploy dual-key, validate, revoke | Operational runbook | [.mmd](secrets-rotation.mmd) |
| [finops-budget-alerts.svg](finops-budget-alerts.svg) | Threshold monitoring, alert routing | Operational runbook | [.mmd](finops-budget-alerts.mmd) |

Diagrams with Figma source are maintained in [Figma file `2l5XrS7QRy5MYFI9PwcPmK`](https://www.figma.com/design/2l5XrS7QRy5MYFI9PwcPmK). All others render from Mermaid or Draw.io source.

The active public portfolio deployment is lighter than the enterprise deployment references shown here. In particular, the multi-region deployment, compliance, and DR/failover diagrams should be read as target-state reference material unless explicitly called out as current implementation.
