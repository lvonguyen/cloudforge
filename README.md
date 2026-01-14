# CloudForge

**Enterprise Cloud Governance Platform with Self-Service Provisioning**

CloudForge is a reference architecture and implementation for an Internal Developer Platform (IDP) that enables self-service cloud resource provisioning with built-in governance, compliance guardrails, and exception management workflows.

## 🎯 What This Solves

Enterprise cloud environments face a constant tension:
- **Developers** want fast, self-service access to infrastructure
- **Security** needs guardrails, approvals, and audit trails
- **Finance** requires cost controls, tagging, and chargeback
- **Compliance** demands policy enforcement and exception documentation

CloudForge bridges these needs with a unified platform that provides:
- Self-service portal for requesting cloud resources
- Policy-as-code guardrails (OPA/Rego)
- Golden path Terraform modules (pre-approved, versioned)
- Exception workflow integration with enterprise GRC tools
- Multi-cloud support (AWS, Azure, GCP)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PORTAL LAYER                                    │
│         (Self-Service UI - Backstage / Custom React)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    App      │  │   Infra     │  │  Exception  │  │  Dashboard  │        │
│  │ Registration│  │  Catalog    │  │   Request   │  │  & Reports  │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────┘        │
└─────────┼────────────────┼────────────────┼────────────────────────────────┘
          │                │                │
┌─────────▼────────────────▼────────────────▼────────────────────────────────┐
│                         ORCHESTRATION LAYER                                 │
│                    (Temporal Workflows / Argo)                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Registration    │  Approval     │  Provisioning  │  Compliance      │  │
│  │  Workflow        │  Workflow     │  Workflow      │  Scan Workflow   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
          │                │                │
┌─────────▼────────────────▼────────────────▼────────────────────────────────┐
│                          POLICY ENGINE                                      │
│                         (OPA / Rego)                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Region    │  │    Cost     │  │  Network    │  │  Exception  │        │
│  │  Policies   │  │  Policies   │  │  Policies   │  │  Validator  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
          │                │                │
┌─────────▼────────────────▼────────────────▼────────────────────────────────┐
│                        INTEGRATION LAYER                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    CMDB     │  │     GRC     │  │  Terraform  │  │   Cloud     │        │
│  │ (ServiceNow)│  │  (Archer)   │  │  (Atlantis) │  │   APIs      │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Repository Structure

```
cloudforge/
├── cmd/
│   └── server/             # API server entrypoint
├── internal/
│   ├── ai/                 # AI provider integration (Claude, OpenAI)
│   ├── api/                # API handlers and rate limiting
│   ├── cicd/               # CI/CD security scanning
│   │   ├── sast/           # SAST integrations (SonarQube, Checkov, Veracode)
│   │   └── vcs/            # VCS integrations (GitHub, GitLab, Azure DevOps)
│   ├── compliance/         # Compliance frameworks and deduplication
│   ├── container/          # Container security module
│   ├── grc/                # GRC provider abstraction (Archer, ServiceNow)
│   ├── identity/           # Identity providers (Entra ID, Okta) + Zero Trust
│   ├── observability/      # Logging, metrics, tracing, health checks
│   ├── policy/             # OPA integration
│   ├── secrets/            # Secrets management module
│   ├── waf/                # WAF golden templates and compliance scanner
│   ├── workflow/           # Temporal workflow definitions
│   └── finops/             # FinOps cost management (merged)
│       ├── aggregator/     # Multi-cloud cost aggregation
│       ├── anomaly/        # Cost anomaly detection
│       ├── chargeback/     # Cost allocation engine
│       └── reporter/       # Showback/chargeback reports
├── migrations/             # Database migrations
├── policies/               # OPA/Rego policies
├── configs/                # Configuration templates
├── docs/
│   ├── architecture/       # HLD, DDD, data models, diagrams
│   ├── adr/                # Architecture Decision Records
│   ├── runbooks/           # Operational procedures
│   └── DR-BC.md            # Disaster Recovery & Business Continuity
└── scripts/                # Utility scripts
```

## 🚀 Key Features

### Self-Service Portal
- Application registration with metadata capture
- Infrastructure request catalog (golden modules)
- Exception request workflow
- Compliance dashboards

### Policy-as-Code
- Region restrictions (data residency)
- Instance size limits (cost control)
- Network exposure rules (security)
- Tagging requirements (governance)
- Exception validation (GRC integration)

### GRC Integration
Pluggable providers for enterprise GRC platforms:
- **RSA Archer** - Full exception workflow integration
- **ServiceNow GRC** - Native ServiceNow integration
- **PostgreSQL** - Lightweight option for smaller orgs
- **In-Memory** - For demos and testing

### Multi-Cloud Support
- AWS (primary)
- Azure
- GCP
- Extensible provider pattern

### FinOps Cost Management
- **Cost Aggregation**: Multi-cloud cost data from AWS Cost Explorer, Azure Cost Management, GCP Billing
- **Anomaly Detection**: ML-based spend anomaly alerting with configurable thresholds
- **Chargeback/Showback**: Tag-based cost allocation with automated reports
- **Budget Tracking**: Proactive budget alerts via Slack/PagerDuty
- **Optimization**: Resource rightsizing and savings recommendations

## 🛠️ Tech Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| API Server | Go | Core platform API |
| Portal | Backstage / React | Self-service UI |
| Workflows | Temporal | Orchestration, approvals |
| Policies | OPA / Rego | Guardrails, validation |
| IaC | Terraform | Resource provisioning |
| Database | PostgreSQL | State, audit logs |
| Identity | OIDC (Okta/Azure AD) | Authentication |

## 🏃 Quick Start

### Prerequisites
- Go 1.21+
- Docker & Docker Compose
- Terraform 1.5+
- OPA CLI

### Local Development

```bash
# Clone repository
git clone https://github.com/yourusername/cloudforge.git
cd cloudforge

# Start dependencies (Postgres, OPA, Temporal)
docker-compose up -d

# Run migrations
make migrate

# Start API server
make run

# Run tests
make test
```

### Configuration

```yaml
# configs/local.yaml
server:
  port: 8080
  
database:
  host: localhost
  port: 5432
  name: cloudforge
  
grc:
  provider: memory  # memory | postgres | archer | servicenow
  
policy:
  opa_url: http://localhost:8181
  
workflow:
  temporal_host: localhost:7233
```

## Documentation

- [High-Level Design](docs/architecture/HLD.md)
- [Detailed Design Document](docs/architecture/DDD.md)
- [Component Rationale](docs/architecture/component-rationale.md)
- [DR/BC Plan](docs/DR-BC.md)
- [API Reference](docs/api.md)
- [Policy Authoring Guide](docs/policies.md)

### Architecture Decision Records
- [ADR-001: Programming Language](docs/adr/ADR-001-programming-language.md)
- [ADR-002: Database Selection](docs/adr/ADR-002-database-selection.md)
- [ADR-003: Caching Strategy](docs/adr/ADR-003-caching-strategy.md)
- [ADR-004: AI Provider Selection](docs/adr/ADR-004-ai-provider-selection.md)
- [ADR-005: Rate Limiting](docs/adr/ADR-005-rate-limiting.md)
- [ADR-006: Authentication](docs/adr/ADR-006-authentication.md)

### Technical Runbooks
- [01-deployment.md](docs/runbooks/01-deployment.md) - Deployment procedures
- [02-incident-response.md](docs/runbooks/02-incident-response.md) - Incident handling
- [04-performance-troubleshooting.md](docs/runbooks/04-performance-troubleshooting.md) - Performance issues

## Security Considerations

- All API endpoints require authentication (OIDC via Entra ID/Okta)
- Service-to-service communication uses mTLS
- Secrets managed via HashiCorp Vault with multi-cloud support
- Audit logging for all provisioning actions
- RBAC with Zero Trust policy enforcement
- API rate limiting and throttling
- Container security scanning
- CI/CD pipeline security (SAST/DAST integration)

## Observability

- **Logging**: Structured JSON logging with zap
- **Metrics**: Prometheus metrics at `/metrics`
- **Tracing**: OpenTelemetry distributed tracing
- **Health**: Kubernetes-ready liveness/readiness probes at `/health`, `/ready`, `/live`
- **Dashboards**: Grafana dashboards included

## Compliance Frameworks

Built-in support for:
- **General**: CIS, NIST CSF, ISO 27001, PCI-DSS
- **Cloud**: AWS Security Best Practice, GCP CIS, Azure MCSB
- **Healthcare**: HIPAA, HITRUST
- **Finance**: SOX, GLBA, FFIEC
- **Government**: FedRAMP, CMMC, NIST 800-53/800-171
- **AI**: NIST AI RMF, ISO 42001
- **Automotive**: ISO 21434, UN ECE R155, TISAX

## 🗺️ Roadmap

- [ ] Core API and GRC abstraction layer
- [ ] OPA policy engine integration
- [ ] Terraform golden module catalog
- [ ] Backstage portal integration
- [ ] Temporal workflow orchestration
- [ ] Multi-cloud provider support
- [ ] Cost estimation integration
- [ ] Compliance reporting dashboard

## 📝 License

MIT License - See [LICENSE](LICENSE)

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

---

**Note:** This is a reference architecture and portfolio project demonstrating enterprise cloud governance patterns. Production deployments require additional hardening, testing, and customization for your organization's specific requirements.
