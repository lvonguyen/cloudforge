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

## 📁 Repository Structure

```
cloudforge/
├── cmd/
│   └── server/             # API server entrypoint
├── internal/
│   ├── grc/                # GRC provider abstraction (Archer, ServiceNow, Postgres)
│   ├── handlers/           # HTTP handlers
│   ├── models/             # Domain models
│   ├── policy/             # OPA integration
│   └── workflow/           # Temporal workflow definitions
├── migrations/             # Database migrations
├── policies/               # OPA/Rego policies
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   └── common/
├── configs/                # Configuration templates
├── docs/
│   ├── architecture/       # HLD, data models, diagrams
│   ├── adr/                # Architecture Decision Records
│   └── runbooks/           # Operational procedures
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

## 📖 Documentation

- [High-Level Design](docs/architecture/HLD.md)
- [Data Model](docs/architecture/data-model.md)
- [API Reference](docs/api.md)
- [Policy Authoring Guide](docs/policies.md)
- [Deployment Guide](docs/deployment.md)

### Architecture Decision Records
- [ADR-001: Workflow Engine Selection](docs/adr/001-workflow-engine.md)
- [ADR-002: Policy Engine Selection](docs/adr/002-policy-engine.md)
- [ADR-003: GRC Integration Pattern](docs/adr/003-grc-integration.md)

## 🔐 Security Considerations

- All API endpoints require authentication (OIDC)
- Service-to-service communication uses mTLS
- Secrets managed via HashiCorp Vault
- Audit logging for all provisioning actions
- RBAC for portal access

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
