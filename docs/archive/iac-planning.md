# CloudForge IaC + Policy-as-Code Planning

**Status:** Draft
**Author:** Architecture Session
**Date:** 2026-02-26
**Scope:** Deploy structure, Rego policies, Terraform modules, LoE estimation, interview talking points

---

## 1. Existing Infrastructure Baseline

### What Already Exists

| Artifact | Path | Notes |
|---|---|---|
| Dockerfile | `Dockerfile` | Multi-stage Go build, non-root user, Alpine runtime |
| docker-compose.yml | `docker-compose.yml` | API + Postgres + OPA + Temporal + Temporal UI |
| OPA policies | `policies/common/{cost,network,regions}.rego` | Cloud provisioning governance |
| AI governance OPA | `internal/ai-governance/opa/engine.go` | In-process OPA for AI agent tool/data-flow control |
| Policy evaluator | `internal/policy/evaluator.go` | HTTP REST client to external OPA |
| Config template | `configs/config.example.yaml` | All infra coordinates: DB, OPA, Temporal, Redis |

### Two-Track OPA Architecture

CloudForge runs OPA in two modes that complement each other:

```
[Cloud Provisioning Path]                [AI Agent Path]
  HTTP request → policy/evaluator.go      in-process → ai-governance/opa/engine.go
       |                                          |
  POST /v1/data/cloudforge/provisioning    rego.PreparedEvalQuery (in-memory)
       |                                          |
  External OPA server (docker/k8s)         OPA Go library (embedded)
       |                                          |
  policies/common/*.rego                   BaseToolAccessPolicy / BaseDataFlowPolicy
```

This distinction matters for the IaC design: the external OPA server needs its own
deployment unit and policy bundle; the embedded engine needs its Rego files bundled
into the container image.

---

## 2. Proposed `deploy/` Directory Structure

```
deploy/
├── terraform/
│   ├── modules/
│   │   ├── compute/             # Cloud-agnostic container workload
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── database/            # Managed relational DB (Postgres-compatible)
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── networking/          # VPC, subnets, security groups
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── auth/                # Zero-trust access layer
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── monitoring/          # Metrics, logs, traces
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   └── cdn-frontend/        # Static frontend + CDN
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   ├── environments/
│   │   ├── dev/
│   │   │   ├── main.tf          # Module composition for dev
│   │   │   ├── variables.tf
│   │   │   ├── terraform.tfvars # gitignored — dev values
│   │   │   └── backend.tf
│   │   ├── staging/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   ├── terraform.tfvars # gitignored
│   │   │   └── backend.tf
│   │   └── prod/
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       ├── terraform.tfvars # gitignored
│   │       └── backend.tf
│   ├── policies/                # Rego policies checked against Terraform plan JSON
│   │   ├── cost-guardrails.rego
│   │   ├── security-baseline.rego
│   │   ├── naming-convention.rego
│   │   ├── network-isolation.rego
│   │   └── ai-governance.rego
│   ├── main.tf                  # Root module (delegates to environments/)
│   ├── variables.tf
│   ├── outputs.tf
│   └── backend.tf
├── docker/
│   ├── Dockerfile.backend       # (symlink or copy of root Dockerfile)
│   ├── Dockerfile.frontend      # React SPA build
│   └── docker-compose.yml       # (symlink or copy of root docker-compose.yml)
└── scripts/
    ├── plan-with-policy.sh      # terraform plan → JSON → conftest → gate
    └── deploy.sh                # Idempotent deploy (plan → policy check → apply)
```

**Design rationale:** Environments compose modules rather than duplicating HCL.
Each module exposes a `cloud_provider` variable to switch between GCP/AWS/Azure
resource implementations inside the same module file using `count` + `locals`.

---

## 3. Terraform Module Design

### 3.1 `compute/` — Cloud-Agnostic Container Workload

```hcl
# deploy/terraform/modules/compute/variables.tf

variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-{service})"
  type        = string
}

variable "environment" {
  description = "Deployment environment: dev, staging, prod"
  type        = string
}

variable "service_name" {
  description = "Service identifier (e.g., api, opa, temporal)"
  type        = string
}

variable "container_image" {
  description = "Full container image URI with tag"
  type        = string
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8080
}

variable "min_instances" {
  type    = number
  default = 1
}

variable "max_instances" {
  type    = number
  default = 5
}

variable "cpu"    { type = string; default = "1" }
variable "memory" { type = string; default = "512Mi" }

variable "env_vars" {
  description = "Environment variables for the container"
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Secret references (name => secret_manager_path)"
  type        = map(string)
  default     = {}
}

variable "vpc_id"            { type = string }
variable "subnet_ids"        { type = list(string) }
variable "service_account"   { type = string; default = "" }
variable "tags"              { type = map(string); default = {} }
```

```hcl
# deploy/terraform/modules/compute/main.tf

locals {
  resource_name = "${var.project_name}-${var.environment}-${var.service_name}"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })
}

# ─── GCP: Cloud Run ──────────────────────────────────────────────────────────
resource "google_cloud_run_v2_service" "this" {
  count    = var.cloud_provider == "gcp" ? 1 : 0
  name     = local.resource_name
  location = var.region

  template {
    service_account = var.service_account

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    vpc_access {
      network_interfaces {
        network    = var.vpc_id
        subnetwork = var.subnet_ids[0]
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.container_image
      ports { container_port = var.container_port }
      resources {
        limits = { cpu = var.cpu, memory = var.memory }
      }

      dynamic "env" {
        for_each = var.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secrets
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }
  }

  labels = local.common_tags
}

# ─── AWS: ECS Fargate ────────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "this" {
  count                    = var.cloud_provider == "aws" ? 1 : 0
  family                   = local.resource_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu == "1" ? "256" : var.cpu
  memory                   = replace(var.memory, "Mi", "")
  execution_role_arn       = var.service_account
  task_role_arn            = var.service_account

  container_definitions = jsonencode([{
    name      = var.service_name
    image     = var.container_image
    essential = true
    portMappings = [{ containerPort = var.container_port, protocol = "tcp" }]
    environment = [for k, v in var.env_vars : { name = k, value = v }]
    secrets = [for k, v in var.secrets : { name = k, valueFrom = v }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/${local.resource_name}"
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])

  tags = local.common_tags
}

resource "aws_ecs_service" "this" {
  count           = var.cloud_provider == "aws" ? 1 : 0
  name            = local.resource_name
  cluster         = var.aws_ecs_cluster_id
  task_definition = aws_ecs_task_definition.this[0].arn
  desired_count   = var.min_instances
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.this[0].id]
    assign_public_ip = false  # Always private — policy enforced
  }

  tags = local.common_tags
}

# ─── Azure: Container Apps ───────────────────────────────────────────────────
resource "azurerm_container_app" "this" {
  count                        = var.cloud_provider == "azure" ? 1 : 0
  name                         = local.resource_name
  resource_group_name          = var.azure_resource_group
  container_app_environment_id = var.azure_container_env_id

  template {
    min_replicas = var.min_instances
    max_replicas = var.max_instances

    container {
      name   = var.service_name
      image  = var.container_image
      cpu    = var.cpu
      memory = var.memory

      dynamic "env" {
        for_each = var.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secrets
        content {
          name        = env.key
          secret_name = lower(replace(env.key, "_", "-"))
        }
      }
    }
  }

  tags = local.common_tags
}
```

```hcl
# deploy/terraform/modules/compute/outputs.tf

output "service_url" {
  description = "URL of the deployed service"
  value = (
    var.cloud_provider == "gcp"   ? try(google_cloud_run_v2_service.this[0].uri, "") :
    var.cloud_provider == "aws"   ? try("https://${aws_lb.this[0].dns_name}", "") :
    var.cloud_provider == "azure" ? try(azurerm_container_app.this[0].latest_revision_fqdn, "") :
    ""
  )
}

output "resource_name" {
  value = local.resource_name
}
```

### 3.2 Environment Composition (Dev Example)

```hcl
# deploy/terraform/environments/dev/main.tf

module "networking" {
  source         = "../../modules/networking"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "dev"
  cidr_block     = "10.10.0.0/16"
}

module "database" {
  source         = "../../modules/database"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "dev"
  vpc_id         = module.networking.vpc_id
  subnet_ids     = module.networking.private_subnet_ids
  instance_tier  = "SMALL"  # Passes CF cost policy
}

module "cloudforge_api" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "dev"
  service_name    = "api"
  container_image = var.cloudforge_image
  vpc_id          = module.networking.vpc_id
  subnet_ids      = module.networking.private_subnet_ids
  min_instances   = 1
  max_instances   = 3
  env_vars = {
    GRC_PROVIDER     = "postgres"
    OPA_URL          = "http://localhost:8181"
    TEMPORAL_HOST    = "temporal:7233"
  }
  secrets = {
    DATABASE_URL             = "cloudforge-dev-db-url"
    CLOUDFORGE_JWT_SECRET    = "cloudforge-dev-jwt-secret"
    CLOUDFORGE_REDIS_PASSWORD = "cloudforge-dev-redis-password"
  }
  tags = {
    application_id = var.project_name
    environment    = "dev"
    cost_center    = "engineering"
    owner          = "platform-team"
  }
}

module "opa" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "dev"
  service_name    = "opa"
  container_image = "openpolicyagent/opa:latest"
  container_port  = 8181
  vpc_id          = module.networking.vpc_id
  subnet_ids      = module.networking.private_subnet_ids
  min_instances   = 1
  max_instances   = 2
  tags = {
    application_id = var.project_name
    environment    = "dev"
    cost_center    = "engineering"
    owner          = "platform-team"
  }
}
```

---

## 4. Rego Policy Content

These policies live in `deploy/terraform/policies/` and are evaluated by
`conftest` against `terraform plan -out=plan.json`. They complement the runtime
OPA policies in `policies/common/` — the runtime policies gate actual resource
operations; these policies gate the *plan* before `terraform apply`.

### 4.1 `security-baseline.rego`

```rego
# deploy/terraform/policies/security-baseline.rego
# Evaluated against: terraform plan JSON (terraform show -json plan.tfplan)
# Enforces: encryption at rest/transit, no public IPs, TLS 1.2+, no default VPC
package terraform.security_baseline

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ─── Encryption at Rest ──────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "aws_db_instance",
        "aws_rds_cluster",
        "google_sql_database_instance",
        "azurerm_postgresql_flexible_server"
    ]
    config := resource.change.after
    not config.storage_encrypted
    msg := sprintf(
        "SECURITY-001: %s '%s' must have storage_encrypted = true",
        [resource.type, resource.name]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_s3_bucket"]
    not has_encryption(resource.change.after)
    msg := sprintf(
        "SECURITY-002: S3 bucket '%s' must enable server-side encryption",
        [resource.name]
    )
}

has_encryption(config) if {
    _ := config.server_side_encryption_configuration[_]
}

# ─── No Public IPs on Backend Services ───────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_cloud_run_v2_service"
    config := resource.change.after
    ingress := config.ingress
    ingress == "INGRESS_TRAFFIC_ALL"  # public — block on non-LB services
    not is_load_balancer_service(resource.name)
    msg := sprintf(
        "SECURITY-003: Cloud Run service '%s' must use VPC ingress only (not INGRESS_TRAFFIC_ALL). Use a load balancer in front.",
        [resource.name]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    config := resource.change.after
    config.associate_public_ip_address == true
    msg := sprintf(
        "SECURITY-004: EC2 instance '%s' must not have a public IP. Use NAT gateway for outbound access.",
        [resource.name]
    )
}

# Cloud Run / ECS backend services should NOT be publicly routable
# (frontend CDN / load balancers are the only public entry points)
is_load_balancer_service(name) if {
    contains(name, "frontend")
}

is_load_balancer_service(name) if {
    contains(name, "cdn")
}

# ─── TLS 1.2+ Enforcement ────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    config := resource.change.after
    config.protocol == "HTTPS"
    ssl_policy := config.ssl_policy
    ssl_policy in ["ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04"]
    msg := sprintf(
        "SECURITY-005: ALB listener '%s' must use TLS 1.2+ policy (ELBSecurityPolicy-TLS13-1-2-2021-06 or newer)",
        [resource.name]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_compute_ssl_policy"
    config := resource.change.after
    config.min_tls_version in ["TLS_1_0", "TLS_1_1"]
    msg := sprintf(
        "SECURITY-006: SSL policy '%s' must set min_tls_version = TLS_1_2 or TLS_1_3",
        [resource.name]
    )
}

# ─── No Default VPC Usage ────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_instance", "aws_ecs_service", "aws_rds_instance"]
    config := resource.change.after
    is_default_vpc(config.vpc_id)
    msg := sprintf(
        "SECURITY-007: Resource '%s' must not use the default VPC. Use a purpose-built VPC.",
        [resource.name]
    )
}

# Placeholder — in practice, query a data source for the default VPC ID
is_default_vpc(vpc_id) if {
    startswith(vpc_id, "default-")
}

# ─── IAM Least Privilege ─────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_iam_policy", "google_project_iam_binding"]
    config := resource.change.after
    has_wildcard_action(config)
    msg := sprintf(
        "SECURITY-008: IAM policy '%s' uses wildcard action '*'. Define specific permissions.",
        [resource.name]
    )
}

has_wildcard_action(config) if {
    statement := config.statement[_]
    statement.actions[_] == "*"
}
```

### 4.2 `cost-guardrails.rego`

```rego
# deploy/terraform/policies/cost-guardrails.rego
# Blocks oversized instance types and storage allocations (mirrors runtime cost.rego)
package terraform.cost_guardrails

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Approved instance types — mirrors policies/common/cost.rego SMALL + STANDARD tiers
approved_aws_instance_types := {
    "t3.micro", "t3.small", "t3.medium",          # SMALL
    "t3.large", "t3.xlarge", "m6i.large",          # STANDARD
    "m6i.xlarge", "m6i.2xlarge"
}

approved_gcp_machine_types := {
    "e2-micro", "e2-small", "e2-medium",           # SMALL
    "e2-standard-2", "e2-standard-4",              # STANDARD
    "e2-standard-8", "n2-standard-2", "n2-standard-4"
}

approved_azure_vm_sizes := {
    "Standard_B1s", "Standard_B1ms", "Standard_B2s",  # SMALL
    "Standard_D2s_v5", "Standard_D4s_v5", "Standard_D8s_v5"  # STANDARD
}

# ─── Instance Type Violations ────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    instance_type := resource.change.after.instance_type
    not instance_type in approved_aws_instance_types
    msg := sprintf(
        "COST-001: EC2 instance '%s' uses unapproved type '%s'. Approved types: %v",
        [resource.name, instance_type, approved_aws_instance_types]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_compute_instance"
    machine_type := resource.change.after.machine_type
    not machine_type in approved_gcp_machine_types
    msg := sprintf(
        "COST-002: GCE instance '%s' uses unapproved machine type '%s'. Approved types: %v",
        [resource.name, machine_type, approved_gcp_machine_types]
    )
}

# ─── Storage Size Limits ─────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "aws_db_instance",
        "google_sql_database_instance",
        "azurerm_postgresql_flexible_server"
    ]
    allocated_storage := resource.change.after.allocated_storage
    allocated_storage > 100
    msg := sprintf(
        "COST-003: Database '%s' requests %dGB storage (max 100GB without exception). Submit COST-003 exception.",
        [resource.name, allocated_storage]
    )
}

# ─── Required Tags for Cost Attribution ──────────────────────────────────────

required_tags := ["application_id", "environment", "cost_center", "owner"]

deny contains msg if {
    resource := input.resource_changes[_]
    resource.change.actions[_] in ["create", "update"]
    tag := required_tags[_]
    not resource.change.after.tags[tag]
    msg := sprintf(
        "COST-004: Resource '%s' (%s) is missing required tag '%s'",
        [resource.name, resource.type, tag]
    )
}

# ─── Auto-Scaling Upper Bound ─────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_appautoscaling_policy",
        "azurerm_container_app"
    ]
    max_count := resource.change.after.max_instance_count
    max_count > 20
    msg := sprintf(
        "COST-005: Service '%s' sets max_instance_count = %d (limit: 20). Increases require finance approval.",
        [resource.name, max_count]
    )
}
```

### 4.3 `naming-convention.rego`

```rego
# deploy/terraform/policies/naming-convention.rego
# Enforces {project}-{env}-{service} naming pattern across all resources
package terraform.naming_convention

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Resources that must follow the naming convention
named_resource_types := {
    "aws_instance",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "google_cloud_run_v2_service",
    "google_sql_database_instance",
    "google_storage_bucket",
    "azurerm_container_app",
    "azurerm_postgresql_flexible_server",
    "azurerm_storage_account"
}

valid_environments := {"dev", "staging", "prod", "sandbox"}

# Pattern: {project}-{env}-{service}
# Example: cloudforge-prod-api, cloudforge-staging-opa
name_valid(name) if {
    parts := split(name, "-")
    count(parts) >= 3
    env_part := parts[1]
    env_part in valid_environments
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in named_resource_types
    resource.change.actions[_] in ["create", "update"]
    not name_valid(resource.change.after.name)
    msg := sprintf(
        "NAMING-001: Resource '%s' (%s) does not follow naming convention '{project}-{env}-{service}'. Got: '%s'",
        [resource.name, resource.type, resource.change.after.name]
    )
}

# Warn on names that look like bare service names without project prefix
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type in named_resource_types
    resource.change.actions[_] == "create"
    name := resource.change.after.name
    not contains(name, "-")
    msg := sprintf(
        "NAMING-002: Resource '%s' name '%s' has no hyphens — likely missing project/env prefix",
        [resource.name, name]
    )
}
```

### 4.4 `network-isolation.rego`

```rego
# deploy/terraform/policies/network-isolation.rego
# Blocks overly permissive security groups and enforces private subnet usage
package terraform.network_isolation

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Sensitive ports must never have public ingress — mirrors network.rego at runtime
sensitive_ports := {22, 3389, 5432, 3306, 27017, 6379, 9200, 8181}

# ─── Security Group Rules ────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_security_group", "aws_vpc_security_group_ingress_rule"]
    rule := get_ingress_rules(resource.change.after)[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port != 443
    rule.from_port != 80
    msg := sprintf(
        "NETWORK-001: Security group '%s' has public ingress on port %d. Only 80/443 are allowed from 0.0.0.0/0.",
        [resource.name, rule.from_port]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_security_group", "aws_vpc_security_group_ingress_rule"]
    rule := get_ingress_rules(resource.change.after)[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port in sensitive_ports
    msg := sprintf(
        "NETWORK-002: Security group '%s' exposes sensitive port %d to the internet (0.0.0.0/0).",
        [resource.name, rule.from_port]
    )
}

get_ingress_rules(config) := rules if {
    rules := config.ingress
} else := []

# ─── GCP Firewall Rules ───────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    config := resource.change.after
    config.direction == "INGRESS"
    "0.0.0.0/0" in config.source_ranges
    not is_http_rule(config)
    msg := sprintf(
        "NETWORK-003: GCP firewall rule '%s' allows 0.0.0.0/0 ingress on non-HTTP ports.",
        [resource.name]
    )
}

is_http_rule(config) if {
    allow := config.allow[_]
    allow.ports[_] in ["80", "443"]
}

# ─── Database Private Subnet Enforcement ─────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "aws_db_instance",
        "aws_rds_cluster",
        "google_sql_database_instance"
    ]
    config := resource.change.after
    config.publicly_accessible == true
    msg := sprintf(
        "NETWORK-004: Database '%s' must not be publicly accessible. Set publicly_accessible = false.",
        [resource.name]
    )
}

# ─── OPA Server Must Not Be Publicly Accessible ───────────────────────────────
# OPA exposes all policy data — it MUST be internal-only

deny contains msg if {
    resource := input.resource_changes[_]
    contains(resource.name, "opa")
    resource.type in ["google_cloud_run_v2_service", "aws_ecs_service"]
    config := resource.change.after

    # Cloud Run: ingress must not be "all"
    ingress := config.ingress
    ingress != "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
    ingress != "INGRESS_TRAFFIC_INTERNAL_ONLY"
    msg := sprintf(
        "NETWORK-005: OPA service '%s' must use internal ingress only. OPA exposes policy data.",
        [resource.name]
    )
}
```

### 4.5 `ai-governance.rego`

```rego
# deploy/terraform/policies/ai-governance.rego
# Ties into CloudForge's AI governance module:
# - Validates model references against the approved allowlist
# - Requires observability (logging, tracing) for any AI service deployment
# - Blocks direct internet egress from AI agent containers
package terraform.ai_governance

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Approved AI models — mirrors the model allowlist in internal/ai-governance/models.go
approved_models := {
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
    "gpt-4o",
    "gpt-4o-mini",
    "qwen-32b"
}

# ─── Model Allowlist Enforcement ─────────────────────────────────────────────
# Any container with AI_MODEL or LLM_MODEL env var must use an approved model.

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition",
        "azurerm_container_app"
    ]
    config := resource.change.after
    model := get_env_var(config, "AI_MODEL")
    model != ""
    not model in approved_models
    msg := sprintf(
        "AI-GOV-001: Service '%s' uses unapproved AI model '%s'. Approved models: %v",
        [resource.name, model, approved_models]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition",
        "azurerm_container_app"
    ]
    config := resource.change.after
    model := get_env_var(config, "LLM_MODEL")
    model != ""
    not model in approved_models
    msg := sprintf(
        "AI-GOV-002: Service '%s' references unapproved LLM '%s' via LLM_MODEL env var.",
        [resource.name, model]
    )
}

# ─── Observability Required for AI Services ───────────────────────────────────
# Any service with an AI model env var must have structured logging + tracing enabled.

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition"
    ]
    config := resource.change.after
    has_ai_model(config)
    not has_observability(config)
    msg := sprintf(
        "AI-GOV-003: AI service '%s' must have LOG_LEVEL and OTEL_EXPORTER_OTLP_ENDPOINT set for observability.",
        [resource.name]
    )
}

has_ai_model(config) if {
    get_env_var(config, "AI_MODEL") != ""
}

has_ai_model(config) if {
    get_env_var(config, "LLM_MODEL") != ""
}

has_observability(config) if {
    get_env_var(config, "LOG_LEVEL") != ""
    get_env_var(config, "OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

# ─── Egress Control for AI Agent Services ────────────────────────────────────
# AI agents must be VPC-constrained — egress to internet must go through NAT,
# not direct internet access. This prevents prompt injection + exfiltration.

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_cloud_run_v2_service"
    config := resource.change.after
    has_ai_model(config)
    vpc_access := config.template[_].vpc_access
    vpc_access.egress != "PRIVATE_RANGES_ONLY"
    vpc_access.egress != "ALL_TRAFFIC"  # ALL_TRAFFIC through VPC is acceptable
    msg := sprintf(
        "AI-GOV-004: AI service '%s' must route egress through VPC (PRIVATE_RANGES_ONLY or ALL_TRAFFIC through VPC connector).",
        [resource.name]
    )
}

# ─── OPA Policy Bundle Required for AI Services ───────────────────────────────
# AI services must mount a policy bundle path — wires into ai-governance/opa/engine.go

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition"
    ]
    config := resource.change.after
    has_ai_model(config)
    policy_path := get_env_var(config, "POLICY_BUNDLE_PATH")
    policy_path == ""
    msg := sprintf(
        "AI-GOV-005: AI service '%s' must set POLICY_BUNDLE_PATH for OPA governance (wires into ai-governance/opa/engine.go).",
        [resource.name]
    )
}

# ─── Helper: Extract environment variable from container config ───────────────

get_env_var(config, key) := value if {
    # Cloud Run v2 container env format
    env_entry := config.template[_].containers[_].env[_]
    env_entry.name == key
    value := env_entry.value
} else := ""
```

---

## 5. `plan-with-policy.sh` Script

```bash
#!/usr/bin/env bash
# deploy/scripts/plan-with-policy.sh
# Usage: ./plan-with-policy.sh [--env dev|staging|prod] [--provider gcp|aws|azure]
#
# Runs: terraform plan → JSON export → conftest evaluate against Rego policies
# Exit codes: 0 = pass, 1 = policy violations (blocks CI), 2 = warnings only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
POLICY_DIR="${TERRAFORM_DIR}/policies"

ENV="${ENV:-dev}"
PROVIDER="${PROVIDER:-gcp}"
PLAN_FILE="${TMPDIR:-/tmp}/cloudforge-plan-${ENV}.tfplan"
PLAN_JSON="${TMPDIR:-/tmp}/cloudforge-plan-${ENV}.json"

# ─── Argument Parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --env)      ENV="$2";      shift 2 ;;
        --provider) PROVIDER="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [--env dev|staging|prod] [--provider gcp|aws|azure]"
            exit 0
            ;;
        *) echo "[!] Unknown argument: $1"; exit 1 ;;
    esac
done

ENV_DIR="${TERRAFORM_DIR}/environments/${ENV}"
if [[ ! -d "${ENV_DIR}" ]]; then
    echo "[!] Environment directory not found: ${ENV_DIR}"
    exit 1
fi

# ─── Dependency Check ─────────────────────────────────────────────────────────
for tool in terraform conftest jq; do
    if ! command -v "${tool}" &>/dev/null; then
        echo "[!] Required tool not found: ${tool}"
        echo "    Install: https://developer.hashicorp.com/terraform | https://www.conftest.dev | https://jqlang.org"
        exit 1
    fi
done

echo "[*] CloudForge Policy-Gated Plan"
echo "    Environment : ${ENV}"
echo "    Provider    : ${PROVIDER}"
echo "    Policy dir  : ${POLICY_DIR}"
echo ""

# ─── Step 1: Terraform Init + Plan ───────────────────────────────────────────
echo "[>] Step 1: terraform init"
terraform -chdir="${ENV_DIR}" init -input=false -backend=false 2>&1 | tail -5

echo "[>] Step 2: terraform plan → ${PLAN_FILE}"
terraform -chdir="${ENV_DIR}" plan \
    -var="cloud_provider=${PROVIDER}" \
    -input=false \
    -out="${PLAN_FILE}" 2>&1

# ─── Step 2: Export Plan to JSON ─────────────────────────────────────────────
echo "[>] Step 3: export plan JSON → ${PLAN_JSON}"
terraform -chdir="${ENV_DIR}" show -json "${PLAN_FILE}" > "${PLAN_JSON}"

RESOURCE_COUNT=$(jq '.resource_changes | length' "${PLAN_JSON}")
echo "    Resources in plan: ${RESOURCE_COUNT}"

# ─── Step 3: conftest Evaluation ─────────────────────────────────────────────
echo ""
echo "[>] Step 4: conftest evaluate"
echo "    Policies: $(ls "${POLICY_DIR}"/*.rego | xargs -I{} basename {})"
echo ""

CONFTEST_EXIT=0
conftest test "${PLAN_JSON}" \
    --policy "${POLICY_DIR}" \
    --namespace "terraform" \
    --output table \
    2>&1 || CONFTEST_EXIT=$?

echo ""

# ─── Step 4: Gate on Exit Code ───────────────────────────────────────────────
if [[ ${CONFTEST_EXIT} -eq 0 ]]; then
    echo "[+] All policy checks PASSED. Safe to apply."
    echo "    Run: terraform -chdir=${ENV_DIR} apply ${PLAN_FILE}"
    exit 0
elif [[ ${CONFTEST_EXIT} -eq 2 ]]; then
    echo "[!] Policy checks passed with WARNINGS. Review above before applying."
    exit 2
else
    echo "[-] Policy VIOLATIONS detected. Resolve before applying."
    echo ""
    echo "    Common remediation paths:"
    echo "    - SECURITY-*: Review encryption/public IP/TLS settings in module variables"
    echo "    - COST-*:     Downsize instance type or submit exception via CloudForge UI"
    echo "    - NAMING-*:   Ensure resource names follow {project}-{env}-{service}"
    echo "    - NETWORK-*:  Restrict security group CIDRs; move databases to private subnets"
    echo "    - AI-GOV-*:   Set AI_MODEL to approved model; add observability env vars"
    exit 1
fi
```

---

## 6. `deploy.sh` — Idempotent Deploy

```bash
#!/usr/bin/env bash
# deploy/scripts/deploy.sh
# Usage: ./deploy.sh --env dev --provider gcp [--execute]
#
# Dry-run by default. Pass --execute to actually apply.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENV="${ENV:-dev}"
PROVIDER="${PROVIDER:-gcp}"
EXECUTE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --env)      ENV="$2";      shift 2 ;;
        --provider) PROVIDER="$2"; shift 2 ;;
        --execute)  EXECUTE=true;  shift ;;
        *) echo "[!] Unknown: $1"; exit 1 ;;
    esac
done

echo "[*] CloudForge Deploy"
echo "    Environment : ${ENV}"
echo "    Provider    : ${PROVIDER}"
echo "    Execute     : ${EXECUTE}"
echo ""

# Step 1: Always run policy check first
"${SCRIPT_DIR}/plan-with-policy.sh" --env "${ENV}" --provider "${PROVIDER}"
PLAN_EXIT=$?

if [[ ${PLAN_EXIT} -eq 1 ]]; then
    echo "[-] Deploy aborted: policy violations must be resolved."
    exit 1
fi

if [[ "${EXECUTE}" != "true" ]]; then
    echo "[*] Dry-run complete. Pass --execute to apply."
    exit 0
fi

# Step 2: Apply
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
ENV_DIR="${TERRAFORM_DIR}/environments/${ENV}"
PLAN_FILE="${TMPDIR:-/tmp}/cloudforge-plan-${ENV}.tfplan"

echo "[>] Applying..."
terraform -chdir="${ENV_DIR}" apply "${PLAN_FILE}"
echo "[+] Deploy complete."
```

---

## 7. Level of Effort Estimation

### File Count

| Area | Files | Notes |
|---|---|---|
| Terraform modules | 18 | 6 modules x 3 files each |
| Environment configs | 12 | 3 envs x 4 files each |
| Rego policies | 5 | cost, security, naming, network, ai-governance |
| Dockerfiles | 2 | backend (exists), frontend (new) |
| Scripts | 2 | plan-with-policy.sh, deploy.sh |
| **Total** | **39** | |

### Complexity Per Module

| Module | Complexity | Notes |
|---|---|---|
| `compute/` | High | Three cloud providers, secret injection, scaling config |
| `database/` | Medium | Cloud SQL/RDS/Azure DB for Postgres with private VPC |
| `networking/` | High | VPC, subnets (public/private), NAT, security groups per provider |
| `auth/` | Medium | CF Access (GCP), Cognito (AWS), Azure AD B2C stub |
| `monitoring/` | Medium | Log routing, metrics export, alert policies |
| `cdn-frontend/` | Low | CF Pages/S3+CloudFront/Azure CDN — mostly static |

### Phase Breakdown

**Phase 1 — MVP (local docker-compose only, ~8 agent-hours)**
- Polish existing `Dockerfile` + `docker-compose.yml`
- Add `Dockerfile.frontend`
- Write all 5 Rego policies (already done above)
- Write `plan-with-policy.sh`
- Write `deploy.sh`
- Deliverable: `make policy-check` and `make deploy-local` work

**Phase 2 — Single Cloud (GCP Cloud Run, ~16 agent-hours)**
- Implement `compute/` module (GCP path only)
- Implement `database/` module (Cloud SQL Postgres)
- Implement `networking/` module (VPC, subnets, Cloud NAT)
- Dev environment composition
- Wire `plan-with-policy.sh` into CI (GitHub Actions)
- Deliverable: `./deploy.sh --env dev --provider gcp --execute` works end-to-end

**Phase 3 — Multi-Cloud Parity (~24 agent-hours)**
- Add AWS (ECS Fargate) path to all modules
- Add Azure (Container Apps) stubs
- Staging + prod environment configs
- Remote state (GCS bucket / S3 / Azure Blob)
- Deliverable: same modules deploy to all three providers

**Phase 4 — Production-Grade (~12 agent-hours)**
- Certificate management (ACM / Cloud Domains / Azure DNS)
- Secrets rotation automation
- Drift detection in CI
- OPA bundle auto-deploy on policy change
- Deliverable: audit-ready infrastructure

**Total:** ~60 agent-hours across 4 phases

---

## 8. Interview Talking Points by Target Company

### Deloitte — Cloud Security Architect (Manager)

**Resonant themes:** Multi-cloud governance, compliance automation, policy lifecycle

- **PaC as compliance evidence:** `plan-with-policy.sh` generates a machine-readable audit trail before every `terraform apply`. This is the technical implementation of "continuous compliance" — not just a checkbox.
- **Exception workflow:** The exception pattern in `cost.rego` + `network.rego` mirrors real enterprise GRC tooling (Archer, ServiceNow). CloudForge already has both connectors. The Rego policy calls `has_valid_exception(app_id, policy_code)` which hits the GRC backend.
- **Multi-cloud parity:** The single `compute/` module deploys to GCP/AWS/Azure via the `cloud_provider` variable. Governance policies (naming, tagging, encryption) apply identically regardless of provider — no cloud-specific policy silos.
- **Talking point:** "I built a policy-as-code layer where the same Rego rules that govern runtime API calls also gate Terraform plan evaluation. Teams get immediate, actionable feedback before infra changes land in any environment."

### Vercel — Infrastructure / Platform Role

**Resonant themes:** Developer experience, simplicity, deployment automation

- **Zero-friction gates:** `plan-with-policy.sh` outputs human-readable remediation steps when a policy fails, not just error codes. Developer sees "COST-003: database requests 200GB storage (max 100GB). Submit COST-003 exception." — actionable, not opaque.
- **Dogfooding pattern:** CloudForge deploys itself using the same governance it provides to tenants. This is the "zero-trust your own platform" credibility story.
- **Simplicity of module interface:** A dev environment wires six modules in ~50 lines of HCL. The module API is intentionally narrow — one `cloud_provider` variable, standard naming, common tags.
- **Talking point:** "Good infrastructure tooling gets out of the developer's way. Policy failures are explained, not just blocked — with specific remediation paths and links to the exception workflow."

### GitLab — Principal / Staff Engineer

**Resonant themes:** CI/CD integration, policy pipelines, open source tooling

- **Pipeline integration:** `plan-with-policy.sh` is designed as a CI step. Exit code 0 = pass, 1 = block, 2 = warn. CI can treat warnings as advisory and violations as blocking — exactly the pattern GitLab uses with SAST/DAST.
- **Policy as code in git:** Rego policies live in the repo alongside HCL. Policy changes go through the same PR review workflow as code changes. GitLab CI can run `conftest test` on every policy PR.
- **OPA + conftest:** Using conftest (HashiCorp's Rego runner for config files) over proprietary linters keeps the stack open. Any CI system can run it.
- **Talking point:** "Treating policy as a first-class artifact in the git workflow — with the same review, testing, and rollback story as application code — is how you make governance sustainable in a 200-engineer org."

### Stripe — Staff / Principal Engineer

**Resonant themes:** Security-first, cost controls, operational rigor

- **Defense in depth for infra:** Two OPA layers: compile-time (conftest against Terraform plan) and runtime (CloudForge API evaluates provisioning requests). Neither alone is sufficient; together they cover the full blast radius.
- **Cost predictability:** `COST-005` blocks max instance count > 20 at plan time. Combined with the tiered instance allowlist, unexpected spend spikes are caught before infra exists, not in the monthly bill.
- **Auditability:** Every policy evaluation returns a structured response (`allow`, `deny[]`, `warn[]`, `evaluated_at`). The decision is logged and queryable. This is the "explain any decision to any auditor" story.
- **Talking point:** "The best security control is one that's invisible to the developer but generates a paper trail for the auditor. Blocking a public database before it's created is cheaper than finding it in a pen test."

### Anthropic — Engineering Manager

**Resonant themes:** AI governance, responsible deployment, safety properties

- **`ai-governance.rego` as a Terraform gate:** Before any AI service can be deployed, its container must declare an approved model, observability endpoints, and a policy bundle path. The `POLICY_BUNDLE_PATH` requirement wires Terraform-deployed services to the in-process OPA engine in `ai-governance/opa/engine.go`.
- **Model allowlist:** The Rego `approved_models` set mirrors the model registry in `internal/ai-governance/models.go`. A model not on the list cannot be deployed — not blocked by convention, blocked by policy evaluation.
- **Egress control (`AI-GOV-004`):** AI agent services must route through the VPC — no direct internet access. This limits prompt injection surface and prevents exfiltration via model API calls.
- **Talking point:** "Responsible AI deployment requires governance at the infrastructure layer, not just the model layer. Before a container running an LLM can be deployed, it must declare its model, its observability config, and its policy bundle — otherwise terraform apply is blocked."

---

## 9. Makefile Integration (Suggested Additions)

Add to existing `Makefile`:

```makefile
# IaC targets
.PHONY: policy-check deploy-local plan-dev plan-staging plan-prod

policy-check:
	@cd deploy/scripts && ./plan-with-policy.sh --env dev --provider gcp

plan-dev:
	@cd deploy/scripts && ./plan-with-policy.sh --env dev --provider $(PROVIDER)

plan-staging:
	@cd deploy/scripts && ./plan-with-policy.sh --env staging --provider $(PROVIDER)

plan-prod:
	@cd deploy/scripts && ./plan-with-policy.sh --env prod --provider $(PROVIDER)

deploy-local:
	docker compose up -d --build
	@echo "[+] CloudForge running at http://localhost:8080"
	@echo "    OPA:     http://localhost:8181"
	@echo "    Temporal: http://localhost:8088"
```

---

## 10. Key Architectural Decisions

| Decision | Rationale |
|---|---|
| `conftest` over `terraform-compliance` | conftest uses the same OPA Rego as runtime policies — single policy language, no tool switching |
| Per-provider paths with `count` not modules | Avoids provider aliasing complexity; easier to test individual provider paths |
| Tags enforced at both plan and runtime | Plan-time catches new resources; runtime catches drift/updates via CloudForge API |
| OPA external + embedded (two tracks) | External OPA for provisioning (needs policy hot-reload); embedded for AI agent eval (needs sub-millisecond latency) |
| `POLICY_BUNDLE_PATH` required for AI services | Forces runtime policy wiring at deploy time — governance can't be opted out of |

---

*This document covers the full IaC + PaC design for CloudForge self-hosting and governance demonstration.
See `docs/architecture/` for the system architecture diagrams and `docs/DR-BC.md` for recovery runbooks.*
