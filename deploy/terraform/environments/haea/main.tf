# ─── HAEA Cloud Guard — Production Environment ───────────────────────────────
#
# Naming convention:
#   Project:  haea-cg (HAEA Cloud Guard)
#   Roles:    haea-cg-cspm-reader, haea-cg-cost-reader, haea-cg-app
#   Tags:     application_id=haea-cg, cost_center=security, owner=haea-security-tft
#
# Architecture:
#   Central security account hosts: API, OIDC provider, state, secrets
#   Tenant accounts host: haea-cg-cspm-reader role (cross-account trust)
#   GCP: WIF pool → service account with SCC Viewer
#   Azure: Federated identity credential → Security Reader
#
# CSPM reader policies are in cspm-readers.tf

# ─── Networking ──────────────────────────────────────────────────────────────

module "network" {
  source         = "../../modules/network"
  cloud_provider = "aws"
  project_name   = var.project_name
  environment    = var.environment
  region         = var.region
  cidr_block     = "10.40.0.0/16"
  subnet_count   = 3
  enable_nat     = true
  enable_flow_logs = true
}

# ─── Database ────────────────────────────────────────────────────────────────

module "database" {
  source         = "../../modules/database"
  cloud_provider = "aws"
  project_name   = var.project_name
  environment    = var.environment
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  instance_tier  = "STANDARD"
  storage_gb     = 50
  backup_enabled = true
  region         = var.region
}

# ─── Redis ───────────────────────────────────────────────────────────────────

module "redis" {
  source         = "../../modules/redis"
  cloud_provider = "aws"
  project_name   = var.project_name
  environment    = var.environment
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  memory_size_gb = 2
  ha_enabled     = true
  region         = var.region
}

# ─── Compute: Cloud Guard API ────────────────────────────────────────────────

module "aegis_api" {
  source          = "../../modules/compute"
  cloud_provider  = "aws"
  project_name    = var.project_name
  environment     = var.environment
  service_name    = "api"
  container_image = var.aegis_image
  vpc_id          = module.network.vpc_id
  subnet_ids      = module.network.subnet_ids
  min_instances   = 2
  max_instances   = 6
  cpu             = "2"
  memory          = "2Gi"
  region          = var.region

  env_vars = {
    APP_ENV                = "production"
    GRC_PROVIDER           = "postgres"
    IDENTITY_PROVIDER      = "okta"
    CONTAINER_SCANNER      = "trivy"
    FINOPS_PROVIDER        = "aws"
    AEGIS_AI_ENABLED       = "true"
    AEGIS_AI_REGION        = var.region
    AEGIS_TRACING_ENABLED  = "true"
    RATE_LIMIT_ENABLED     = "true"
    OPA_URL                = "http://localhost:8181"
    LOG_LEVEL              = "warn"
  }

  secrets = {
    DATABASE_URL              = "${var.project_name}-${var.environment}-db-url"
    AEGIS_JWT_SECRET          = "${var.project_name}-${var.environment}-jwt-secret"
    AEGIS_REDIS_PASSWORD      = "${var.project_name}-${var.environment}-redis-password"
    OKTA_API_TOKEN            = "${var.project_name}-${var.environment}-okta-api-token"
    GREYNOISE_API_KEY         = "${var.project_name}-${var.environment}-greynoise-key"
    HIBP_API_KEY              = "${var.project_name}-${var.environment}-hibp-key"
    OTX_API_KEY               = "${var.project_name}-${var.environment}-otx-key"
    ASANA_PAT                 = "${var.project_name}-${var.environment}-asana-pat"
    ASANA_WEBHOOK_TOKEN       = "${var.project_name}-${var.environment}-asana-webhook-token"
  }

  tags = {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "security"
    owner          = "haea-security-tft"
  }
}

# ─── Compute: OPA Sidecar ───────────────────────────────────────────────────

module "opa" {
  source          = "../../modules/compute"
  cloud_provider  = "aws"
  project_name    = var.project_name
  environment     = var.environment
  service_name    = "opa"
  container_image = "openpolicyagent/opa:latest"
  container_port  = 8181
  vpc_id          = module.network.vpc_id
  subnet_ids      = module.network.subnet_ids
  min_instances   = 2
  max_instances   = 4
  region          = var.region

  tags = {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "security"
    owner          = "haea-security-tft"
  }
}

# ─── Secrets Manager ─────────────────────────────────────────────────────────

module "secrets" {
  source         = "../../modules/secrets"
  cloud_provider = "aws"
  project_name   = var.project_name
  environment    = var.environment
  region         = var.region

  secret_names = toset([
    "db-url",
    "jwt-secret",
    "redis-password",
    "okta-api-token",
    "greynoise-key",
    "hibp-key",
    "otx-key",
    "asana-pat",
    "asana-webhook-token",
    "bedrock-access-key",
    "bedrock-secret-key",
  ])

  tags = {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "security"
    owner          = "haea-security-tft"
  }
}

# ─── IAM: App Runtime Roles ──────────────────────────────────────────────────

module "iam" {
  source                    = "../../modules/iam"
  cloud_provider            = "aws"
  project_name              = var.project_name
  environment               = var.environment
  region                    = var.region
  enable_finops             = true
  enable_container_scanning = true
  enable_waf                = false

  tags = {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "security"
    owner          = "haea-security-tft"
  }
}

# ─── Monitoring ──────────────────────────────────────────────────────────────

module "monitoring" {
  source         = "../../modules/monitoring"
  cloud_provider = "aws"
  project_name   = var.project_name
  environment    = var.environment
  region         = var.region
  alert_emails   = var.alert_emails

  tags = {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "security"
    owner          = "haea-security-tft"
  }
}

# ─── CSPM reader roles + OIDC federation are in cspm-readers.tf ──────────────
