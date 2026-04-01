terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  backend "gcs" {
    bucket = "aegis-tfstate"
    prefix = "aegis/staging"
  }
}

# ─── Networking ─────────────────────────────────────────────────────────────

module "network" {
  source         = "../../modules/network"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "staging"
  region         = var.region
  cidr_block     = "10.20.0.0/16"
  subnet_count   = 2
  enable_nat     = true
  enable_flow_logs = true
}

# ─── Database ───────────────────────────────────────────────────────────────

module "database" {
  source         = "../../modules/database"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "staging"
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  instance_tier  = "SMALL"
  storage_gb     = 50
  backup_enabled = true
  region         = var.region
}

# ─── Redis ──────────────────────────────────────────────────────────────────

module "redis" {
  source         = "../../modules/redis"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "staging"
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  memory_size_gb = 2
  ha_enabled     = true
  region         = var.region
}

# ─── Compute: Cloud Aegis API ───────────────────────────────────────────────

module "aegis_api" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "staging"
  service_name    = "api"
  container_image = var.aegis_image
  vpc_id          = module.network.vpc_id
  subnet_ids      = module.network.subnet_ids
  min_instances   = 2
  max_instances   = 5
  cpu             = "1"
  memory          = "1Gi"
  region          = var.region

  env_vars = {
    GRC_PROVIDER  = "postgres"
    OPA_URL       = "http://localhost:8181"
    TEMPORAL_HOST = "temporal:7233"
    LOG_LEVEL     = "info"
  }

  secrets = {
    AEGIS_DATABASE_URL        = "aegis-staging-db-url"
    AEGIS_JWT_SECRET     = "aegis-staging-jwt-secret"
    AEGIS_REDIS_PASSWORD = "aegis-staging-redis-password"
  }

  tags = {
    application_id = var.project_name
    environment    = "staging"
    cost_center    = "engineering"
    owner          = "platform-team"
  }
}

# ─── Compute: OPA Sidecar ──────────────────────────────────────────────────

module "opa" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "staging"
  service_name    = "opa"
  container_image = "openpolicyagent/opa:latest"
  container_port  = 8181
  vpc_id          = module.network.vpc_id
  subnet_ids      = module.network.subnet_ids
  min_instances   = 1
  max_instances   = 3
  region          = var.region

  tags = {
    application_id = var.project_name
    environment    = "staging"
    cost_center    = "engineering"
    owner          = "platform-team"
  }
}
