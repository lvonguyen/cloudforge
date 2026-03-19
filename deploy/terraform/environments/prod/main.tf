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
    prefix = "aegis/prod"
  }
}

# ─── Networking ─────────────────────────────────────────────────────────────

module "network" {
  source         = "../../modules/network"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "prod"
  region         = var.region
  cidr_block     = "10.30.0.0/16"
  subnet_count   = 3           # Multi-AZ: 3 subnets per tier
  enable_nat     = true
  enable_flow_logs = true
}

# ─── Database ───────────────────────────────────────────────────────────────

module "database" {
  source         = "../../modules/database"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "prod"
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  instance_tier  = "STANDARD"   # Production-grade sizing
  storage_gb     = 100
  backup_enabled = true
  region         = var.region
}

# ─── Redis ──────────────────────────────────────────────────────────────────

module "redis" {
  source         = "../../modules/redis"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "prod"
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  memory_size_gb = 4
  ha_enabled     = true          # Replication + automatic failover
  region         = var.region
}

# ─── Compute: Cloud Aegis API ───────────────────────────────────────────────

module "aegis_api" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "prod"
  service_name    = "api"
  container_image = var.aegis_image
  vpc_id          = module.network.vpc_id
  subnet_ids      = module.network.subnet_ids
  min_instances   = 3            # Always-on for production traffic
  max_instances   = 10
  cpu             = "2"
  memory          = "2Gi"
  region          = var.region

  env_vars = {
    GRC_PROVIDER  = "postgres"
    OPA_URL       = "http://localhost:8181"
    TEMPORAL_HOST = "temporal:7233"
    LOG_LEVEL     = "warn"
  }

  secrets = {
    DATABASE_URL              = "aegis-prod-db-url"
    AEGIS_JWT_SECRET     = "aegis-prod-jwt-secret"
    AEGIS_REDIS_PASSWORD = "aegis-prod-redis-password"
  }

  tags = {
    application_id = var.project_name
    environment    = "prod"
    cost_center    = "engineering"
    owner          = "platform-team"
  }
}

# ─── Compute: OPA Sidecar ──────────────────────────────────────────────────

module "opa" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "prod"
  service_name    = "opa"
  container_image = "openpolicyagent/opa:latest"
  container_port  = 8181
  vpc_id          = module.network.vpc_id
  subnet_ids      = module.network.subnet_ids
  min_instances   = 2
  max_instances   = 5
  region          = var.region

  tags = {
    application_id = var.project_name
    environment    = "prod"
    cost_center    = "engineering"
    owner          = "platform-team"
  }
}
