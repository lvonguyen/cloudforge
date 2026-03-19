# NOTE: The networking module is Phase 2. When implemented, it will provision
# VPC, subnets, and firewall rules. For now, supply vpc_id and subnet_ids
# as tfvars pointing to pre-existing network resources.
#
# module "networking" {
#   source         = "../../modules/networking"
#   cloud_provider = var.cloud_provider
#   project_name   = var.project_name
#   environment    = "dev"
#   cidr_block     = "10.10.0.0/16"
# }

variable "vpc_id" {
  description = "VPC/network ID (provided until networking module is implemented)"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Subnet IDs (provided until networking module is implemented)"
  type        = list(string)
  default     = []
}

module "database" {
  source         = "../../modules/database"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "dev"
  vpc_id         = var.vpc_id
  subnet_ids     = var.subnet_ids
  instance_tier  = "SMALL"  # Passes CF cost policy
  region         = var.region
}

module "redis" {
  source         = "../../modules/redis"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "dev"
  vpc_id         = var.vpc_id
  subnet_ids     = var.subnet_ids
  memory_size_gb = 1
  ha_enabled     = false
  region         = var.region
}

module "aegis_api" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "dev"
  service_name    = "api"
  container_image = var.aegis_image
  vpc_id          = var.vpc_id
  subnet_ids      = var.subnet_ids
  min_instances   = 1
  max_instances   = 3
  region          = var.region

  env_vars = {
    GRC_PROVIDER  = "postgres"
    OPA_URL       = "http://localhost:8181"
    TEMPORAL_HOST = "temporal:7233"
  }

  secrets = {
    DATABASE_URL              = "aegis-dev-db-url"
    AEGIS_JWT_SECRET     = "aegis-dev-jwt-secret"
    AEGIS_REDIS_PASSWORD = "aegis-dev-redis-password"
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
  vpc_id          = var.vpc_id
  subnet_ids      = var.subnet_ids
  min_instances   = 1
  max_instances   = 2
  region          = var.region

  tags = {
    application_id = var.project_name
    environment    = "dev"
    cost_center    = "engineering"
    owner          = "platform-team"
  }
}
