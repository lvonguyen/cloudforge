locals {
  resource_name = "${var.project_name}-${var.environment}-redis"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })
}

# ─── GCP: Memorystore Redis ──────────────────────────────────────────────────
resource "google_redis_instance" "this" {
  count                   = var.cloud_provider == "gcp" ? 1 : 0
  name                    = local.resource_name
  tier                    = var.ha_enabled ? "STANDARD_HA" : "BASIC"
  memory_size_gb          = var.memory_size_gb
  region                  = var.region
  redis_version           = var.redis_version
  authorized_network      = var.vpc_id
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  auth_enabled            = true

  labels = local.common_tags
}

# ─── AWS: ElastiCache Redis ──────────────────────────────────────────────────
resource "aws_elasticache_replication_group" "this" {
  count                      = var.cloud_provider == "aws" ? 1 : 0
  replication_group_id       = local.resource_name
  description                = "Redis cache for ${var.project_name} ${var.environment}"
  node_type                  = var.memory_size_gb <= 1 ? "cache.t3.micro" : "cache.t3.small"
  num_cache_clusters         = var.ha_enabled ? 2 : 1
  engine_version             = "7.0"
  port                       = 6379
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  automatic_failover_enabled = var.ha_enabled
  subnet_group_name          = aws_elasticache_subnet_group.this[0].name

  tags = local.common_tags
}

resource "aws_elasticache_subnet_group" "this" {
  count      = var.cloud_provider == "aws" ? 1 : 0
  name       = "${local.resource_name}-subnets"
  subnet_ids = var.subnet_ids
}

# ─── Azure: Azure Cache for Redis ────────────────────────────────────────────
resource "azurerm_redis_cache" "this" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = local.resource_name
  resource_group_name = var.azure_resource_group
  location            = var.region
  capacity            = var.memory_size_gb <= 1 ? 0 : 1
  family              = "C"
  sku_name            = var.ha_enabled ? "Standard" : "Basic"
  non_ssl_port_enabled = false
  minimum_tls_version = "1.2"
  redis_version       = "6"
  subnet_id           = length(var.subnet_ids) > 0 ? var.subnet_ids[0] : null

  redis_configuration {
    maxmemory_policy = "allkeys-lru"
  }

  tags = local.common_tags
}
