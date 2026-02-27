output "host" {
  description = "Redis host address"
  value = (
    var.cloud_provider == "gcp"   ? try(google_redis_instance.this[0].host, "") :
    var.cloud_provider == "aws"   ? try(aws_elasticache_replication_group.this[0].primary_endpoint_address, "") :
    var.cloud_provider == "azure" ? try(azurerm_redis_cache.this[0].hostname, "") :
    ""
  )
}

output "port" {
  description = "Redis port (SSL port for Azure)"
  value = (
    var.cloud_provider == "gcp"   ? try(google_redis_instance.this[0].port, 6379) :
    var.cloud_provider == "aws"   ? 6379 :
    var.cloud_provider == "azure" ? try(azurerm_redis_cache.this[0].ssl_port, 6380) :
    6379
  )
}

output "resource_name" {
  description = "Canonical resource name used across all providers"
  value       = local.resource_name
}
