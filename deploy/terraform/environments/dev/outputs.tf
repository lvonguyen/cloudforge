output "api_url" {
  description = "Cloud Aegis API service URL"
  value       = module.aegis_api.service_url
}

output "database_connection" {
  description = "Database connection identifier"
  value       = module.database.connection_name
  sensitive   = true
}

output "redis_host" {
  description = "Redis cache host"
  value       = module.redis.host
}
