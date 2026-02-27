output "connection_name" {
  description = "Database connection identifier (Cloud SQL connection name, RDS endpoint, or Azure FQDN)"
  value = (
    var.cloud_provider == "gcp"   ? try(google_sql_database_instance.this[0].connection_name, "") :
    var.cloud_provider == "aws"   ? try(aws_db_instance.this[0].endpoint, "") :
    var.cloud_provider == "azure" ? try(azurerm_postgresql_flexible_server.this[0].fqdn, "") :
    ""
  )
}

output "database_name" {
  description = "Name of the application database"
  value       = var.db_name
}

output "resource_name" {
  description = "Canonical resource name used across all providers"
  value       = local.resource_name
}
