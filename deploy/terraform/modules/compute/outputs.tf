output "service_url" {
  description = "URL of the deployed service"
  value = (
    var.cloud_provider == "gcp"   ? try(google_cloud_run_v2_service.this[0].uri, "") :
    var.cloud_provider == "aws"   ? try("https://${aws_ecs_service.this[0].name}.${var.region}.ecs.amazonaws.com", "") :
    var.cloud_provider == "azure" ? try(azurerm_container_app.this[0].latest_revision_fqdn, "") :
    ""
  )
}

output "resource_name" {
  description = "Canonical resource name used across all providers"
  value       = local.resource_name
}
