output "secret_ids" {
  description = "Map of secret name => provider-specific secret ID/ARN"
  value = (
    var.cloud_provider == "gcp"   ? { for k, v in google_secret_manager_secret.this : k => v.id } :
    var.cloud_provider == "aws"   ? { for k, v in aws_secretsmanager_secret.this : k => v.arn } :
    var.cloud_provider == "azure" ? { for k, v in azurerm_key_vault_secret.this : k => v.id } :
    {}
  )
}

output "vault_id" {
  description = "Azure Key Vault ID (empty for GCP/AWS)"
  value       = var.cloud_provider == "azure" ? try(azurerm_key_vault.this[0].id, "") : ""
}

output "vault_uri" {
  description = "Azure Key Vault URI (empty for GCP/AWS)"
  value       = var.cloud_provider == "azure" ? try(azurerm_key_vault.this[0].vault_uri, "") : ""
}

output "resource_name" {
  description = "Canonical resource name used across all providers"
  value       = local.resource_name
}
