output "app_role_arn" {
  description = "Application role ARN/email/principal (provider-specific)"
  value = (
    var.cloud_provider == "gcp"   ? try(google_service_account.app[0].email, "") :
    var.cloud_provider == "aws"   ? try(aws_iam_role.app[0].arn, "") :
    var.cloud_provider == "azure" ? try(azurerm_user_assigned_identity.app[0].principal_id, "") :
    ""
  )
}

output "cost_reader_role_arn" {
  description = "FinOps cost-reader role ARN/email/principal (empty if enable_finops = false)"
  value = (
    var.cloud_provider == "gcp"   ? try(google_service_account.cost_reader[0].email, "") :
    var.cloud_provider == "aws"   ? try(aws_iam_role.cost_reader[0].arn, "") :
    var.cloud_provider == "azure" ? try(azurerm_user_assigned_identity.cost_reader[0].principal_id, "") :
    ""
  )
}

output "app_identity_id" {
  description = "Azure User Assigned Identity ID (Azure only, empty for others)"
  value       = var.cloud_provider == "azure" ? try(azurerm_user_assigned_identity.app[0].id, "") : ""
}

output "resource_name" {
  description = "Canonical resource name used across all providers"
  value       = local.resource_name
}
