output "log_group_name" {
  description = "Application log group/workspace name"
  value = (
    var.cloud_provider == "gcp"   ? "" :
    var.cloud_provider == "aws"   ? try(aws_cloudwatch_log_group.app[0].name, "") :
    var.cloud_provider == "azure" ? try(azurerm_log_analytics_workspace.this[0].name, "") :
    ""
  )
}

output "alert_topic_arn" {
  description = "SNS topic ARN for alerts (AWS only, empty for others)"
  value       = var.cloud_provider == "aws" ? try(aws_sns_topic.alerts[0].arn, "") : ""
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID (Azure only, empty for others)"
  value       = var.cloud_provider == "azure" ? try(azurerm_log_analytics_workspace.this[0].id, "") : ""
}

output "resource_name" {
  description = "Canonical resource name used across all providers"
  value       = local.resource_name
}
