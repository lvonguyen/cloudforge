locals {
  resource_name = "${var.project_name}-${var.environment}-monitoring"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })
}

# ─── GCP: Cloud Monitoring + Log Sink + Uptime Checks ─────────────────────────

resource "google_monitoring_notification_channel" "email" {
  count        = var.cloud_provider == "gcp" ? length(var.alert_emails) : 0
  display_name = "${local.resource_name}-email-${count.index}"
  type         = "email"

  labels = {
    email_address = var.alert_emails[count.index]
  }
}

resource "google_monitoring_alert_policy" "high_error_rate" {
  count        = var.cloud_provider == "gcp" ? 1 : 0
  display_name = "${local.resource_name}-high-error-rate"
  combiner     = "OR"

  conditions {
    display_name = "Error rate > ${var.error_rate_threshold}%"

    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/request_count\" AND metric.labels.response_code_class=\"5xx\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.error_rate_threshold
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [for ch in google_monitoring_notification_channel.email : ch.id]
}

resource "google_monitoring_uptime_check_config" "health" {
  count        = var.cloud_provider == "gcp" && var.health_check_path != "" ? 1 : 0
  display_name = "${local.resource_name}-health"
  timeout      = "10s"
  period       = "60s"

  http_check {
    path         = var.health_check_path
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.gcp_project_id
      host       = var.service_host
    }
  }
}

resource "google_logging_project_sink" "audit" {
  count                  = var.cloud_provider == "gcp" && var.enable_audit_log_sink ? 1 : 0
  name                   = "${local.resource_name}-audit-sink"
  destination            = "storage.googleapis.com/${google_storage_bucket.audit_logs[0].name}"
  filter                 = "logName:\"logs/cloudaudit.googleapis.com\""
  unique_writer_identity = true
}

resource "google_storage_bucket" "audit_logs" {
  count         = var.cloud_provider == "gcp" && var.enable_audit_log_sink ? 1 : 0
  name          = "${local.resource_name}-audit-logs"
  location      = var.region
  force_destroy = var.environment != "prod"
  storage_class = "STANDARD"

  lifecycle_rule {
    action { type = "Delete" }
    condition { age = var.log_retention_days }
  }

  labels = local.common_tags
}

# ─── AWS: CloudWatch Alarms + Log Groups + SNS ────────────────────────────────

resource "aws_sns_topic" "alerts" {
  count = var.cloud_provider == "aws" ? 1 : 0
  name  = "${local.resource_name}-alerts"
  tags  = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.cloud_provider == "aws" ? length(var.alert_emails) : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_emails[count.index]
}

resource "aws_cloudwatch_log_group" "app" {
  count             = var.cloud_provider == "aws" ? 1 : 0
  name              = "/aegis/${var.environment}/app"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "audit" {
  count             = var.cloud_provider == "aws" ? 1 : 0
  name              = "/aegis/${var.environment}/audit"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  count               = var.cloud_provider == "aws" ? 1 : 0
  alarm_name          = "${local.resource_name}-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "5XXError"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Sum"
  threshold           = var.error_rate_threshold
  alarm_description   = "High 5xx error rate for ${var.project_name} ${var.environment}"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  ok_actions          = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    ServiceName = "${var.project_name}-${var.environment}-api"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  count               = var.cloud_provider == "aws" ? 1 : 0
  alarm_name          = "${local.resource_name}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = var.cpu_threshold
  alarm_description   = "High CPU utilization for ${var.project_name} ${var.environment}"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    ServiceName = "${var.project_name}-${var.environment}-api"
  }

  tags = local.common_tags
}

# ─── Azure: Monitor Action Group + Metric Alerts + Log Analytics ──────────────

resource "azurerm_log_analytics_workspace" "this" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = local.resource_name
  resource_group_name = var.azure_resource_group
  location            = var.region
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = local.common_tags
}

resource "azurerm_monitor_action_group" "alerts" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = "${local.resource_name}-alerts"
  resource_group_name = var.azure_resource_group
  short_name          = "aegis-alert"

  dynamic "email_receiver" {
    for_each = var.alert_emails
    content {
      name                    = "alert-${email_receiver.key}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "high_error_rate" {
  count               = var.cloud_provider == "azure" && var.azure_container_app_id != "" ? 1 : 0
  name                = "${local.resource_name}-high-error-rate"
  resource_group_name = var.azure_resource_group
  scopes              = [var.azure_container_app_id]
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"

  criteria {
    metric_namespace = "Microsoft.App/containerApps"
    metric_name      = "Requests"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = var.error_rate_threshold

    dimension {
      name     = "statusCodeCategory"
      operator = "Include"
      values   = ["5xx"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.alerts[0].id
  }

  tags = local.common_tags
}
