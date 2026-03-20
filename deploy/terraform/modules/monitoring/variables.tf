variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-monitoring)"
  type        = string
}

variable "environment" {
  description = "Deployment environment: dev, staging, prod"
  type        = string
}

variable "region" {
  description = "Deployment region"
  type        = string
  default     = "us-central1"
}

variable "alert_emails" {
  description = "Email addresses for alert notifications"
  type        = list(string)
  default     = []
}

variable "error_rate_threshold" {
  description = "5xx error rate threshold to trigger alert"
  type        = number
  default     = 5
}

variable "cpu_threshold" {
  description = "CPU utilization percentage threshold for alerts"
  type        = number
  default     = 80
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

variable "health_check_path" {
  description = "Health check endpoint path (GCP uptime check, empty to disable)"
  type        = string
  default     = "/healthz"
}

variable "service_host" {
  description = "Service hostname for uptime checks (GCP only)"
  type        = string
  default     = ""
}

variable "gcp_project_id" {
  description = "GCP project ID (GCP only)"
  type        = string
  default     = ""
}

variable "enable_audit_log_sink" {
  description = "Enable Cloud Audit Log sink to GCS (GCP only)"
  type        = bool
  default     = true
}

variable "azure_resource_group" {
  description = "Azure resource group name (Azure only)"
  type        = string
  default     = ""
}

variable "azure_container_app_id" {
  description = "Azure Container App resource ID for metric alerts (Azure only)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Resource tags/labels"
  type        = map(string)
  default     = {}
}
