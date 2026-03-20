variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-iam)"
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

variable "enable_finops" {
  description = "Create FinOps cost-reader role (Cost Explorer / Billing Viewer)"
  type        = bool
  default     = false
}

variable "enable_waf" {
  description = "Grant WAF management permissions to the app role (AWS only)"
  type        = bool
  default     = false
}

variable "enable_container_scanning" {
  description = "Grant container registry read access for image scanning"
  type        = bool
  default     = false
}

variable "gcp_project_id" {
  description = "GCP project ID for IAM bindings (GCP only)"
  type        = string
  default     = ""
}

variable "gcp_roles" {
  description = "GCP IAM roles to grant to the app service account"
  type        = list(string)
  default = [
    "roles/run.invoker",
    "roles/secretmanager.secretAccessor",
    "roles/cloudsql.client",
  ]
}

variable "azure_resource_group" {
  description = "Azure resource group name (Azure only)"
  type        = string
  default     = ""
}

variable "azure_subscription_scope" {
  description = "Azure subscription scope for role assignments (e.g., /subscriptions/{id})"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Resource tags/labels"
  type        = map(string)
  default     = {}
}
