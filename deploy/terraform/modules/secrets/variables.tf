variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-secrets)"
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

variable "secret_names" {
  description = "Set of secret names to provision (values populated out-of-band via 1Password or console)"
  type        = set(string)
  default     = []
}

variable "service_account" {
  description = "Service account email granted accessor role (GCP only)"
  type        = string
  default     = ""
}

variable "kms_key_id" {
  description = "KMS key ARN for secret encryption (AWS only, uses default aws/secretsmanager if empty)"
  type        = string
  default     = ""
}

variable "enable_rotation" {
  description = "Enable automatic secret rotation (AWS only)"
  type        = bool
  default     = false
}

variable "rotation_lambda_arn" {
  description = "Lambda ARN for secret rotation (AWS only, required if enable_rotation = true)"
  type        = string
  default     = ""
}

variable "rotation_days" {
  description = "Rotate secrets every N days (AWS only)"
  type        = number
  default     = 30
}

variable "azure_tenant_id" {
  description = "Azure AD tenant ID (Azure only)"
  type        = string
  default     = ""
}

variable "azure_resource_group" {
  description = "Azure resource group name (Azure only)"
  type        = string
  default     = ""
}

variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access the Key Vault (Azure only)"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Resource tags/labels"
  type        = map(string)
  default     = {}
}
