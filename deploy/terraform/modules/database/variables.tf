variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-db)"
  type        = string
}

variable "environment" {
  description = "Deployment environment: dev, staging, prod"
  type        = string
}

variable "vpc_id" {
  description = "VPC/network ID for private connectivity"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for database placement"
  type        = list(string)
}

variable "region" {
  description = "Deployment region"
  type        = string
  default     = "us-central1"
}

variable "instance_tier" {
  description = "SMALL or STANDARD — maps to provider-specific sizes"
  type        = string
  default     = "SMALL"
  validation {
    condition     = contains(["SMALL", "STANDARD"], var.instance_tier)
    error_message = "instance_tier must be SMALL or STANDARD."
  }
}

variable "db_name" {
  description = "Name of the default database to create"
  type        = string
  default     = "aegis"
}

variable "db_version" {
  description = "PostgreSQL version (GCP format: POSTGRES_15)"
  type        = string
  default     = "POSTGRES_15"
}

variable "storage_gb" {
  description = "Initial storage size in GB"
  type        = number
  default     = 20
}

variable "backup_enabled" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Resource tags/labels"
  type        = map(string)
  default     = {}
}

variable "azure_resource_group" {
  description = "Azure resource group name (Azure only)"
  type        = string
  default     = ""
}
