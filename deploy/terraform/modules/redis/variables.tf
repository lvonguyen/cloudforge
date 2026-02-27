variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-redis)"
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

variable "vpc_id" {
  description = "VPC/network ID for private connectivity"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for cache placement (AWS ElastiCache, Azure subnet delegation)"
  type        = list(string)
  default     = []
}

variable "memory_size_gb" {
  description = "Redis memory size in GB"
  type        = number
  default     = 1
}

variable "redis_version" {
  description = "Redis version (GCP format: REDIS_7_0)"
  type        = string
  default     = "REDIS_7_0"
}

variable "ha_enabled" {
  description = "Enable high-availability mode (replication/failover)"
  type        = bool
  default     = false
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
