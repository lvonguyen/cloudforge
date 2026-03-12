variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-network)"
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

variable "cidr_block" {
  description = "CIDR block for the VPC/VNet (e.g., 10.0.0.0/16)"
  type        = string
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "cidr_block must be a valid CIDR notation (e.g., 10.0.0.0/16)."
  }
}

variable "subnet_count" {
  description = "Number of subnets per tier (public and private)"
  type        = number
  default     = 2
  validation {
    condition     = var.subnet_count >= 1 && var.subnet_count <= 6
    error_message = "subnet_count must be between 1 and 6."
  }
}

variable "enable_nat" {
  description = "Enable NAT gateway for private subnet internet access"
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs for network traffic monitoring"
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
