variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cloud_provider)
    error_message = "cloud_provider must be gcp, aws, or azure."
  }
}

variable "project_name" {
  description = "Project name (used in resource naming: {project}-{env}-{service})"
  type        = string
}

variable "environment" {
  description = "Deployment environment: dev, staging, prod"
  type        = string
}

variable "service_name" {
  description = "Service identifier (e.g., api, opa, temporal)"
  type        = string
}

variable "container_image" {
  description = "Full container image URI with tag"
  type        = string
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8080
}

variable "min_instances" {
  type    = number
  default = 1
}

variable "max_instances" {
  type    = number
  default = 5
}

variable "cpu" {
  type    = string
  default = "1"
}

variable "memory" {
  type    = string
  default = "512Mi"
}

variable "env_vars" {
  description = "Environment variables for the container"
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Secret references (name => secret_manager_path)"
  type        = map(string)
  default     = {}
}

variable "vpc_id"            { type = string }
variable "subnet_ids"        { type = list(string) }
variable "security_group_ids" {
  description = "Security group IDs for ECS network configuration (AWS only)"
  type        = list(string)
  default     = []
}
variable "service_account" {
  type    = string
  default = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "aws_ecs_cluster_id" {
  description = "ECS cluster ID (AWS only)"
  type        = string
  default     = ""
}

variable "target_group_arn" {
  description = "ALB/NLB target group ARN for ECS service registration (AWS only)"
  type        = string
  default     = ""
}

variable "azure_resource_group" {
  description = "Azure resource group name (Azure only)"
  type        = string
  default     = ""
}

variable "azure_container_env_id" {
  description = "Azure Container Apps environment ID (Azure only)"
  type        = string
  default     = ""
}
