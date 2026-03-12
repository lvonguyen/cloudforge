variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  default     = "gcp"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cloudforge"
}

variable "region" {
  description = "Deployment region"
  type        = string
  default     = "us-central1"
}

variable "cloudforge_image" {
  description = "Container image URI for CloudForge API"
  type        = string
  default     = "ghcr.io/lvonguyen/cloudforge:staging"
}
