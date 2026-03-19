variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  default     = "gcp"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "aegis"
}

variable "region" {
  description = "Deployment region"
  type        = string
  default     = "us-central1"
}

variable "aegis_image" {
  description = "Container image URI for Cloud Aegis API"
  type        = string
  default     = "ghcr.io/lvonguyen/aegis:latest"
}
