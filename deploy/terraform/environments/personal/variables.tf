variable "cloud_provider" {
  description = "Target cloud: gcp, aws, azure"
  type        = string
  default     = "aws"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "aegis"
}

variable "region" {
  description = "AWS region (us-east-1 matches existing SecurityHub findings)"
  type        = string
  default     = "us-east-1"
}

variable "alert_emails" {
  description = "Email addresses for monitoring alert notifications"
  type        = list(string)
  default     = ["liem@vonguyen.io"]
}

variable "deploy_puppygraph" {
  description = "Deploy PuppyGraph graph database (adds ~$181/mo for r6i.xlarge)"
  type        = bool
  default     = false
}

variable "puppygraph_allowed_cidr" {
  description = "CIDR for PuppyGraph UI/SSH access (your IP + /32)"
  type        = string
  default     = "47.156.79.74/32"
}
