variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "haea-cg"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
}

variable "region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aegis_image" {
  description = "Container image URI for Cloud Guard API"
  type        = string
  default     = "registry.gitlab.haea.com/security/cloud-guard:latest"
}

variable "alert_emails" {
  description = "Email addresses for monitoring alerts"
  type        = list(string)
  default     = []
}

# ─── OIDC Federation ─────────────────────────────────────────────────────────

variable "oidc_issuer_url" {
  description = "GitLab OIDC issuer URL (e.g., https://gitlab.haea.com)"
  type        = string
}

variable "oidc_audience" {
  description = "OIDC audience for STS trust"
  type        = string
  default     = "sts.amazonaws.com"
}

variable "oidc_subject_claim" {
  description = "OIDC sub claim filter (e.g., project_path:security/cloud-guard:ref_type:branch:ref:main)"
  type        = string
}

# ─── AWS Tenant Accounts ─────────────────────────────────────────────────────

variable "aws_tenant_accounts" {
  description = "Map of HAEA AWS accounts for CSPM finding ingestion"
  type = map(object({
    account_id  = string
    alias       = string
    regions     = list(string)
    role_name   = optional(string, "haea-cs-read-automation")
  }))
  default = {}
  # Example:
  # {
  #   hma-prod = {
  #     account_id = "111111111111"
  #     alias      = "hma-prod"
  #     regions    = ["us-east-1", "us-west-2"]
  #   }
  #   hma-staging = {
  #     account_id = "222222222222"
  #     alias      = "hma-staging"
  #     regions    = ["us-east-1"]
  #   }
  # }
}

# ─── GCP ─────────────────────────────────────────────────────────────────────

variable "gcp_project_id" {
  description = "GCP project ID for WIF + SCC access"
  type        = string
  default     = ""
}

variable "gcp_wif_pool_id" {
  description = "Workload Identity Federation pool ID"
  type        = string
  default     = "haea-cg-cspm-pool"
}

# ─── Azure ───────────────────────────────────────────────────────────────────

variable "azure_subscription_id" {
  description = "Azure subscription ID for security reader access"
  type        = string
  default     = ""
}

variable "azure_tenant_id" {
  description = "Azure AD / Entra ID tenant ID"
  type        = string
  default     = ""
}
