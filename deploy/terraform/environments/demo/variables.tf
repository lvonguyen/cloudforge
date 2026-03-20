variable "okta_org_name" {
  description = "Okta org name (e.g., 'integrator-3493576' for integrator-3493576.okta.com)"
  type        = string
  default     = "integrator-3493576"
}

variable "okta_api_token" {
  description = "Okta API token — inject via op run or TF_VAR_okta_api_token"
  type        = string
  sensitive   = true
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token — inject via op run or TF_VAR_cloudflare_api_token"
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
  default     = "ae37aa845fab76f33146ea048c81ca7d"
}
