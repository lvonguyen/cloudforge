variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "project_name" {
  description = "Cloudflare Pages project name"
  type        = string
}

variable "production_branch" {
  description = "Git branch for production deployments"
  type        = string
  default     = "main"
}

variable "build_command" {
  description = "Build command for Pages"
  type        = string
  default     = "npm run build"
}

variable "build_output_dir" {
  description = "Build output directory"
  type        = string
  default     = "dist"
}

variable "build_root_dir" {
  description = "Root directory for the build (relative to repo root)"
  type        = string
  default     = "frontend"
}

variable "env_vars" {
  description = "Environment variables for the Pages production deployment"
  type        = map(string)
  default     = {}
}
