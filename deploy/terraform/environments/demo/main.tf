terraform {
  required_version = ">= 1.5.0"

  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }

  # Local backend for demo environment (no shared state needed).
  # Migrate to GCS/S3 if multiple operators manage this env.
}

# ─── Providers ──────────────────────────────────────────────────────────────
# Tokens injected via:
#   op run -- terraform apply
# which resolves op:// references in env vars.

provider "okta" {
  org_name  = var.okta_org_name
  base_url  = "okta.com"
  api_token = var.okta_api_token
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ─── Okta SPA App ──────────────────────────────────────────────────────────

module "okta_spa" {
  source         = "../../modules/okta"
  okta_app_label = "CloudForge Demo"

  redirect_uris = [
    "https://cloudforge.lvonguyen.com/callback",
    "http://localhost:5173/callback",
  ]

  post_logout_redirect_uris = [
    "https://cloudforge.lvonguyen.com",
    "http://localhost:5173",
  ]
}

# ─── Cloudflare Pages ──────────────────────────────────────────────────────

module "cloudflare_pages" {
  source                 = "../../modules/cloudflare-pages"
  cloudflare_account_id  = var.cloudflare_account_id
  project_name           = "cloudforge-demo"
  production_branch      = "main"
  build_command           = "cd frontend && npm ci && npm run build"
  build_output_dir        = "frontend/dist"
  build_root_dir          = ""

  env_vars = {
    VITE_PRODUCT_NAME    = "CloudForge"
    VITE_COMPANY_NAME    = "Contoso"
    VITE_STORAGE_PREFIX  = "cloudforge"
    VITE_ENABLED_MODULES = "cloudforge,posture-management,threat-intel,remediation-engine,ops-center,attack-paths,compliance,finops"
    NODE_VERSION         = "20"
  }
}
