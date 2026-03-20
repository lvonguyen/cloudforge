output "okta_client_id" {
  description = "Okta SPA client ID"
  value       = module.okta_spa.app_client_id
}

output "okta_redirect_uris" {
  description = "Configured Okta redirect URIs"
  value       = module.okta_spa.redirect_uris
}

output "pages_url" {
  description = "Cloudflare Pages URL"
  value       = module.cloudflare_pages.pages_url
}
