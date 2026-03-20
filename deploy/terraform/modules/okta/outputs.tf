output "app_client_id" {
  description = "Okta SPA client ID"
  value       = okta_app_oauth.aegis_spa.client_id
}

output "redirect_uris" {
  description = "Configured redirect URIs"
  value       = okta_app_oauth.aegis_spa.redirect_uris
}
