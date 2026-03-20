terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
  }
}

# Okta SPA application — manage redirect URIs declaratively.
# The app itself was created in the Okta admin console; this resource
# imports it and manages only the redirect_uris + post_logout_redirect_uris.

data "okta_app_oauth" "aegis_spa" {
  label = var.okta_app_label
}

resource "okta_app_oauth" "aegis_spa" {
  label                     = data.okta_app_oauth.aegis_spa.label
  type                      = "browser"
  grant_types               = ["authorization_code"]
  response_types            = ["code"]
  token_endpoint_auth_method = "none"

  redirect_uris = var.redirect_uris

  post_logout_redirect_uris = var.post_logout_redirect_uris

  lifecycle {
    # Preserve fields managed outside Terraform
    ignore_changes = [
      profile,
      login_uri,
      logo_uri,
    ]
  }
}
