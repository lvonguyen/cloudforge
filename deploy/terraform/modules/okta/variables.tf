variable "okta_app_label" {
  description = "Label of the existing Okta SPA application to manage"
  type        = string
}

variable "redirect_uris" {
  description = "OAuth2 login redirect URIs for the SPA"
  type        = list(string)
}

variable "post_logout_redirect_uris" {
  description = "Post-logout redirect URIs"
  type        = list(string)
  default     = []
}
