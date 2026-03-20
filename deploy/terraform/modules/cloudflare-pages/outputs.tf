output "pages_url" {
  description = "Cloudflare Pages production URL"
  value       = "https://${var.project_name}.pages.dev"
}

output "project_name" {
  description = "Pages project name"
  value       = cloudflare_pages_project.frontend.name
}
