output "vpc_id" {
  description = "VPC/VNet ID"
  value = (
    var.cloud_provider == "gcp"   ? try(google_compute_network.this[0].id, "") :
    var.cloud_provider == "aws"   ? try(aws_vpc.this[0].id, "") :
    var.cloud_provider == "azure" ? try(azurerm_virtual_network.this[0].id, "") :
    ""
  )
}

output "subnet_ids" {
  description = "Private subnet IDs (used by compute, database, and redis modules)"
  value = (
    var.cloud_provider == "gcp"   ? [for s in google_compute_subnetwork.private : s.id] :
    var.cloud_provider == "aws"   ? [for s in aws_subnet.private : s.id] :
    var.cloud_provider == "azure" ? [for s in azurerm_subnet.private : s.id] :
    []
  )
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value = (
    var.cloud_provider == "gcp"   ? [for s in google_compute_subnetwork.public : s.id] :
    var.cloud_provider == "aws"   ? [for s in aws_subnet.public : s.id] :
    var.cloud_provider == "azure" ? [for s in azurerm_subnet.public : s.id] :
    []
  )
}

output "nat_gateway_id" {
  description = "NAT gateway ID (empty if NAT is disabled)"
  value = (
    var.cloud_provider == "gcp"   ? try(google_compute_router_nat.this[0].id, "") :
    var.cloud_provider == "aws"   ? try(aws_nat_gateway.this[0].id, "") :
    var.cloud_provider == "azure" ? try(azurerm_nat_gateway.this[0].id, "") :
    ""
  )
}

output "resource_name" {
  description = "Canonical resource name used across all providers"
  value       = local.resource_name
}
