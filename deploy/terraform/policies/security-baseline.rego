# deploy/terraform/policies/security-baseline.rego
# Evaluated against: terraform plan JSON (terraform show -json plan.tfplan)
# Enforces: encryption at rest/transit, no public IPs, TLS 1.2+, no default VPC
package terraform.security_baseline

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ─── Encryption at Rest ──────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "aws_db_instance",
        "aws_rds_cluster",
        "google_sql_database_instance",
        "azurerm_postgresql_flexible_server"
    ]
    config := resource.change.after
    not config.storage_encrypted
    msg := sprintf(
        "SECURITY-001: %s '%s' must have storage_encrypted = true",
        [resource.type, resource.name]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_s3_bucket"]
    not has_encryption(resource.change.after)
    msg := sprintf(
        "SECURITY-002: S3 bucket '%s' must enable server-side encryption",
        [resource.name]
    )
}

has_encryption(config) if {
    _ := config.server_side_encryption_configuration[_]
}

# ─── No Public IPs on Backend Services ───────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_cloud_run_v2_service"
    config := resource.change.after
    ingress := config.ingress
    ingress == "INGRESS_TRAFFIC_ALL"  # public — block on non-LB services
    not is_load_balancer_service(resource.name)
    msg := sprintf(
        "SECURITY-003: Cloud Run service '%s' must use VPC ingress only (not INGRESS_TRAFFIC_ALL). Use a load balancer in front.",
        [resource.name]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    config := resource.change.after
    config.associate_public_ip_address == true
    msg := sprintf(
        "SECURITY-004: EC2 instance '%s' must not have a public IP. Use NAT gateway for outbound access.",
        [resource.name]
    )
}

# Cloud Run / ECS backend services should NOT be publicly routable
# (frontend CDN / load balancers are the only public entry points)
is_load_balancer_service(name) if {
    contains(name, "frontend")
}

is_load_balancer_service(name) if {
    contains(name, "cdn")
}

# ─── TLS 1.2+ Enforcement ────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    config := resource.change.after
    config.protocol == "HTTPS"
    ssl_policy := config.ssl_policy
    ssl_policy in ["ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04"]
    msg := sprintf(
        "SECURITY-005: ALB listener '%s' must use TLS 1.2+ policy (ELBSecurityPolicy-TLS13-1-2-2021-06 or newer)",
        [resource.name]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_compute_ssl_policy"
    config := resource.change.after
    config.min_tls_version in ["TLS_1_0", "TLS_1_1"]
    msg := sprintf(
        "SECURITY-006: SSL policy '%s' must set min_tls_version = TLS_1_2 or TLS_1_3",
        [resource.name]
    )
}

# ─── No Default VPC Usage ────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_instance", "aws_ecs_service", "aws_rds_instance"]
    config := resource.change.after
    is_default_vpc(config.vpc_id)
    msg := sprintf(
        "SECURITY-007: Resource '%s' must not use the default VPC. Use a purpose-built VPC.",
        [resource.name]
    )
}

# Placeholder — in practice, query a data source for the default VPC ID
is_default_vpc(vpc_id) if {
    startswith(vpc_id, "default-")
}

# ─── IAM Least Privilege ─────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_iam_policy", "google_project_iam_binding"]
    config := resource.change.after
    has_wildcard_action(config)
    msg := sprintf(
        "SECURITY-008: IAM policy '%s' uses wildcard action '*'. Define specific permissions.",
        [resource.name]
    )
}

has_wildcard_action(config) if {
    statement := config.statement[_]
    statement.actions[_] == "*"
}
