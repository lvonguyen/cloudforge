# deploy/terraform/policies/network-isolation.rego
# Blocks overly permissive security groups and enforces private subnet usage
package terraform.network_isolation

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Sensitive ports must never have public ingress — mirrors network.rego at runtime
sensitive_ports := {22, 3389, 5432, 3306, 27017, 6379, 9200, 8181}

# ─── Security Group Rules ────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_security_group", "aws_vpc_security_group_ingress_rule"]
    rule := get_ingress_rules(resource.change.after)[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port != 443
    rule.from_port != 80
    msg := sprintf(
        "NETWORK-001: Security group '%s' has public ingress on port %d. Only 80/443 are allowed from 0.0.0.0/0.",
        [resource.name, rule.from_port]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in ["aws_security_group", "aws_vpc_security_group_ingress_rule"]
    rule := get_ingress_rules(resource.change.after)[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port in sensitive_ports
    msg := sprintf(
        "NETWORK-002: Security group '%s' exposes sensitive port %d to the internet (0.0.0.0/0).",
        [resource.name, rule.from_port]
    )
}

get_ingress_rules(config) := rules if {
    rules := config.ingress
} else := []

# ─── GCP Firewall Rules ───────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    config := resource.change.after
    config.direction == "INGRESS"
    "0.0.0.0/0" in config.source_ranges
    not is_http_rule(config)
    msg := sprintf(
        "NETWORK-003: GCP firewall rule '%s' allows 0.0.0.0/0 ingress on non-HTTP ports.",
        [resource.name]
    )
}

is_http_rule(config) if {
    allow := config.allow[_]
    allow.ports[_] in ["80", "443"]
}

# ─── Database Private Subnet Enforcement ─────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "aws_db_instance",
        "aws_rds_cluster",
        "google_sql_database_instance"
    ]
    config := resource.change.after
    config.publicly_accessible == true
    msg := sprintf(
        "NETWORK-004: Database '%s' must not be publicly accessible. Set publicly_accessible = false.",
        [resource.name]
    )
}

# ─── OPA Server Must Not Be Publicly Accessible ───────────────────────────────
# OPA exposes all policy data — it MUST be internal-only

deny contains msg if {
    resource := input.resource_changes[_]
    contains(resource.name, "opa")
    resource.type in ["google_cloud_run_v2_service", "aws_ecs_service"]
    config := resource.change.after

    # Cloud Run: ingress must not be "all"
    ingress := config.ingress
    ingress != "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
    ingress != "INGRESS_TRAFFIC_INTERNAL_ONLY"
    msg := sprintf(
        "NETWORK-005: OPA service '%s' must use internal ingress only. OPA exposes policy data.",
        [resource.name]
    )
}
