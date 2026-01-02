# policies/common/network.rego
# Network security policies for cloud resources
package cloudforge.network

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Deny public ingress on sensitive ports
sensitive_ports := [22, 3389, 5432, 3306, 27017, 6379, 9200]

deny contains msg if {
    rule := input.resource.security_group_rules[_]
    rule.direction == "ingress"
    rule.cidr == "0.0.0.0/0"
    rule.port in sensitive_ports
    
    msg := sprintf(
        "Public ingress (0.0.0.0/0) on port %d is not allowed. Use VPN or bastion access.",
        [rule.port]
    )
}

# Deny all public ingress without exception
deny contains msg if {
    rule := input.resource.security_group_rules[_]
    rule.direction == "ingress"
    rule.cidr == "0.0.0.0/0"
    
    not rule.port in [80, 443]  # HTTP/HTTPS allowed for load balancers
    not has_valid_exception(input.application.id, "NETWORK-001")
    
    msg := sprintf(
        "Public ingress on port %d requires exception approval. Submit exception for policy NETWORK-001.",
        [rule.port]
    )
}

# Warn on overly permissive CIDR ranges
warn contains msg if {
    rule := input.resource.security_group_rules[_]
    rule.direction == "ingress"
    cidr_too_broad(rule.cidr)
    rule.cidr != "0.0.0.0/0"  # Already caught by deny rule
    
    msg := sprintf(
        "Ingress rule with broad CIDR %s on port %d. Consider narrowing to specific IPs or subnets.",
        [rule.cidr, rule.port]
    )
}

# Check if CIDR is broader than /16
cidr_too_broad(cidr) if {
    parts := split(cidr, "/")
    count(parts) == 2
    prefix := to_number(parts[1])
    prefix < 16
}

# Require encryption in transit
deny contains msg if {
    input.resource.type == "database"
    not input.resource.encryption_in_transit
    
    msg := "Database must have encryption in transit enabled (SSL/TLS required)."
}

# Require encryption at rest
deny contains msg if {
    input.resource.type in ["database", "storage", "disk"]
    not input.resource.encryption_at_rest
    
    msg := sprintf(
        "%s must have encryption at rest enabled.",
        [input.resource.type]
    )
}

# VPC requirements
deny contains msg if {
    input.resource.type in ["compute", "database", "container"]
    not input.resource.vpc_id
    
    msg := "Resource must be deployed in a VPC."
}

# Private subnet requirement for databases
deny contains msg if {
    input.resource.type == "database"
    input.resource.subnet_type == "public"
    
    msg := "Databases must be deployed in private subnets only."
}

# Check for valid exception
has_valid_exception(app_id, policy_code) if {
    exception := data.exceptions[_]
    exception.application_id == app_id
    exception.policy_violated == policy_code
    exception.status == "APPROVED"
    not is_expired(exception)
}

is_expired(exception) if {
    exception.expiration_date
    time.now_ns() > time.parse_rfc3339_ns(exception.expiration_date)
}
