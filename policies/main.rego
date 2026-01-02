# policies/main.rego
# Main entry point for CloudForge policy evaluation
package cloudforge

import future.keywords.if
import future.keywords.in
import future.keywords.contains

import data.cloudforge.regions
import data.cloudforge.cost
import data.cloudforge.network

# Aggregate all deny messages from sub-policies
deny contains msg if {
    msg := regions.deny[_]
}

deny contains msg if {
    msg := cost.deny[_]
}

deny contains msg if {
    msg := network.deny[_]
}

# Aggregate all warnings
warn contains msg if {
    msg := regions.warn[_]
}

warn contains msg if {
    msg := cost.warn[_]
}

warn contains msg if {
    msg := network.warn[_]
}

# Main decision - allow if no deny messages
default allow := false

allow if {
    count(deny) == 0
}

# Response structure for policy evaluation
response := {
    "allow": allow,
    "deny": deny,
    "warn": warn,
    "application_id": input.application.id,
    "resource_type": input.resource.type,
    "evaluated_at": time.now_ns()
}
