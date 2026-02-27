# deploy/terraform/policies/cost-guardrails.rego
# Blocks oversized instance types and storage allocations (mirrors runtime cost.rego)
package terraform.cost_guardrails

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Approved instance types — mirrors policies/common/cost.rego SMALL + STANDARD tiers
approved_aws_instance_types := {
    "t3.micro", "t3.small", "t3.medium",          # SMALL
    "t3.large", "t3.xlarge", "m6i.large",          # STANDARD
    "m6i.xlarge", "m6i.2xlarge"
}

approved_gcp_machine_types := {
    "e2-micro", "e2-small", "e2-medium",           # SMALL
    "e2-standard-2", "e2-standard-4",              # STANDARD
    "e2-standard-8", "n2-standard-2", "n2-standard-4"
}

approved_azure_vm_sizes := {
    "Standard_B1s", "Standard_B1ms", "Standard_B2s",  # SMALL
    "Standard_D2s_v5", "Standard_D4s_v5", "Standard_D8s_v5"  # STANDARD
}

# ─── Instance Type Violations ────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    instance_type := resource.change.after.instance_type
    not instance_type in approved_aws_instance_types
    msg := sprintf(
        "COST-001: EC2 instance '%s' uses unapproved type '%s'. Approved types: %v",
        [resource.name, instance_type, approved_aws_instance_types]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_compute_instance"
    machine_type := resource.change.after.machine_type
    not machine_type in approved_gcp_machine_types
    msg := sprintf(
        "COST-002: GCE instance '%s' uses unapproved machine type '%s'. Approved types: %v",
        [resource.name, machine_type, approved_gcp_machine_types]
    )
}

# ─── Storage Size Limits ─────────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "aws_db_instance",
        "google_sql_database_instance",
        "azurerm_postgresql_flexible_server"
    ]
    allocated_storage := resource.change.after.allocated_storage
    allocated_storage > 100
    msg := sprintf(
        "COST-003: Database '%s' requests %dGB storage (max 100GB without exception). Submit COST-003 exception.",
        [resource.name, allocated_storage]
    )
}

# ─── Required Tags for Cost Attribution ──────────────────────────────────────

required_tags := ["application_id", "environment", "cost_center", "owner"]

deny contains msg if {
    resource := input.resource_changes[_]
    resource.change.actions[_] in ["create", "update"]
    tag := required_tags[_]
    not resource.change.after.tags[tag]
    msg := sprintf(
        "COST-004: Resource '%s' (%s) is missing required tag '%s'",
        [resource.name, resource.type, tag]
    )
}

# ─── Auto-Scaling Upper Bound ─────────────────────────────────────────────────

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_appautoscaling_policy",
        "azurerm_container_app"
    ]
    max_count := resource.change.after.max_instance_count
    max_count > 20
    msg := sprintf(
        "COST-005: Service '%s' sets max_instance_count = %d (limit: 20). Increases require finance approval.",
        [resource.name, max_count]
    )
}
