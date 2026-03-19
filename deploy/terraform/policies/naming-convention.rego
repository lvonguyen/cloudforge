# deploy/terraform/policies/naming-convention.rego
# Enforces {project}-{env}-{service} naming pattern across all resources
package terraform.naming_convention

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Resources that must follow the naming convention
named_resource_types := {
    "aws_instance",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "google_cloud_run_v2_service",
    "google_sql_database_instance",
    "google_storage_bucket",
    "azurerm_container_app",
    "azurerm_postgresql_flexible_server",
    "azurerm_storage_account"
}

valid_environments := {"dev", "staging", "prod", "sandbox"}

# Pattern: {project}-{env}-{service}
# Example: aegis-prod-api, aegis-staging-opa
name_valid(name) if {
    parts := split(name, "-")
    count(parts) >= 3
    env_part := parts[1]
    env_part in valid_environments
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in named_resource_types
    resource.change.actions[_] in ["create", "update"]
    not name_valid(resource.change.after.name)
    msg := sprintf(
        "NAMING-001: Resource '%s' (%s) does not follow naming convention '{project}-{env}-{service}'. Got: '%s'",
        [resource.name, resource.type, resource.change.after.name]
    )
}

# Warn on names that look like bare service names without project prefix
warn contains msg if {
    resource := input.resource_changes[_]
    resource.type in named_resource_types
    resource.change.actions[_] == "create"
    name := resource.change.after.name
    not contains(name, "-")
    msg := sprintf(
        "NAMING-002: Resource '%s' name '%s' has no hyphens — likely missing project/env prefix",
        [resource.name, name]
    )
}
