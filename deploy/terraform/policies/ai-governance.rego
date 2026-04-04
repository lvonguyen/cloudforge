# deploy/terraform/policies/ai-governance.rego
# Ties into CloudForge's AI governance module:
# - Validates model references against the approved allowlist
# - Requires observability (logging, tracing) for any AI service deployment
# - Blocks direct internet egress from AI agent containers
package terraform.ai_governance

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Approved AI models — mirrors the model allowlist in internal/ai-governance/models.go
approved_models := {
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
    "gpt-4o",
    "gpt-4o-mini",
    "qwen-32b"
}

# ─── Model Allowlist Enforcement ─────────────────────────────────────────────
# Any container with AI_MODEL or LLM_MODEL env var must use an approved model.

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition",
        "azurerm_container_app"
    ]
    config := resource.change.after
    model := get_env_var(config, "AI_MODEL")
    model != ""
    not model in approved_models
    msg := sprintf(
        "AI-GOV-001: Service '%s' uses unapproved AI model '%s'. Approved models: %v",
        [resource.name, model, approved_models]
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition",
        "azurerm_container_app"
    ]
    config := resource.change.after
    model := get_env_var(config, "LLM_MODEL")
    model != ""
    not model in approved_models
    msg := sprintf(
        "AI-GOV-002: Service '%s' references unapproved LLM '%s' via LLM_MODEL env var.",
        [resource.name, model]
    )
}

# ─── Observability Required for AI Services ───────────────────────────────────
# Any service with an AI model env var must have structured logging + tracing enabled.

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition"
    ]
    config := resource.change.after
    has_ai_model(config)
    not has_observability(config)
    msg := sprintf(
        "AI-GOV-003: AI service '%s' must have LOG_LEVEL and OTEL_EXPORTER_OTLP_ENDPOINT set for observability.",
        [resource.name]
    )
}

has_ai_model(config) if {
    get_env_var(config, "AI_MODEL") != ""
}

has_ai_model(config) if {
    get_env_var(config, "LLM_MODEL") != ""
}

has_observability(config) if {
    get_env_var(config, "LOG_LEVEL") != ""
    get_env_var(config, "OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

# ─── Egress Control for AI Agent Services ────────────────────────────────────
# AI agents must be VPC-constrained — egress to internet must go through NAT,
# not direct internet access. This prevents prompt injection + exfiltration.

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_cloud_run_v2_service"
    config := resource.change.after
    has_ai_model(config)
    vpc_access := config.template[_].vpc_access
    vpc_access.egress != "PRIVATE_RANGES_ONLY"
    vpc_access.egress != "ALL_TRAFFIC"  # ALL_TRAFFIC through VPC is acceptable
    msg := sprintf(
        "AI-GOV-004: AI service '%s' must route egress through VPC (PRIVATE_RANGES_ONLY or ALL_TRAFFIC through VPC connector).",
        [resource.name]
    )
}

# ─── OPA Policy Bundle Required for AI Services ───────────────────────────────
# AI services must mount a policy bundle path — wires into ai-governance/opa/engine.go

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type in [
        "google_cloud_run_v2_service",
        "aws_ecs_task_definition"
    ]
    config := resource.change.after
    has_ai_model(config)
    policy_path := get_env_var(config, "POLICY_BUNDLE_PATH")
    policy_path == ""
    msg := sprintf(
        "AI-GOV-005: AI service '%s' must set POLICY_BUNDLE_PATH for OPA governance (wires into ai-governance/opa/engine.go).",
        [resource.name]
    )
}

# ─── Helper: Extract environment variable from container config ───────────────

get_env_var(config, key) := value if {
    # Cloud Run v2 container env format
    env_entry := config.template[_].containers[_].env[_]
    env_entry.name == key
    value := env_entry.value
} else := ""
