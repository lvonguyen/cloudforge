# policies/common/cost.rego
# Cost control policies for cloud resource provisioning
package cloudforge.cost

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Instance size tiers
# Requests for instances above STANDARD tier require finance approval
instance_tiers := {
    "aws": {
        "SMALL": ["t3.micro", "t3.small", "t3.medium"],
        "STANDARD": ["t3.large", "t3.xlarge", "m6i.large", "m6i.xlarge", "m6i.2xlarge"],
        "LARGE": ["m6i.4xlarge", "m6i.8xlarge", "r6i.large", "r6i.xlarge", "r6i.2xlarge", "r6i.4xlarge"],
        "OVERSIZED": ["m6i.12xlarge", "m6i.16xlarge", "m6i.24xlarge", "m6i.32xlarge",
                      "r6i.12xlarge", "r6i.16xlarge", "r6i.24xlarge", "r6i.32xlarge"]
    },
    "azure": {
        "SMALL": ["Standard_B1s", "Standard_B1ms", "Standard_B2s"],
        "STANDARD": ["Standard_D2s_v5", "Standard_D4s_v5", "Standard_D8s_v5"],
        "LARGE": ["Standard_D16s_v5", "Standard_D32s_v5", "Standard_E4s_v5", "Standard_E8s_v5"],
        "OVERSIZED": ["Standard_D48s_v5", "Standard_D64s_v5", "Standard_E32s_v5", "Standard_E64s_v5"]
    },
    "gcp": {
        "SMALL": ["e2-micro", "e2-small", "e2-medium"],
        "STANDARD": ["e2-standard-2", "e2-standard-4", "e2-standard-8", "n2-standard-2", "n2-standard-4"],
        "LARGE": ["n2-standard-8", "n2-standard-16", "n2-highmem-4", "n2-highmem-8"],
        "OVERSIZED": ["n2-standard-32", "n2-standard-48", "n2-standard-64", "n2-highmem-16", "n2-highmem-32"]
    }
}

# Get instance tier for a given instance type
get_instance_tier(cloud, instance_type) := tier if {
    some t in ["SMALL", "STANDARD", "LARGE", "OVERSIZED"]
    instance_type in instance_tiers[cloud][t]
    tier := t
}

# Default tier if not found (conservative - treat as oversized)
get_instance_tier(cloud, instance_type) := "UNKNOWN" if {
    not instance_type in instance_tiers[cloud]["SMALL"]
    not instance_type in instance_tiers[cloud]["STANDARD"]
    not instance_type in instance_tiers[cloud]["LARGE"]
    not instance_type in instance_tiers[cloud]["OVERSIZED"]
}

# Deny oversized instances without exception
deny contains msg if {
    cloud := input.resource.cloud_provider
    instance_type := input.resource.instance_type
    tier := get_instance_tier(cloud, instance_type)
    
    tier == "OVERSIZED"
    not has_valid_exception(input.application.id, "COST-001")
    
    msg := sprintf(
        "Instance type '%s' is in OVERSIZED tier and requires exception approval. Submit exception request for policy COST-001.",
        [instance_type]
    )
}

# Deny unknown instance types (not in approved list)
deny contains msg if {
    cloud := input.resource.cloud_provider
    instance_type := input.resource.instance_type
    tier := get_instance_tier(cloud, instance_type)
    
    tier == "UNKNOWN"
    
    msg := sprintf(
        "Instance type '%s' is not in the approved instance catalog. Contact platform team to add if needed.",
        [instance_type]
    )
}

# Warn for LARGE instances (allowed but flagged)
warn contains msg if {
    cloud := input.resource.cloud_provider
    instance_type := input.resource.instance_type
    tier := get_instance_tier(cloud, instance_type)
    
    tier == "LARGE"
    
    msg := sprintf(
        "Instance type '%s' is in LARGE tier. Consider if a smaller instance would suffice. Monthly cost estimate: $%d",
        [instance_type, estimated_monthly_cost(cloud, instance_type)]
    )
}

# Basic cost estimation (placeholder - would integrate with cloud pricing APIs)
estimated_monthly_cost(cloud, instance_type) := cost if {
    cloud == "aws"
    get_instance_tier(cloud, instance_type) == "LARGE"
    cost := 500
}

estimated_monthly_cost(cloud, instance_type) := cost if {
    cloud == "aws"
    get_instance_tier(cloud, instance_type) == "OVERSIZED"
    cost := 2000
}

estimated_monthly_cost(cloud, instance_type) := 100 if {
    true  # Default fallback
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

# Tagging requirements
required_tags := ["application_id", "environment", "cost_center", "owner"]

deny contains msg if {
    tag := required_tags[_]
    not input.resource.tags[tag]
    
    msg := sprintf(
        "Required tag '%s' is missing. All resources must have tags: %v",
        [tag, required_tags]
    )
}

# Environment validation
valid_environments := ["dev", "staging", "prod", "sandbox"]

deny contains msg if {
    env := input.resource.tags.environment
    not env in valid_environments
    
    msg := sprintf(
        "Invalid environment tag '%s'. Must be one of: %v",
        [env, valid_environments]
    )
}
