# policies/common/regions.rego
# Region restriction policies for data residency and compliance
package cloudforge.regions

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Approved regions by classification level
# STANDARD: General workloads
# SENSITIVE: Contains PII or customer data
# RESTRICTED: Regulated data (HIPAA, PCI, etc.)

approved_regions := {
    "STANDARD": {
        "aws": ["us-east-1", "us-west-2", "eu-west-1"],
        "azure": ["eastus", "westus2", "westeurope"],
        "gcp": ["us-central1", "us-east1", "europe-west1"]
    },
    "SENSITIVE": {
        "aws": ["us-east-1", "us-west-2"],
        "azure": ["eastus", "westus2"],
        "gcp": ["us-central1", "us-east1"]
    },
    "RESTRICTED": {
        "aws": ["us-east-1"],
        "azure": ["eastus"],
        "gcp": ["us-central1"]
    }
}

# Default to STANDARD if no classification specified
default data_classification := "STANDARD"

# Get data classification from input or application metadata
data_classification := input.application.data_classification if {
    input.application.data_classification
}

# Check if region is approved for the cloud provider and data classification
region_approved if {
    cloud := input.resource.cloud_provider
    region := input.resource.region
    classification := data_classification
    
    region in approved_regions[classification][cloud]
}

# Deny rule for region violations
deny contains msg if {
    not region_approved
    not has_valid_exception(input.application.id, "REGION-001")
    
    msg := sprintf(
        "Region '%s' is not approved for %s data classification. Approved regions: %v. Submit exception request for policy REGION-001 if needed.",
        [input.resource.region, data_classification, approved_regions[data_classification][input.resource.cloud_provider]]
    )
}

# Check for valid exception in GRC system
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

# Warn if exception is expiring soon (within 30 days)
warn contains msg if {
    exception := data.exceptions[_]
    exception.application_id == input.application.id
    exception.policy_violated == "REGION-001"
    exception.status == "APPROVED"
    
    expiration := time.parse_rfc3339_ns(exception.expiration_date)
    now := time.now_ns()
    thirty_days := 30 * 24 * 60 * 60 * 1000000000
    
    expiration - now < thirty_days
    expiration > now
    
    msg := sprintf(
        "Region exception for application %s expires in less than 30 days. Renewal required.",
        [input.application.id]
    )
}
