use serde::{Deserialize, Serialize};

/// Full Finding struct — all 56 fields for round-trip JSON fidelity.
/// Used by the data loader and serializer; the attack path module uses the
/// minimal 11-field Finding from types.rs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullFinding {
    pub id: String,
    pub source: String,
    pub source_finding_id: String,
    #[serde(rename = "type")]
    pub finding_type: String,
    pub title: String,
    pub description: String,
    pub resource_type: String,
    pub resource_id: String,
    pub resource_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource_arn: String,
    pub platform: String,
    pub cloud_provider: String,
    pub region: String,
    pub account_id: String,
    pub account_name: String,
    pub environment_type: String,
    pub static_severity: String,
    pub severity: String,
    #[serde(default)]
    pub ai_risk_score: f64,
    #[serde(default)]
    pub ai_risk_level: String,
    #[serde(default)]
    pub ai_risk_rationale: String,
    #[serde(default)]
    pub ai_contextual_factors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cvss_vector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(default)]
    pub exploit_available: bool,
    #[serde(default)]
    pub cves: Vec<Cve>,
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    #[serde(default)]
    pub compliance_mappings: Vec<ComplianceMapping>,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub auto_remediatable: bool,
    pub category: String,
    pub status: String,
    #[serde(default)]
    pub workflow_status: String,
    #[serde(default)]
    pub suppressed: bool,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub line_of_business: String,
    #[serde(default)]
    pub first_found_at: String,
    #[serde(default)]
    pub last_seen_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sla_breach_date: String,
    #[serde(default)]
    pub due_date: String,
    #[serde(default)]
    pub deduplication_key: String,
    #[serde(default)]
    pub canonical_rule_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub integrity_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub nvd_url: String,
    #[serde(default)]
    pub mitre_url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cvss_vector: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cvss_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(default)]
    pub cisa_known_exploited: bool,
    #[serde(default)]
    pub published: String,
    #[serde(default)]
    pub modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapping {
    pub framework_id: String,
    pub framework_name: String,
    pub control_id: String,
    #[serde(default)]
    pub control_title: String,
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub url: String,
}

/// Maximum results per serialization call (prevents OOM on unfiltered 20K datasets).
const MAX_SERIALIZATION_LIMIT: usize = 10_000;

/// Filter passed from Go to narrow serialization output.
#[derive(Debug, Default, Deserialize)]
pub struct FindingsFilter {
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

/// Load findings from a JSON byte slice.
pub fn load_findings(data: &[u8]) -> Result<Vec<FullFinding>, serde_json::Error> {
    serde_json::from_slice(data)
}

/// Serialize findings with optional filtering.
pub fn serialize_findings(
    findings: &[FullFinding],
    filter: Option<&FindingsFilter>,
) -> Result<Vec<u8>, serde_json::Error> {
    match filter {
        None => serde_json::to_vec(findings),
        Some(f) => {
            let iter = findings.iter().filter(|finding| {
                if let Some(ref sev) = f.severity && finding.severity != *sev {
                    return false;
                }
                if let Some(ref prov) = f.provider && finding.cloud_provider != *prov {
                    return false;
                }
                if let Some(ref st) = f.status && finding.status != *st {
                    return false;
                }
                if let Some(ref cat) = f.category && finding.category != *cat {
                    return false;
                }
                true
            });

            let offset = f.offset.unwrap_or(0);
            let limit = f.limit.unwrap_or(MAX_SERIALIZATION_LIMIT);

            let filtered: Vec<&FullFinding> = iter.skip(offset).take(limit).collect();
            serde_json::to_vec(&filtered)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal_finding() {
        let json = r#"[{
            "id": "f-001",
            "source": "aws-securityhub",
            "source_finding_id": "arn:aws:...",
            "type": "vulnerability",
            "title": "Open S3 bucket",
            "description": "S3 bucket allows public access",
            "resource_type": "storage",
            "resource_id": "arn:aws:s3:::my-bucket",
            "resource_name": "my-bucket",
            "platform": "aws",
            "cloud_provider": "AWS",
            "region": "us-east-1",
            "account_id": "123456789012",
            "account_name": "prod",
            "environment_type": "production",
            "static_severity": "HIGH",
            "severity": "HIGH",
            "category": "DATA",
            "status": "ACTIVE"
        }]"#;

        let findings = load_findings(json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "f-001");
        assert_eq!(findings[0].severity, "HIGH");

        let serialized = serialize_findings(&findings, None).unwrap();
        let re_parsed: Vec<FullFinding> = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(re_parsed[0].id, "f-001");
    }

    #[test]
    fn filter_by_severity() {
        let json = r#"[
            {"id":"f1","source":"s","source_finding_id":"sf","type":"t","title":"t","description":"d",
             "resource_type":"compute","resource_id":"r1","resource_name":"R1","platform":"aws",
             "cloud_provider":"AWS","region":"us-east-1","account_id":"a","account_name":"a",
             "environment_type":"prod","static_severity":"HIGH","severity":"HIGH","category":"NET","status":"ACTIVE"},
            {"id":"f2","source":"s","source_finding_id":"sf","type":"t","title":"t","description":"d",
             "resource_type":"storage","resource_id":"r2","resource_name":"R2","platform":"aws",
             "cloud_provider":"AWS","region":"us-east-1","account_id":"a","account_name":"a",
             "environment_type":"prod","static_severity":"LOW","severity":"LOW","category":"DATA","status":"ACTIVE"}
        ]"#;

        let findings = load_findings(json.as_bytes()).unwrap();
        let filter = FindingsFilter {
            severity: Some("HIGH".to_string()),
            ..Default::default()
        };

        let result = serialize_findings(&findings, Some(&filter)).unwrap();
        let parsed: Vec<FullFinding> = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "f1");
    }

    #[test]
    fn filter_with_pagination() {
        let json = r#"[
            {"id":"f1","source":"s","source_finding_id":"s","type":"t","title":"t","description":"d",
             "resource_type":"r","resource_id":"r","resource_name":"R","platform":"p",
             "cloud_provider":"AWS","region":"r","account_id":"a","account_name":"a",
             "environment_type":"e","static_severity":"H","severity":"HIGH","category":"C","status":"ACTIVE"},
            {"id":"f2","source":"s","source_finding_id":"s","type":"t","title":"t","description":"d",
             "resource_type":"r","resource_id":"r","resource_name":"R","platform":"p",
             "cloud_provider":"AWS","region":"r","account_id":"a","account_name":"a",
             "environment_type":"e","static_severity":"H","severity":"HIGH","category":"C","status":"ACTIVE"},
            {"id":"f3","source":"s","source_finding_id":"s","type":"t","title":"t","description":"d",
             "resource_type":"r","resource_id":"r","resource_name":"R","platform":"p",
             "cloud_provider":"AWS","region":"r","account_id":"a","account_name":"a",
             "environment_type":"e","static_severity":"H","severity":"HIGH","category":"C","status":"ACTIVE"}
        ]"#;

        let findings = load_findings(json.as_bytes()).unwrap();
        let filter = FindingsFilter {
            offset: Some(1),
            limit: Some(1),
            ..Default::default()
        };

        let result = serialize_findings(&findings, Some(&filter)).unwrap();
        let parsed: Vec<FullFinding> = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "f2");
    }
}
