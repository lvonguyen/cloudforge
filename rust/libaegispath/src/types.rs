use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Minimal Finding — only the 11 fields used by the attack path algorithm.
/// serde ignores unknown fields by default, so deserializing the full 56-field
/// Go JSON works without allocating unused data.
#[derive(Debug, Clone, Deserialize)]
pub struct Finding {
    pub id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub resource_name: String,
    pub cloud_provider: String,
    pub region: String,
    pub account_id: String,
    pub severity: String,
    pub category: String,
    #[serde(default)]
    pub exploit_available: bool,
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub score: f64,
    pub hop_count: usize,
    pub entry_point: AttackPathNode,
    pub target: AttackPathNode,
    pub nodes: Vec<AttackPathNode>,
    pub edges: Vec<AttackPathEdge>,
    pub mitre_tactics: Vec<String>,
    pub finding_ids: Vec<String>,
    // AI fields — not set by computeAttackPaths, included for JSON parity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_likelihood: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub ai_confidence: f64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ai_validated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_risk_narrative: Option<String>,
    #[serde(default)]
    pub ai_enriched: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub low_confidence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathNode {
    pub id: String,
    pub finding_id: String,
    pub resource_id: String,
    pub resource_name: String,
    pub resource_type: String,
    pub provider: String,
    pub account_id: String,
    pub region: String,
    pub severity: String,
    pub category: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub label: String,
    pub edge_type: String,
}

/// BTreeMap ensures keys are sorted alphabetically, matching Go's encoding/json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathStats {
    pub total_findings: usize,
    pub findings_in_paths: usize,
    pub isolated_findings: usize,
    pub coverage_percent: f64,
    pub total_paths: usize,
    pub critical_paths: usize,
    pub high_paths: usize,
    pub medium_paths: usize,
    pub by_provider: BTreeMap<String, usize>,
}

/// FFI result wrapper — serialized to JSON and returned across the C boundary.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttackPathResult {
    pub paths: Vec<AttackPath>,
    pub stats: AttackPathStats,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero_f64(f: &f64) -> bool {
    *f == 0.0
}
