use std::collections::{BTreeMap, HashMap, HashSet};

use rayon::prelude::*;

use crate::types::*;

fn severity_rank(s: &str) -> i32 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn is_entry_point(f: &Finding) -> bool {
    if f.category == "NETWORK" {
        return true;
    }
    if f.category == "VULNERABILITY" && f.exploit_available {
        return true;
    }
    let rt = f.resource_type.to_ascii_lowercase();
    if matches!(rt.as_str(), "compute" | "container" | "serverless")
        && (f.severity == "CRITICAL" || f.severity == "HIGH")
    {
        return true;
    }
    false
}

fn is_target(f: &Finding) -> bool {
    let rt = f.resource_type.to_ascii_lowercase();
    matches!(rt.as_str(), "storage" | "database" | "secret" | "encryption")
}

fn can_connect(a: &Finding, b: &Finding) -> bool {
    if a.account_id != b.account_id {
        return false;
    }
    if a.resource_id == b.resource_id {
        return false;
    }
    a.region == b.region || a.resource_type == b.resource_type
}

/// Build a chain from entry through intermediates to target.
/// Returns None if no viable chain exists.
fn build_chain<'a>(
    entry: &'a Finding,
    intermediates: &'a [&'a Finding],
    target: &'a Finding,
) -> Option<Vec<&'a Finding>> {
    if entry.account_id != target.account_id {
        return None;
    }
    if entry.id == target.id {
        return None;
    }

    // Direct connection
    if can_connect(entry, target) {
        return Some(vec![entry, target]);
    }

    // Try to find a bridging intermediate
    for mid in intermediates {
        if mid.id == entry.id || mid.id == target.id {
            continue;
        }
        if can_connect(entry, mid)
            && can_connect(mid, target)
            && (mid.region == entry.region || mid.region == target.region)
        {
            return Some(vec![entry, mid, target]);
        }
    }

    None
}

fn infer_edge_type(from: &Finding, to: &Finding) -> &'static str {
    let to_rt = to.resource_type.to_ascii_lowercase();
    if matches!(to_rt.as_str(), "storage" | "database" | "secret") {
        return "data_access";
    }
    if from.category == "IDENTITY" || to.category == "IDENTITY" {
        return "iam_trust";
    }
    if from.category == "NETWORK" || to.category == "NETWORK" {
        return "network_reachable";
    }
    "lateral_movement"
}

fn edge_type_label(edge_type: &str) -> &str {
    match edge_type {
        "network_reachable" => "network access",
        "data_access" => "data access",
        "iam_trust" => "IAM trust",
        "lateral_movement" => "lateral movement",
        other => other, // match Go: return raw edge_type for unknown types
    }
}

fn build_attack_path(id: &str, account_id: &str, chain: &[&Finding]) -> AttackPath {
    let mut nodes = Vec::with_capacity(chain.len());
    let mut edges = Vec::with_capacity(chain.len().saturating_sub(1));
    let mut finding_ids = Vec::with_capacity(chain.len());
    let mut tactics_set = HashSet::new();
    let mut max_severity = "LOW";
    let mut score: f64 = 0.0;

    for (i, f) in chain.iter().enumerate() {
        let node_id = format!("{id}-node-{i}");
        nodes.push(AttackPathNode {
            id: node_id.clone(),
            finding_id: f.id.clone(),
            resource_id: f.resource_id.clone(),
            resource_name: f.resource_name.clone(),
            resource_type: f.resource_type.clone(),
            provider: f.cloud_provider.clone(),
            account_id: f.account_id.clone(),
            region: f.region.clone(),
            severity: f.severity.clone(),
            category: f.category.clone(),
            label: f.resource_name.clone(),
        });
        finding_ids.push(f.id.clone());

        if severity_rank(&f.severity) > severity_rank(max_severity) {
            max_severity = match f.severity.as_str() {
                "CRITICAL" => "CRITICAL",
                "HIGH" => "HIGH",
                "MEDIUM" => "MEDIUM",
                "LOW" => "LOW",
                _ => max_severity,
            };
        }
        score += severity_rank(&f.severity) as f64 * 25.0;

        for t in &f.mitre_tactics {
            tactics_set.insert(t.clone());
        }

        if i > 0 {
            let edge_type = infer_edge_type(chain[i - 1], f);
            edges.push(AttackPathEdge {
                id: format!("{id}-edge-{}", i - 1),
                source: format!("{id}-node-{}", i - 1),
                target: node_id,
                label: edge_type_label(edge_type).to_string(),
                edge_type: edge_type.to_string(),
            });
        }
    }

    if score > 100.0 {
        score = 100.0;
    }

    let mut tactics: Vec<String> = tactics_set.into_iter().collect();
    tactics.sort();

    let first = chain.first().unwrap();
    let last = chain.last().unwrap();
    let title = format!("{} \u{2192} {}", first.resource_name, last.resource_name);
    let desc = format!(
        "{}-hop path in {} account {}: {} ({}) to {} ({})",
        chain.len() - 1,
        first.cloud_provider,
        account_id,
        first.resource_name,
        first.category,
        last.resource_name,
        last.category,
    );

    AttackPath {
        id: id.to_string(),
        title,
        description: desc,
        severity: max_severity.to_string(),
        score,
        hop_count: chain.len() - 1,
        entry_point: nodes[0].clone(),
        target: nodes.last().unwrap().clone(),
        nodes,
        edges,
        mitre_tactics: tactics,
        finding_ids,
        ai_description: None,
        ai_remediation: None,
        ai_likelihood: None,
        ai_confidence: 0.0,
        ai_validated: false,
        ai_risk_narrative: None,
        ai_enriched: false,
        low_confidence: false,
    }
}

/// Per-account result collected from rayon parallel iteration.
struct AccountResult {
    paths: Vec<AttackPath>,
    findings_in_paths: HashSet<String>,
}

/// Compute attack paths from findings using BFS with rayon parallelism.
///
/// Algorithm (mirrors Go `computeAttackPaths` in attackpath.go):
/// 1. Group findings by account_id
/// 2. For each account (in parallel via rayon):
///    a. Classify findings as entry/intermediate/target
///    b. For each (entry, target) pair, try buildChain
///    c. Build lateral movement paths for HIGH/CRITICAL findings not in paths
/// 3. Merge results, sort by severity desc then score desc
/// 4. Compute coverage statistics
pub fn compute_attack_paths(findings: &[Finding]) -> AttackPathResult {
    if findings.is_empty() {
        return AttackPathResult {
            paths: vec![],
            stats: AttackPathStats {
                total_findings: 0,
                findings_in_paths: 0,
                isolated_findings: 0,
                coverage_percent: 0.0,
                total_paths: 0,
                critical_paths: 0,
                high_paths: 0,
                medium_paths: 0,
                by_provider: BTreeMap::new(),
            },
        };
    }

    // Group by account
    let mut by_account: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_account.entry(f.account_id.as_str()).or_default().push(f);
    }

    // Collect account keys for deterministic ordering (matches Go map iteration stability)
    let mut account_keys: Vec<&str> = by_account.keys().copied().collect();
    account_keys.sort();

    // Process each account in parallel using rayon
    let account_results: Vec<AccountResult> = account_keys
        .par_iter()
        .map(|&account_id| {
            let account_findings = &by_account[account_id];
            if account_findings.len() < 2 {
                return AccountResult {
                    paths: vec![],
                    findings_in_paths: HashSet::new(),
                };
            }

            let mut entry_points = Vec::new();
            let mut intermediates = Vec::new();
            let mut targets = Vec::new();

            for f in account_findings {
                if is_entry_point(f) {
                    entry_points.push(*f);
                } else if is_target(f) {
                    targets.push(*f);
                } else {
                    intermediates.push(*f);
                }
            }

            let mut paths = Vec::new();
            let mut findings_in_paths = HashSet::new();
            let mut path_id = 0usize;

            // Entry → target chains
            for entry in &entry_points {
                for target in &targets {
                    if let Some(chain) = build_chain(entry, &intermediates, target) {
                        path_id += 1;
                        // Placeholder ID — will be renumbered after merge
                        let id = format!("{account_id}-{path_id:03}");
                        let path = build_attack_path(&id, account_id, &chain);
                        for f in &chain {
                            findings_in_paths.insert(f.id.clone());
                        }
                        paths.push(path);
                    }
                }
            }

            // Lateral movement for HIGH/CRITICAL findings not already in paths
            for (i, f1) in account_findings.iter().enumerate() {
                if findings_in_paths.contains(&f1.id) {
                    continue;
                }
                if severity_rank(&f1.severity) < 3 {
                    continue;
                }
                for f2 in &account_findings[i + 1..] {
                    if severity_rank(&f2.severity) < 3 {
                        continue;
                    }
                    if findings_in_paths.contains(&f2.id) {
                        continue;
                    }
                    if can_connect(f1, f2) {
                        path_id += 1;
                        let id = format!("{account_id}-{path_id:03}");
                        let chain = vec![*f1, *f2];
                        let path = build_attack_path(&id, account_id, &chain);
                        findings_in_paths.insert(f1.id.clone());
                        findings_in_paths.insert(f2.id.clone());
                        paths.push(path);
                    }
                }
            }

            AccountResult {
                paths,
                findings_in_paths,
            }
        })
        .collect();

    // Merge results and assign global IDs
    let mut all_paths = Vec::new();
    let mut all_findings_in_paths = HashSet::new();
    let mut global_id = 0usize;

    for result in account_results {
        for mut path in result.paths {
            global_id += 1;
            let new_id = format!("ap-{global_id:03}");

            // Rewrite all internal IDs: strip old prefix, prepend new global ID.
            // Uses strip_prefix instead of str::replace to avoid substring collisions.
            let old_id = path.id.clone();
            path.id = new_id.clone();
            let rewrite = |s: &str| -> String {
                s.strip_prefix(old_id.as_str())
                    .map(|suffix| format!("{new_id}{suffix}"))
                    .unwrap_or_else(|| s.to_string())
            };
            path.entry_point.id = rewrite(&path.entry_point.id);
            path.target.id = rewrite(&path.target.id);
            for node in &mut path.nodes {
                node.id = rewrite(&node.id);
            }
            for edge in &mut path.edges {
                edge.id = rewrite(&edge.id);
                edge.source = rewrite(&edge.source);
                edge.target = rewrite(&edge.target);
            }

            all_paths.push(path);
        }
        all_findings_in_paths.extend(result.findings_in_paths);
    }

    // Sort: severity descending, then score descending (matches Go sort.Slice)
    all_paths.sort_by(|a, b| {
        let ra = severity_rank(&a.severity);
        let rb = severity_rank(&b.severity);
        if ra != rb {
            return rb.cmp(&ra);
        }
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Compute stats
    let findings_in_count = all_findings_in_paths.len();
    let total = findings.len();
    let coverage = if total > 0 {
        findings_in_count as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    let mut critical_paths = 0;
    let mut high_paths = 0;
    let mut medium_paths = 0;
    let mut by_provider: BTreeMap<String, usize> = BTreeMap::new();

    for p in &all_paths {
        match p.severity.as_str() {
            "CRITICAL" => critical_paths += 1,
            "HIGH" => high_paths += 1,
            _ => medium_paths += 1,
        }
        if let Some(first_node) = p.nodes.first() {
            *by_provider.entry(first_node.provider.clone()).or_default() += 1;
        }
    }

    AttackPathResult {
        paths: all_paths,
        stats: AttackPathStats {
            total_findings: total,
            findings_in_paths: findings_in_count,
            isolated_findings: total - findings_in_count,
            coverage_percent: coverage,
            total_paths: global_id,
            critical_paths,
            high_paths,
            medium_paths,
            by_provider,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(id: &str, account: &str, region: &str, rtype: &str, cat: &str, sev: &str) -> Finding {
        Finding {
            id: id.to_string(),
            resource_type: rtype.to_string(),
            resource_id: format!("res-{id}"),
            resource_name: format!("Resource {id}"),
            cloud_provider: "AWS".to_string(),
            region: region.to_string(),
            account_id: account.to_string(),
            severity: sev.to_string(),
            category: cat.to_string(),
            exploit_available: cat == "VULNERABILITY",
            mitre_tactics: vec![],
        }
    }

    #[test]
    fn empty_findings() {
        let result = compute_attack_paths(&[]);
        assert!(result.paths.is_empty());
        assert_eq!(result.stats.total_findings, 0);
    }

    #[test]
    fn single_finding_no_paths() {
        let findings = vec![make_finding("f1", "acct-1", "us-east-1", "compute", "NETWORK", "HIGH")];
        let result = compute_attack_paths(&findings);
        assert!(result.paths.is_empty());
        assert_eq!(result.stats.isolated_findings, 1);
    }

    #[test]
    fn direct_entry_to_target() {
        let findings = vec![
            make_finding("f1", "acct-1", "us-east-1", "compute", "NETWORK", "HIGH"),
            make_finding("f2", "acct-1", "us-east-1", "storage", "DATA", "CRITICAL"),
        ];
        let result = compute_attack_paths(&findings);
        assert_eq!(result.paths.len(), 1);
        assert_eq!(result.paths[0].hop_count, 1);
        assert_eq!(result.paths[0].nodes.len(), 2);
        assert_eq!(result.stats.findings_in_paths, 2);
    }

    #[test]
    fn three_hop_chain() {
        let findings = vec![
            make_finding("f1", "acct-1", "us-east-1", "compute", "NETWORK", "HIGH"),
            make_finding("f2", "acct-1", "us-east-1", "container", "IDENTITY", "MEDIUM"),
            make_finding("f3", "acct-1", "us-east-1", "storage", "DATA", "CRITICAL"),
        ];
        let result = compute_attack_paths(&findings);
        assert!(!result.paths.is_empty());
        // Should find at least a direct or indirect path
        let max_hops = result.paths.iter().map(|p| p.hop_count).max().unwrap_or(0);
        assert!(max_hops >= 1);
    }

    #[test]
    fn cross_account_no_path() {
        let findings = vec![
            make_finding("f1", "acct-1", "us-east-1", "compute", "NETWORK", "HIGH"),
            make_finding("f2", "acct-2", "us-east-1", "storage", "DATA", "CRITICAL"),
        ];
        let result = compute_attack_paths(&findings);
        assert!(result.paths.is_empty());
    }

    #[test]
    fn lateral_movement() {
        let findings = vec![
            make_finding("f1", "acct-1", "us-east-1", "iam", "IDENTITY", "CRITICAL"),
            make_finding("f2", "acct-1", "us-east-1", "iam", "IDENTITY", "HIGH"),
        ];
        let result = compute_attack_paths(&findings);
        // Both are HIGH+ and in same region, should get a lateral movement path
        assert_eq!(result.paths.len(), 1);
    }

    #[test]
    fn severity_sorting() {
        let findings = vec![
            make_finding("f1", "acct-1", "us-east-1", "compute", "NETWORK", "MEDIUM"),
            make_finding("f2", "acct-1", "us-east-1", "storage", "DATA", "MEDIUM"),
            make_finding("f3", "acct-2", "us-west-2", "compute", "NETWORK", "HIGH"),
            make_finding("f4", "acct-2", "us-west-2", "storage", "DATA", "CRITICAL"),
        ];
        let result = compute_attack_paths(&findings);
        if result.paths.len() >= 2 {
            assert!(severity_rank(&result.paths[0].severity) >= severity_rank(&result.paths[1].severity));
        }
    }

    #[test]
    fn stats_coverage() {
        let findings = vec![
            make_finding("f1", "acct-1", "us-east-1", "compute", "NETWORK", "HIGH"),
            make_finding("f2", "acct-1", "us-east-1", "storage", "DATA", "CRITICAL"),
            make_finding("f3", "acct-1", "us-west-2", "iam", "IDENTITY", "LOW"),
        ];
        let result = compute_attack_paths(&findings);
        assert_eq!(result.stats.total_findings, 3);
        assert!(result.stats.coverage_percent > 0.0);
        assert_eq!(
            result.stats.findings_in_paths + result.stats.isolated_findings,
            result.stats.total_findings
        );
    }

    #[test]
    fn edge_type_label_passthrough() {
        assert_eq!(edge_type_label("network_reachable"), "network access");
        assert_eq!(edge_type_label("data_access"), "data access");
        assert_eq!(edge_type_label("iam_trust"), "IAM trust");
        assert_eq!(edge_type_label("lateral_movement"), "lateral movement");
        // Unknown types pass through (matches Go behavior)
        assert_eq!(edge_type_label("custom_type"), "custom_type");
        assert_eq!(edge_type_label(""), "");
    }
}
