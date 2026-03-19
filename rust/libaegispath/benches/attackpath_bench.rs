use criterion::{criterion_group, criterion_main, Criterion};
use aegispath::attackpath::compute_attack_paths;
use aegispath::types::Finding;
use std::path::PathBuf;

fn find_test_fixture() -> PathBuf {
    // Walk up from the bench binary to find the project root (go.mod).
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("go.mod").exists() {
            break;
        }
        if !dir.pop() {
            panic!("could not find project root (go.mod)");
        }
    }
    // Use the trimmed test fixture (200 findings, ~370KB) for consistent benchmarks.
    // For full-scale benchmarks, switch to frontend/public/mock/findings.json (20K, 42MB).
    dir.join("cmd/server/testdata/findings_test.json")
}

fn load_findings() -> Vec<Finding> {
    let path = find_test_fixture();
    let data = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_slice(&data)
        .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

fn bench_compute(c: &mut Criterion) {
    let findings = load_findings();
    let count = findings.len();

    c.bench_function(&format!("compute_attack_paths ({count} findings)"), |b| {
        b.iter(|| {
            let result = compute_attack_paths(&findings);
            // Prevent dead code elimination
            assert!(result.stats.total_findings == count);
        });
    });
}

fn bench_deserialize(c: &mut Criterion) {
    let path = find_test_fixture();
    let raw = std::fs::read(&path).unwrap();

    c.bench_function("deserialize_findings", |b| {
        b.iter(|| {
            let findings: Vec<Finding> = serde_json::from_slice(&raw).unwrap();
            assert!(!findings.is_empty());
        });
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    let path = find_test_fixture();
    let raw = std::fs::read(&path).unwrap();

    c.bench_function("full_pipeline (deser + compute + ser)", |b| {
        b.iter(|| {
            let findings: Vec<Finding> = serde_json::from_slice(&raw).unwrap();
            let result = compute_attack_paths(&findings);
            let output = serde_json::to_vec(&result).unwrap();
            assert!(!output.is_empty());
        });
    });
}

criterion_group!(benches, bench_compute, bench_deserialize, bench_full_pipeline);
criterion_main!(benches);
