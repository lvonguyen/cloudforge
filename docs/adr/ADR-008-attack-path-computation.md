# ADR-008: Attack Path Computation Strategy

## Status
Accepted

## Context

CloudForge aggregates security findings across multi-cloud environments (AWS, Azure, GCP). With 10K+ active findings in a typical enterprise deployment, individual finding triage creates alert fatigue. Industry leaders (Wiz, Orca) demonstrate that graph-based attack path analysis collapses thousands of isolated findings into dozens of actionable chains — achieving ~98% noise reduction.

The project already has:
- `AttackPathContext` struct in `internal/cspm/normalizer/schema.go` (score, blast radius, toxic combo flags)
- `attack_path` field on the Finding type (frontend + backend)
- Risk scoring integration in `internal/cspm/scoring/risk_scorer.go` that includes attack path context
- Detailed research doc: `docs/research/wiz-attack-path-enhancements.md`

The question is: what level of implementation is appropriate for a portfolio reference implementation vs. a production system?

## Decision

Implement an **in-memory graph engine** with deterministic path computation from existing findings data. No external graph database dependency (Neo4j/Neptune deferred to production roadmap).

### Approach — Tier A+B Hybrid

1. **In-memory adjacency graph** built at startup from loaded findings
   - Nodes: resources extracted from findings (keyed by resource_id)
   - Edges: inferred relationships within the same account (same account_id + compatible resource types = reachable)
   - Edge types: network_reachable (compute -> compute), data_access (identity/compute -> storage), iam_trust (identity -> identity)

2. **BFS traversal** from entry points to sensitive targets
   - Entry points: findings with internet-exposed indicators (NETWORK category, external-facing resource types)
   - Intermediate links: IAM/identity findings, misconfiguration findings
   - Targets: storage resources, databases, data-classified resources
   - Max hop depth: 4 (matches Wiz's typical chain length)

3. **Coverage thresholds** (output guarantees):
   - 100% of CRITICAL/HIGH findings appear in at least one path or are surfaced as "isolated critical"
   - ~60-80% of MEDIUM findings participate as chain links
   - ~20-30% of LOW findings included when they complete chains
   - Remaining isolated findings deprioritized but still visible

4. **Frontend visualization** using `@xyflow/react` (ReactFlow v12) for interactive DAG rendering

### API Design

```
GET /api/v1/attack-paths           — returns all computed paths, sorted by severity
GET /api/v1/attack-paths/{id}      — returns single path with full finding details
GET /api/v1/attack-paths/stats     — returns coverage stats (findings in paths vs isolated)
```

## Consequences

### Positive

- **Zero external dependencies** — works with `go run cmd/server/main.go`
- **Sub-millisecond computation** even at 10K findings
- **Demonstrates algorithmic understanding** (BFS, graph modeling, toxic combination logic)
- **Frontend visualization** provides immediate demo impact

### Negative

- **Not suitable for production scale** (>100K findings, cross-account trust chains)
- **Edge inference is heuristic-based** (same account = reachable), not based on actual network topology

### Notes

- Production path: swap in-memory engine for Neo4j client, keep same response types
- Research doc serves as "here's how I'd architect this at Wiz scale"

## Alternatives Considered

### 1. Neo4j/Neptune Graph Database
Full graph database with Cypher queries for path computation.

**Deferred because**: Adds significant runtime dependency for a portfolio demo. The same node/edge model would back a Neo4j migration — decision is reversible. Research doc documents the production architecture with Cypher query patterns for interview discussion.

### 2. No Attack Path Computation
Display findings as a flat list only, document the architecture in research docs.

**Rejected because**: Attack path visualization is the highest-impact differentiator for the portfolio. A working demo is materially more compelling than a design document alone.

### 3. External Graph Service (Microservice)
Separate service dedicated to graph computation, communicating via gRPC.

**Deferred because**: Adds operational complexity (another container, service discovery) without proportional benefit at demo scale. Can extract later if the engine grows.

## Rust FFI Acceleration (Sprint I+1, 2026-03-18)

The BFS attack path computation was reimplemented in Rust via CGo FFI to address performance at scale:

- **libaegispath** reimplements the BFS graph engine in Rust with `rayon` parallelism for concurrent path computation across account partitions
- **CGo bridge** at `rust/bridge.go` exposes two functions: `ComputeAttackPaths` (runs the Rust BFS engine) and `LoadAndSerializeFindings` (JSON serialization for FFI boundary)
- **Performance**: Go baseline measures 119.5s for 20K findings; Rust projected 15-25s (5-8x speedup) due to zero-copy graph construction and parallel BFS
- **Feature flag**: enabled via `AEGIS_RUST_PATHS=true` environment variable with Go build tag `rust` (falls back to pure-Go engine when disabled)
- **Testing**: 17 Rust unit tests covering graph construction, BFS traversal, edge classification, and empty/degenerate inputs; Criterion benchmarks for regression tracking
- **QA hardening** (Sprint I+4): Vec capacity UB fix, edge_type passthrough, 64MB FFI input cap, C.int truncation fix, staticlib for deployment, strip_prefix ID renumbering

The Rust engine maintains identical output semantics to the Go engine — same JSON response types, same path ordering — ensuring transparent substitution behind the feature flag.

## References

- `docs/research/wiz-attack-path-enhancements.md` — full Wiz-adjacent architecture roadmap
- `internal/cspm/normalizer/schema.go` — AttackPathContext struct
- `internal/cspm/scoring/risk_scorer.go` — risk scoring with attack path context
- `rust/aegispath/` — Rust library source (lib.rs, Cargo.toml)
- `rust/bridge.go` — CGo FFI bridge functions
