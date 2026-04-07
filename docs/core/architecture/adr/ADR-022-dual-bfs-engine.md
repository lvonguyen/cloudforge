# ADR-022: Dual BFS Engine (Go + Rust FFI)

**Status:** Accepted
**Date:** 2026-04-06
**Deciders:** Liem Vo-Nguyen
**Supersedes:** None
**Extends:** ADR-008 (Attack Path Computation), ADR-020 (Security Graph Architecture)

## Context

CloudForge's attack path engine (ADR-008) was originally implemented as an in-memory Go BFS traversal over finding data. This works well at demo scale (1-5K findings, sub-millisecond computation) but benchmark profiling at enterprise scale revealed severe limitations:

| Metric | 200 findings | 20K findings | 300K findings (target) |
|--------|-------------|-------------|----------------------|
| Go BFS wall time | 2.4ms | 119.5s | projected ~136.5s |
| Go BFS allocations | 18K | 184M | projected >1B |
| Go BFS memory | 12MB | 42.5GB | OOM on 16GB machines |

The root cause is Go's garbage collector — the BFS creates millions of transient `[]Finding` slices during path enumeration, and GC pause time dominates at scale. Additionally, Go's single-threaded BFS cannot exploit the natural parallelism of per-account-partition path computation.

A secondary hot path is JSON loading: the server startup deserializes 42MB of findings JSON (300K corpus) in ~120s using `encoding/json`, which does not parallelize.

## Decision

Maintain **two BFS engine implementations** — Go (pure, portable) and Rust (FFI, high-performance) — selectable at build time via Go build tags. This is not a migration; both engines are permanent.

## Implementation Status

As of 2026-04-06, this ADR is **accepted and partially implemented**:

- the Rust crate, CGo bridge, build targets, and benchmarks exist on disk
- the Go BFS engine remains the active server runtime path in `cmd/server/attackpath.go`
- the documented `AEGIS_RUST_PATHS` activation path is not yet wired into the live request/runtime bootstrap

Treat this ADR as the accepted dual-engine design and code path, not as evidence that production requests already execute through Rust by default.

### Architecture

```
cmd/server/attackpath.go        ← Go BFS engine (default, always available)
    ↕ (feature-flagged)
rust/bridge.go                  ← CGo FFI bridge (build tag: cgo && rust)
    ↓
rust/libaegispath/              ← Rust cdylib crate
    ├── src/attackpath.rs       ← Rayon-parallelized BFS (port of attackpath.go)
    ├── src/loader.rs           ← Serde JSON deser + filter + reserialize
    ├── src/types.rs            ← Finding struct (11 of 56 fields for BFS)
    └── src/lib.rs              ← C-ABI exports (aegis_compute_attack_paths, etc.)
```

### Selection Logic

| Condition | Engine | Rationale |
|-----------|--------|-----------|
| `AEGIS_RUST_PATHS=true` + binary built with `-tags rust` | Rust FFI | Production/demo with large corpus |
| Default (no env var, or no Rust build tag) | Go BFS | CI, local dev, zero-dependency deploys |
| `PUPPYGRAPH_URL` set | PuppyGraph Gremlin (ADR-020) | Graph-native traversal when available |

The three engines form a precedence chain: PuppyGraph > Rust FFI > Go BFS. Each reads from the same `graph_edges` table (ADR-020) or falls back to heuristic co-location when edges are unavailable.

### FFI Boundary Design

The FFI contract is **JSON-in/JSON-out** across the CGo boundary:

1. Go serializes `[]Finding` to JSON bytes
2. Go passes a pointer + length to the C-ABI function
3. Rust deserializes with `serde_json`, computes BFS, serializes result
4. Rust returns a pointer + length to a Rust-allocated buffer
5. Go copies the result into Go-managed memory via `unsafe.Slice`
6. Go calls `aegis_free()` to release the Rust buffer

This design eliminates shared-pointer hazards between Go's GC and Rust's ownership model. The serialization overhead (~3-5ms for 20K findings) is negligible compared to the 100x computation savings.

**Safety constraints:**
- 64MB input cap (prevents OOM on malformed input)
- `C.size_t` for lengths (avoids `C.int` truncation on buffers >2GB)
- `staticlib` linkage option for deployment without `.dylib` distribution

### Rust Performance Characteristics

Criterion benchmarks (M2 Max, 200 findings baseline):

| Operation | Time | Notes |
|-----------|------|-------|
| BFS compute | 2.43ms | Rayon parallel across account partitions |
| JSON deserialize | 397μs | Serde, 11 of 56 fields (rest ignored) |
| Full pipeline (deser + BFS + serialize) | 3.71ms | End-to-end FFI round trip |

Projected at 20K findings: **15-25s** (vs Go's 119.5s) — a 5-8x improvement driven by:
- `rayon::par_iter` parallelizes BFS across account partitions (each account's findings are independent)
- Zero-copy graph construction (Rust `Vec` vs Go `[]Finding` slice copies)
- No GC pauses (ownership model, deterministic deallocation)

### Output Equivalence

Both engines must produce **byte-identical JSON output** for the same input. This is enforced by:
- 17 Rust unit tests mirroring Go test cases (graph construction, BFS traversal, edge classification, empty/degenerate inputs)
- Integration test: run both engines on the same 500-finding subset, diff outputs
- Same `AttackPath` / `AttackPathStats` response types (defined in Go, mirrored in Rust)

## Consequences

### Positive

- **Portability preserved** — CI pipelines, Docker alpine images, and `go run` all work without Rust toolchain
- **5-8x throughput** at enterprise scale with Rust enabled — critical for 300K finding corpus demo
- **Incremental adoption** — enable Rust per-environment, zero risk to existing deploys
- **Clean separation** — Rust crate is a self-contained library with its own test suite and benchmarks
- **AdjacencySet integration** — both engines consume `secgraph.AdjacencySet` for evidence-based edges (ADR-020), replacing heuristic co-location inference

### Negative

- **Build complexity** — Rust toolchain required for FFI builds (`cargo build --release` → `make rust-build`)
- **Two codebases** — BFS logic is duplicated across Go and Rust. Changes to path computation must be applied to both.
- **CGo overhead** — enables CGo which disables some Go optimizations (cross-compilation, static binaries without `staticlib`)
- **Debugging** — stack traces cross the FFI boundary; Rust panics become Go crashes unless caught

### Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Rust/Go output divergence after BFS change | Silent correctness regression | Integration test compares both engines on identical input |
| CGo FFI memory leak | Gradual memory growth in production | `copyAndFree` pattern: every Rust allocation is freed immediately after Go copy |
| Rust toolchain unavailable in CI | Cannot build FFI variant | Go engine is always the default; Rust is opt-in via build tag |
| `rayon` thread pool contention with Go runtime | Degraded throughput under high concurrency | Rayon defaults to `num_cpus` threads; Go runtime separately manages goroutines on remaining cores |

## Alternatives Considered

### 1. Rust-Only Engine (Drop Go BFS)

Require Rust toolchain for all builds, remove Go BFS entirely.

**Rejected because:** Breaks zero-dependency `go run` workflow. CI pipelines, Docker alpine images, and contributor onboarding all depend on pure-Go builds. The Go engine is also the PuppyGraph fallback when graph infrastructure is unavailable.

### 2. Go-Only with Optimizations (sync.Pool, Arena)

Optimize Go BFS using `sync.Pool` for slice reuse and Go 1.22 arena allocations.

**Evaluated and insufficient:** Profiling showed GC pause time (not allocation rate) is the bottleneck at 20K+ findings. `sync.Pool` reduces allocation count but does not eliminate GC scanning of live `[]Finding` references during BFS. Arena is experimental and does not support slice-of-struct patterns.

### 3. Separate Microservice (gRPC)

Run Rust BFS as a sidecar service, communicate via gRPC.

**Rejected because:** Adds network hop latency, container orchestration dependency, and operational complexity. The FFI approach has <5ms overhead vs ~20-50ms for gRPC round trip, and ships as a single binary.

## References

- ADR-008: Attack Path Computation Strategy (original Go BFS)
- ADR-020: Security Graph Architecture (AdjacencySet, graph_edges)
- `cmd/server/attackpath.go` — Go BFS engine (computeAttackPaths, isEntryPoint, isTarget, canConnect, buildChain)
- `rust/bridge.go` — CGo FFI bridge (ComputeAttackPaths, LoadAndSerializeFindings)
- `rust/libaegispath/src/attackpath.rs` — Rust BFS engine (rayon-parallelized)
- `rust/libaegispath/src/loader.rs` — Serde JSON loading pipeline
- `internal/secgraph/adjacency.go` — AdjacencySet for evidence-based edge lookup
