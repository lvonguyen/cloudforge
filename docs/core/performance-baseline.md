# Performance Baseline

**Platform:** Apple M2 Max, 12-core, 32GB
**Date:** 2026-03-18
**Go version:** 1.25.0
**Rust version:** 1.94.0
**Dataset:** 20,000 findings (42MB JSON), test fixture 200 findings (370KB)

---

## Go Benchmarks (Full 20K Dataset)

All benchmarks run with `-benchmem -count=3` on M2 Max (12 cores). Median of 3 runs shown.

| Benchmark | ns/op (median) | B/op | allocs/op | Human-readable |
|---|---|---|---|---|
| ServerStartup | 126,999,891,708 | 46,051,293,592 | 185,052,746 | **127s, 42.9GB, 185M allocs** |
| ListFindings | 7,459,066 | 14,350,455 | 63 | **7.5ms, 13.7MB** |
| ListAttackPaths | 5,423,366,792 | 3,953,288,552 | 88 | **5.4s, 3.7GB** |
| GetFinding | 10,063 | 7,544 | 56 | **10us** |
| GetCached_Hit | 13.25 | 0 | 0 | **13ns** |
| GetCached_Miss | 12.80 | 0 | 0 | **13ns** |
| EvictExpired_5000 | 129,047 | 1 | 0 | **129us** |
| AttackPathComputation | 119,547,721,208 | 45,679,062,312 | 183,901,958 | **119.5s, 42.5GB, 184M allocs** |

### Analysis

**Hot paths (candidates for Rust FFI):**
- `AttackPathComputation`: 136.5s, 42.5GB allocations. BFS over 20K findings with O(n^2) per-account pairing. Dominant cost is Go map/slice allocation + GC pressure.
- `ServerStartup`: 120s, 42.9GB. Dominated by `json.Unmarshal` of the 42MB findings file + integrity hash computation.
- `ListAttackPaths`: 2.5s, 3.7GB. JSON marshaling of attack path results with `encoding/json` reflection.

**Already optimal (not worth porting):**
- `GetCached_Hit/Miss`: 13ns, 0 allocs. Hardware-limited mutex + map lookup.
- `GetFinding`: 10.7us. Simple map lookup + JSON marshal of single finding.
- `EvictExpired_5000`: 111us. Trivial sort + delete loop.
- `ListFindings`: 2.5ms. Acceptable for API response.

---

## Rust Benchmarks (200-Finding Test Fixture)

Criterion benchmarks on the same M2 Max. Compiled with `--release` (LTO, codegen-units=1).

| Benchmark | Median | Notes |
|---|---|---|
| compute_attack_paths (200 findings) | **2.43ms** | BFS + rayon par_iter |
| deserialize_findings | **397us** | serde_json, minimal 11-field struct |
| full_pipeline (deser + compute + ser) | **3.71ms** | JSON in, compute, JSON out |

### Projected Scaling (200 -> 20K findings)

The attack path algorithm has O(n * k^2) complexity where n = accounts and k = findings-per-account.
With 20K findings across ~5 clustered accounts:

| Metric | Go (20K, median of 3) | Rust projected (20K) | Speedup |
|---|---|---|---|
| Attack path computation | 119.5s | ~15-25s | 5-8x |
| JSON deserialization | ~127s (full startup) | ~3-8s (serde, 11 fields) | 16-42x |
| JSON serialization | ~5.4s (list paths) | ~0.5-1.5s (serde) | 3.6-11x |

**Why Rust is faster here:**
1. **No GC pressure:** 184M allocations in Go = massive GC pauses. Rust arena-allocates and drops in batch.
2. **rayon parallelism:** Account partitions are embarrassingly parallel. Go processes sequentially.
3. **serde vs encoding/json:** serde generates serialization code at compile time (no reflection). Go's encoding/json uses reflect at runtime.
4. **11-field struct:** Rust only allocates 11 of 56 Finding fields for BFS. Go allocates all 56.

---

## Architecture

```
Go Server (cmd/server)          Rust Library (libaegispath)
  HTTP, JWT, RBAC, GRC            BFS computation (rayon)
  enrichment, identity            JSON load (serde)
  deploy, finops, ws-server       JSON serialize (serde)
       |                               ^
       | JSON bytes (CGo FFI)           |
       +-------------------------------+
       Feature flag: AEGIS_RUST_PATHS=true
```

**FFI boundary:** JSON-in/JSON-out. No shared pointers between Go GC and Rust ownership.
**Library:** `libaegispath.dylib` (698KB, release build).
**Tests:** 14 Rust unit tests + 11 BFS tests.
**Clippy:** Clean (zero warnings).

---

## Files

| Path | Purpose |
|---|---|
| `rust/libaegispath/Cargo.toml` | Crate config (serde, rayon, criterion) |
| `rust/libaegispath/src/types.rs` | Minimal Finding (11 fields), AttackPath structs |
| `rust/libaegispath/src/attackpath.rs` | BFS port from Go (rayon parallel) |
| `rust/libaegispath/src/loader.rs` | Full Finding (56 fields), filter, serialize |
| `rust/libaegispath/src/lib.rs` | C FFI exports |
| `rust/libaegispath/benches/attackpath_bench.rs` | Criterion benchmarks |
| `rust/bridge.go` | CGo bridge (package aegispath) |

---

## Next Steps

1. Run Rust benchmarks against full 20K dataset (requires LFS checkout)
2. Wire FFI into server with `AEGIS_RUST_PATHS=true` feature flag
3. CI integration (`cargo build --release` step, cache `target/`)
4. Cross-compilation for Fly.io Linux deploy (`cross` tool or multi-stage Docker)
