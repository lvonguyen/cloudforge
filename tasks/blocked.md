# Blocked Items

## D19 Shared Postgres Cutover

**Status:** LIVE as of March 31, 2026 — `cloudforge-api` now starts with `FINDINGS_SOURCE=postgres` against the dedicated `cloudforge` Neon database.

### Current State

1. Cloudforge uses the dedicated Development-vault DSN ref `op://Development/4uvialfye3icuwak32yblswaam/credential`
2. The dedicated `cloudforge` database is fully seeded:
   - `findings`: `300000`
   - `resources`: `299998`
   - `accounts`: `240`
   - `graph_edges`: `1091433`
   - `compliance_mappings`: `491435`
3. Full seeded database size on Neon Launch is `1,078,362,112` bytes (`1028 MB`, about `1.03 GB`)
4. Fly runtime secrets are fully deployed, including `AEGIS_DATABASE_URL` and `FINDINGS_SOURCE=postgres`
5. The live API at `https://api.cloudforge-demo.lvonguyen.com/health` is healthy on the Postgres-backed image

### Residual Constraints

1. Large-corpus search and attack-path warmup are intentionally skipped by default on the current Fly VM size
2. Leave `LARGE_CORPUS_WARMUP_ENABLED` unset on the current `2 GB` shared VM unless machine size increases or warmup is redesigned
3. Large-corpus secgraph materialization is also intentionally skipped by default on the current Fly VM size
4. Leave `LARGE_CORPUS_SECGRAPH_SYNC_ENABLED` unset on the current `2 GB` shared VM unless machine size increases or secgraph materialization is redesigned
5. Current consequence:
   - findings/search endpoints now fall back to in-memory keyword search when the large-corpus Bleve index is intentionally skipped
   - hybrid and semantic requests degrade to keyword mode when the search service is intentionally absent
   - attack-path endpoints now lazily materialize a bounded sampled cache on first request instead of returning the empty bootstrap state
   - the first attack-path request on a cold process is slower because it computes a sampled heuristic cache over the 300K corpus
   - secgraph issue materialization stays incomplete on the live demo unless secgraph sync is explicitly re-enabled on a larger footprint

### Next Infra / Feature Work

1. Reintroduce large-corpus attack-path and secgraph materialization in a bounded way:
   - improve the current lazy/on-demand attack-path cache so the first cold request is faster and the sampled heuristic slice is higher fidelity
   - batched background indexing
   - or a larger Fly VM profile
2. Decide whether the large-corpus keyword fallback should remain the steady-state operator experience or whether it should be replaced with a true on-demand Bleve build path
3. Only enable `LARGE_CORPUS_WARMUP_ENABLED=true` and/or `LARGE_CORPUS_SECGRAPH_SYNC_ENABLED=true` after that capacity work is verified on Fly

### Local Development

Local dev can continue using the in-memory provider. Set `AEGIS_DATABASE_URL` / `DATABASE_URL`
to a local Postgres instance only when you specifically want to exercise the Postgres-backed path.

### Code Notes

- `internal/grc.NewProvider(cfg)` already supports the Postgres backend
- The current live constraints are memory-bound background materialization paths, not database connectivity
