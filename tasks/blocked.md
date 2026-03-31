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
3. Full large-corpus secgraph graph-artifact materialization is still intentionally deferred on the current Fly VM size
4. Leave `LARGE_CORPUS_SECGRAPH_SYNC_ENABLED` unset on the current `2 GB` shared VM unless machine size increases or the full secgraph graph-artifact path is redesigned
5. Current consequence:
   - findings/search endpoints now fall back to in-memory keyword search when the large-corpus Bleve index is intentionally skipped
   - hybrid and semantic requests degrade to keyword mode when the search service is intentionally absent
   - attack-path endpoints now lazily materialize a bounded sampled cache on first request instead of returning the empty bootstrap state
   - the first attack-path request on a cold process is slower because it computes a sampled heuristic cache over the 300K corpus
   - the operator-facing issue surface now incrementally materializes on startup in bounded batches even on the current Fly VM size
   - verified March 31, 2026: the first live issue-surface batch committed `77116` evaluations/issues/issue_findings at `2026-03-31T22:23:46Z`, and `issues/stats`, `issues`, and `issues/{id}` all responded successfully on the public demo API
   - the heavier secgraph graph-edge artifacts still stay deferred until the larger-footprint path is redesigned

### Next Infra / Feature Work

1. Reintroduce full large-corpus attack-path and secgraph graph-artifact materialization in a bounded way:
   - improve the current lazy/on-demand attack-path cache so the first cold request is faster and the sampled heuristic slice is higher fidelity
   - batched background indexing / graph-edge builds
   - or a larger Fly VM profile
2. Decide whether the large-corpus keyword fallback should remain the steady-state operator experience or whether it should be replaced with a true on-demand Bleve build path
3. Only enable `LARGE_CORPUS_WARMUP_ENABLED=true` and/or `LARGE_CORPUS_SECGRAPH_SYNC_ENABLED=true` after that capacity work is verified on Fly

### Local Development

Local dev can continue using the in-memory provider. Set `AEGIS_DATABASE_URL` / `DATABASE_URL`
to a local Postgres instance only when you specifically want to exercise the Postgres-backed path.

### Code Notes

- `internal/grc.NewProvider(cfg)` already supports the Postgres backend
- The current live constraints are memory-bound background materialization paths, not database connectivity
