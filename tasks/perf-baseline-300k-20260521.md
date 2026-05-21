# 300K Findings Performance Baseline - 2026-05-21

Target: `https://api.cloudforge.lvonguyen.com`

## Verdict

The live Fly API is healthy and serving the 300K Postgres-backed findings corpus. Basic list/filter pagination is usable, attack-path reads are fast once the sampled cache is warm, and the two current bottlenecks are severity sorting and degraded keyword search.

Local `localhost` benchmarking was blocked because Docker is not running:

```text
failed to connect to the docker API at unix:///Users/lvonguyen/.docker/run/docker.sock
```

For this pass, the benchmark used the live API with a short-lived admin JWT generated from `op://Development/aegis-personal-jwt-secret/credential`. The token was not written to disk.

## Freshness

- Health checked: `2026-05-21T16:55:48Z`
- Benchmark window: `2026-05-21T16:57:36Z` to `2026-05-21T16:58:34Z`
- `/health`: `200`, `postgres=healthy`, Postgres health latency about `65-66ms`
- `/api/v1/findings?page=1&per_page=150`: `total=300000`

## Method

- Sequential requests from this workstation over the public internet.
- One warmup request per scenario was excluded from the measured sample.
- Percentiles use small samples, so p95/p99 should be treated as directional rather than statistically final.
- Cold attack-path lazy materialization was not measured because the live process was already warm.

## Results

| Scenario | Reps | Status | p50 ms | p95 ms | p99 ms | Total | Count | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Findings page 150 default | 10 | 200 | 184 | 868 | 868 | 300000 | 150 | Response about 269 KB. |
| Findings severity=HIGH | 10 | 200 | 132 | 296 | 296 | 56510 | 150 | Indexed filter path looks good. |
| Findings provider=aws | 10 | 200 | 182 | 344 | 344 | 172006 | 150 | Indexed filter path looks good. |
| Findings status=open | 10 | 200 | 243 | 790 | 790 | 207161 | 150 | Valid status filter. `status=new` is a workflow-status value and was excluded. |
| Findings sort=severity desc | 10 | 200 | 2473 | 2726 | 2726 | 300000 | 150 | Current main bottleneck. |
| Attack paths page 20 | 5 | 200 | 32 | 111 | 111 | 5476 | 20 | Warm sampled cache. |
| Attack paths stats | 5 | 200 | 27 | 35 | 35 | n/a | n/a | `mode=sampled`. |
| Findings keyword search | 5 | 200 | 1476 | 1627 | 1627 | 200 | 20 | `mode=keyword`; large-corpus search service is intentionally degraded. |

## Bottlenecks

1. Severity sort is slow: `p50=2.47s`, `p95=2.73s`.
   The current SQL sorts by a `CASE UPPER(severity)` expression. The existing `idx_findings_severity_list` index starts with raw `severity`, so PostgreSQL likely cannot satisfy this order directly. Best next step is `EXPLAIN ANALYZE` on Neon, then either an expression index or a persisted `severity_rank`.

2. Keyword search is degraded but expected under current constraints: `p50=1.48s`, `p95=1.63s`.
   This matches `tasks/blocked.md`: large-corpus search indexing is intentionally skipped on the current Fly VM size, so keyword mode falls back to bounded in-memory behavior.

3. List/filter p95 spikes are mostly payload/network shaped.
   The normal list/filter paths return roughly 260-270 KB per 150-row page. Median latency is under 250ms for the measured list/filter paths, with occasional public-network spikes.

4. Cold attack-path behavior remains unmeasured.
   Warm reads are fast, but the task board's cold-start concern requires a planned Fly restart or an isolated local Postgres run once Docker is available.

## Follow-Up

- Run `EXPLAIN ANALYZE` for the severity sort query against Neon.
- Add an expression index or `severity_rank` if the plan confirms a full sort.
- Measure cold attack-path lazy materialization during a controlled restart window.
- Re-run localhost baseline once Docker Desktop/Postgres is available.
