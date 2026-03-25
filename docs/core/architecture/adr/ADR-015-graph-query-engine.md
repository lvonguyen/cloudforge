# ADR-015: Graph Query Engine

**Status:** Accepted
**Date:** 2026-03-19
**Deciders:** Liem Vo-Nguyen
**Supersedes:** None
**References:** ADR-008 (Attack Path Computation)

## Context

Cloud Aegis currently uses three fragmented graph computation approaches:

1. **libaegispath BFS** -- in-memory Go computation for attack path topology (`computeAttackPaths`)
2. **Investigation Board** -- React Flow client-side graph from flat finding data
3. **DataStore in-memory maps** -- O(1) lookups but no relationship traversal

As the product scales beyond demo/POC toward multi-tenant production, a unified graph query layer is required that supports:

- Multi-hop traversal (e.g., "find all findings reachable from identity X within 3 hops")
- Real-time queries over live data (not pre-computed snapshots)
- Both Gremlin and openCypher query languages (customer preference varies)

## Options

### Option A: PuppyGraph Enterprise (Zero-ETL)

- **Pros:** No data movement, queries Postgres directly, supports Gremlin + openCypher, managed schema mapping
- **Cons:** Vendor dependency (30-day trial), enterprise pricing TBD, JVM-based (memory requirements)
- **Cost:** ~$12/day for r6i.2xlarge (64GB min required; r6i.xlarge returns UnsupportedOperation), production pricing TBD

### Option B: Native Go Graph Layer

- **Pros:** No external dependency, full control, already partially implemented (BFS)
- **Cons:** Significant engineering effort (estimated 3-4 sprints), limited query language support, would need custom Gremlin/Cypher parser
- **Cost:** Engineering time only

### Option C: Neo4j / Apache AGE

- **Pros:** Mature ecosystem, large community, proven at scale
- **Cons:** Requires ETL pipeline, separate database to manage, data synchronization complexity
- **Cost:** Neo4j AuraDB ~$65/month for smallest tier, AGE is free but requires PostgreSQL extension

## Decision

**Option A: PuppyGraph Enterprise** as primary, with **Option B** retained as fallback.

### Rationale

1. Zero-ETL eliminates the data synchronization problem entirely
2. Dual query language support (Gremlin + openCypher) serves both operator and developer personas
3. POC can validate performance against real data topology before committing to production license
4. Existing Go BFS layer remains as fallback if PuppyGraph trial is not extended

## Consequences

- **Positive:** Unified graph query surface, real-time queries, no ETL maintenance
- **Negative:** Runtime dependency on PuppyGraph service, JVM memory overhead
- **Risks:** Trial expiry without license decision, vendor lock-in on query patterns
- **Mitigations:** Feature flag (`PUPPYGRAPH_URL`), Go BFS fallback, ADR review at trial end (2026-04-18)

## Implementation

- Proxy endpoint: `POST /api/v1/graph/query` (RBAC: operator + admin)
- Go client: `internal/graph/client.go`
- Docker: `docker-compose.puppygraph.yml` (local dev)
- Terraform: `deploy/terraform/modules/puppygraph/` (AWS EC2 POC)
- Feature flag: `PUPPYGRAPH_URL` env var (empty = 501 Not Implemented)
