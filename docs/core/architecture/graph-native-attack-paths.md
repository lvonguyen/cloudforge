# Graph-Native Attack Path Queries

Reference for migrating `cmd/server/attackpath.go` heuristics to Gremlin traversals
over the Security Graph (ADR-020). Each section maps a current Go function to its
graph-native equivalent.

## Current Architecture (Heuristic BFS)

```
computeAttackPaths(findings)
  → byAccount (group by account_id)
  → classify: isEntryPoint / isTarget / intermediate
  → buildChain(entry, intermediates, target)
  → lateral movement (CRIT/HIGH pairs, same account)
  → AI enrichment (top-10 via Opus, rest via Sonnet)
```

Edges are **inferred** from co-location: `canConnect(a, b)` returns true when
`a.AccountID == b.AccountID && (a.Region == b.Region || a.ResourceType == b.ResourceType)`.

## Graph-Native Architecture (Gremlin Traversals)

Edges are **explicit** in the `graph_edges` table. PuppyGraph projects them as native
Gremlin edges. No co-location inference needed.

### 1. Find Entry Points

**Current:** `isEntryPoint(f)` — category=NETWORK, VULNERABILITY+exploit, or compute/container/serverless CRIT/HIGH.

**Gremlin:**
```groovy
// Internet-exposed or exploitable findings
g.V().hasLabel('finding').or(
    has('category', 'NETWORK'),
    and(has('category', 'VULNERABILITY'), has('exploit_available', true))
).as('entry')
```

### 2. Find Targets (Sensitive Resources)

**Current:** `isTarget(f)` — resource_type in (storage, database, secret, encryption).

**Gremlin:**
```groovy
// Data-bearing resources
g.V().hasLabel('resource').has('type', within(
    'storage', 'database', 'secret', 'encryption'
)).as('target')
```

### 3. Compute Attack Paths (Entry → Target)

**Current:** `buildChain(entry, intermediates, target)` — direct or 1-intermediate bridge via `canConnect()`.

**Gremlin (explicit edges):**
```groovy
// Find all paths from entry-point findings to sensitive resources
// Uses explicit same_region/same_account/accesses edges instead of heuristic
g.V().hasLabel('finding').or(
    has('category', 'NETWORK'),
    and(has('category', 'VULNERABILITY'), has('exploit_available', true))
).out('affects')                               // finding → entry resource
  .repeat(
    out('same_region', 'same_account', 'accesses', 'exposes')
    .simplePath()
  )
  .until(has('type', within('storage', 'database', 'secret', 'encryption')))
  .times(4)                                     // max 4 hops (ADR-008)
  .path()
  .limit(100)
```

### 4. Lateral Movement Paths

**Current:** CRIT/HIGH finding pairs in the same account that can connect.

**Gremlin:**
```groovy
// CRIT/HIGH findings whose resources share account or region edges
g.V().hasLabel('finding')
  .has('severity', within('CRITICAL', 'HIGH'))
  .out('affects')
  .out('same_account')
  .in('affects')
  .has('severity', within('CRITICAL', 'HIGH'))
  .simplePath()
  .path()
  .limit(50)
```

### 5. Blast Radius (from an Issue)

**Current:** Count of findings in the attack path chain.

**Gremlin:**
```groovy
// Count all resources reachable from an issue's affected resource
g.V('ISS-00042').hasLabel('issue')
  .out('materializes_to')               // issue → finding
  .out('affects')                        // finding → resource
  .out('same_region', 'accesses', 'depends_on')
  .dedup()
  .count()
```

### 6. Control Violation Chains

**New query — not possible with heuristic engine:**
```groovy
// Find resources that fail a specific control AND are reachable from
// an internet-exposed entry point
g.V('CIS-AWS-2.1.1').hasLabel('control')
  .in('evaluated_by')                    // resources evaluated by this control
  .where(
    __.in('affects')                     // findings that affect these resources
      .has('status', 'FAIL')
  )
  .as('vulnerable_resource')
  .in('affects')
  .in('same_region')                     // walk back to entry-point resources
  .in('affects')
  .has('category', 'NETWORK')
  .select('vulnerable_resource')
  .dedup()
  .valueMap('name', 'type', 'region')
```

### 7. Issue Impact Graph (Cypher alternative)

For operators who prefer openCypher:
```cypher
// All issues affecting production resources with blast radius > 5
MATCH (i:issue)-[:materializes_to]->(f:finding)-[:affects]->(r:resource)-[:belongs_to]->(a:account)
WHERE a.environment_type = 'production'
  AND i.blast_radius > 5
  AND i.status = 'OPEN'
RETURN i.id, i.title, i.severity, i.blast_radius,
       collect(DISTINCT r.name) AS affected_resources,
       a.name AS account
ORDER BY i.risk_score DESC
LIMIT 20
```

## Migration Strategy

| Phase | Engine | Edge Source | Notes |
|-------|--------|------------|-------|
| Current | Go BFS (`computeAttackPaths`) | Heuristic: `canConnect()` | No graph DB needed |
| Phase 2 | Go BFS (updated) | `graph_edges` table lookup | Same algorithm, real edges |
| Phase 4 | PuppyGraph Gremlin | `graph_edges` via JDBC | Native graph traversal |
| Future | Neptune Gremlin | ETL from `graph_edges` | Production scale |

The Go BFS engine and PuppyGraph Gremlin produce identical results when operating
over the same edge data — the difference is execution strategy (in-memory BFS vs.
JDBC-backed traversal). Feature flag `PUPPYGRAPH_URL` controls which path executes.

## Edge Materialization (Phase 2 Prerequisite)

Before graph-native queries work, the `graph_edges` table must be populated:

1. **On finding ingestion:** INSERT `affects` edge (finding → resource)
2. **On control evaluation:** INSERT `violates` edge (finding → control) + `evaluated_by` edge (resource → control)
3. **On issue creation:** INSERT `materializes_to` edge (finding → issue)
4. **Periodic backfill:** Materialize `same_account` and `same_region` edges from resource pairs sharing account_id/region
5. **Future — infrastructure discovery:** Populate `accesses`, `exposes`, `depends_on` from IAM policy analysis, network topology, CloudFormation/Terraform dependency graphs
